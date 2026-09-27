"""
Deploy the AWS side of the lab. Safe to re-run: existing resources are reused
or updated.

  python aws/deploy.py --region us-east-1                    # full deploy, Cedar in ENFORCE
  python aws/deploy.py --region us-east-1 --policy-mode LOG_ONLY
  python aws/deploy.py --region us-east-1 --no-policy         # skip the Cedar policy engine

What it builds (all names start with "agentlab"):
  S3 bucket + tagged sample documents        (data plane, ABAC by object tags)
  DynamoDB table agentlab-hr-attributes      (live source of the clearance attribute)
  DynamoDB table agentlab-employees          (structured data for query_employees;
                                              row/column fine-grained access by session tags)
  IAM roles: interceptor (broker), user-scoped (ABAC), docs-tool (no S3!), gateway
  Lambda functions: agentlab-interceptor, agentlab-docs-tool
  AgentCore Gateway with CUSTOM_JWT inbound auth pointed at your Entra tenant
  Gateway target "docs" (Lambda) with 4 tools
  AgentCore Policy engine + Cedar policies
  Finally attaches the interceptor (REQUEST + RESPONSE) and the policy engine.

Order matters: Cedar policies are created BEFORE the token-checking interceptor
is attached, because policy validation calls the gateway without a user token.
"""

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

import boto3
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB = os.path.join(ROOT, ".lab")
PREFIX = "agentlab"
RUNTIME = "python3.12"


def log(msg):
    print(f"[deploy] {msg}", flush=True)


def render(path, **values):
    text = open(path).read()
    for k, v in values.items():
        text = text.replace("{" + k + "}", str(v))
    return text


class Deployer:
    def __init__(self, region, policy_mode, custom_claims=True):
        self.region = region
        self.policy_mode = policy_mode
        self.custom_claims = custom_claims
        self.s = boto3.Session(region_name=region)
        self.account = self.s.client("sts").get_caller_identity()["Account"]
        self.iam = self.s.client("iam")
        self.s3 = self.s.client("s3")
        self.ddb = self.s.client("dynamodb")
        self.lam = self.s.client("lambda")
        self.ac = self.s.client("bedrock-agentcore-control")
        self.aa = self.s.client("accessanalyzer")
        self.entra = json.load(open(os.path.join(LAB, "entra.json")))
        self.bucket = f"{PREFIX}-data-{self.account}-{region}"
        self.state = {"region": region, "account": self.account, "prefix": PREFIX, "bucket": self.bucket}
        self.values = dict(ACCOUNT_ID=self.account, REGION=region, PREFIX=PREFIX,
                           BUCKET=self.bucket, TENANT_ID=self.entra["tenant_id"])

    # ------------------------------------------------------------------ IAM
    def validate_policy(self, name, doc, trust=False):
        """Run IAM Access Analyzer policy validation and print any findings."""
        kw = {"policyDocument": doc, "policyType": "IDENTITY_POLICY"}
        if trust:
            kw.update(policyType="RESOURCE_POLICY", validatePolicyResourceType="AWS::IAM::AssumeRolePolicyDocument")
        try:
            findings = self.aa.validate_policy(**kw)["findings"]
        except ClientError as e:
            log(f"  (Access Analyzer validation skipped for {name}: {e.response['Error']['Code']})")
            return
        serious = [f for f in findings if f["findingType"] == "ERROR"]
        for f in findings:
            log(f"  Access Analyzer {f['findingType']} on {name}: {f['issueCode']} - {f['findingDetails'][:120]}")
        if not findings:
            log(f"  Access Analyzer: {name} has no findings")
        if serious:
            sys.exit(f"Fix the {name} policy before continuing.")

    def role(self, name, trust_doc, inline=None, managed=None, max_session=3600):
        try:
            arn = self.iam.get_role(RoleName=name)["Role"]["Arn"]
            self.iam.update_assume_role_policy(RoleName=name, PolicyDocument=trust_doc)
            log(f"role {name} exists (trust policy updated)")
        except self.iam.exceptions.NoSuchEntityException:
            arn = self.iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_doc,
                                       MaxSessionDuration=max_session,
                                       Tags=[{"Key": "project", "Value": PREFIX}])["Role"]["Arn"]
            log(f"created role {name}")
        for pname, doc in (inline or {}).items():
            self.iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=doc)
        for m in managed or []:
            self.iam.attach_role_policy(RoleName=name, PolicyArn=m)
        return arn

    def deploy_iam(self):
        v = self.values
        lambda_trust = open(os.path.join(HERE, "policies", "lambda_trust.json")).read()
        basic = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

        interceptor_perms = render(os.path.join(HERE, "policies", "interceptor_permissions.json"), **v)
        self.validate_policy("interceptor permissions", interceptor_perms)
        self.state["interceptor_role_arn"] = self.role(
            f"{PREFIX}-interceptor-role", lambda_trust, {"broker": interceptor_perms}, [basic])

        # The trust policy names the interceptor role as principal, so it must exist first.
        user_trust = render(os.path.join(HERE, "policies", "user_scoped_trust.json"), **v)
        abac = render(os.path.join(HERE, "policies", "user_scoped_abac.json"), **v)
        fgac = render(os.path.join(HERE, "policies", "user_scoped_dynamodb_fgac.json"), **v)
        self.validate_policy("user-scoped trust", user_trust, trust=True)
        self.validate_policy("user-scoped ABAC", abac)
        self.validate_policy("user-scoped DynamoDB FGAC", fgac)
        for attempt in range(10):  # new role principals take a few seconds to propagate
            try:
                self.state["user_role_arn"] = self.role(
                    f"{PREFIX}-user-scoped-role", user_trust, {"abac-s3": abac, "fgac-dynamodb": fgac})
                break
            except ClientError as e:
                if "Invalid principal" in str(e) and attempt < 9:
                    time.sleep(5)
                    continue
                raise

        self.state["tool_role_arn"] = self.role(f"{PREFIX}-docs-tool-role", lambda_trust, managed=[basic])

        gw_trust = render(os.path.join(HERE, "policies", "gateway_trust.json"), **v)
        gw_perms = render(os.path.join(HERE, "policies", "gateway_permissions.json"), **v)
        self.validate_policy("gateway permissions", gw_perms)
        self.state["gateway_role_arn"] = self.role(f"{PREFIX}-gateway-role", gw_trust, {"invoke": gw_perms})

    # --------------------------------------------------------------- data
    def deploy_data(self):
        try:
            self.s3.head_bucket(Bucket=self.bucket)
            log(f"bucket {self.bucket} exists")
        except ClientError:
            kwargs = {"Bucket": self.bucket}
            if self.region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
            self.s3.create_bucket(**kwargs)
            log(f"created bucket {self.bucket}")
        self.s3.put_public_access_block(Bucket=self.bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        manifest = json.load(open(os.path.join(ROOT, "data", "manifest.json")))
        for key, tags in manifest.items():
            self.s3.put_object(Bucket=self.bucket, Key=key, Body=open(os.path.join(ROOT, "data", key), "rb").read(),
                               Tagging="&".join(f"{k}={v}" for k, v in tags.items()))
            log(f"  s3://{self.bucket}/{key}  tags={tags}")

        table = f"{PREFIX}-hr-attributes"
        try:
            self.ddb.describe_table(TableName=table)
        except self.ddb.exceptions.ResourceNotFoundException:
            self.ddb.create_table(TableName=table, BillingMode="PAY_PER_REQUEST",
                                  AttributeDefinitions=[{"AttributeName": "oid", "AttributeType": "S"}],
                                  KeySchema=[{"AttributeName": "oid", "KeyType": "HASH"}])
            self.ddb.get_waiter("table_exists").wait(TableName=table)
            log(f"created table {table}")
        for name, u in self.entra["users"].items():
            self.ddb.put_item(TableName=table, Item={
                "oid": {"S": u["oid"]}, "persona": {"S": name}, "clearance": {"S": u["clearance"]}})
        log(f"  seeded clearance for {', '.join(self.entra['users'])}")
        self.state["hr_table"] = table

        # Structured data for query_employees. Partition key = department, so IAM
        # (dynamodb:LeadingKeys) can restrict each session to its own rows.
        emp = f"{PREFIX}-employees"
        try:
            self.ddb.describe_table(TableName=emp)
        except self.ddb.exceptions.ResourceNotFoundException:
            self.ddb.create_table(TableName=emp, BillingMode="PAY_PER_REQUEST",
                                  AttributeDefinitions=[{"AttributeName": "dept_code", "AttributeType": "S"},
                                                        {"AttributeName": "employee_id", "AttributeType": "S"}],
                                  KeySchema=[{"AttributeName": "dept_code", "KeyType": "HASH"},
                                             {"AttributeName": "employee_id", "KeyType": "RANGE"}],
                                  Tags=[{"Key": "project", "Value": PREFIX}])
            self.ddb.get_waiter("table_exists").wait(TableName=emp)
            log(f"created table {emp}")
        rows = json.load(open(os.path.join(ROOT, "data", "structured", "employees.json")))
        for r in rows:
            self.ddb.put_item(TableName=emp, Item={
                k: ({"N": str(v)} if isinstance(v, (int, float)) else {"S": str(v)}) for k, v in r.items()})
        log(f"  seeded {len(rows)} employee rows")
        self.state["employees_table"] = emp

    # ------------------------------------------------------------- lambdas
    def build_zip(self, src_dir, with_deps):
        buf = io.BytesIO()
        with tempfile.TemporaryDirectory() as tmp:
            if with_deps:
                log("  installing PyJWT + cryptography wheels for Lambda (linux x86_64, py3.12)")
                subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--target", tmp,
                                "--platform", "manylinux2014_x86_64", "--implementation", "cp",
                                "--python-version", "3.12", "--only-binary=:all:", "--upgrade",
                                "PyJWT[crypto]>=2.8"], check=True)
            for fn in os.listdir(src_dir):  # handler.py plus any helper modules / policy files
                if fn.endswith((".py", ".json")):
                    shutil.copy(os.path.join(src_dir, fn), tmp)
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for base, _, files in os.walk(tmp):
                    for fn in files:
                        full = os.path.join(base, fn)
                        z.write(full, os.path.relpath(full, tmp))
        return buf.getvalue()

    def function(self, name, role_arn, code, env, timeout=20):
        cfg = dict(Runtime=RUNTIME, Role=role_arn, Handler="handler.lambda_handler",
                   Timeout=timeout, MemorySize=256, Environment={"Variables": env})
        try:
            self.lam.get_function(FunctionName=name)
            self.lam.update_function_code(FunctionName=name, ZipFile=code)
            self.lam.get_waiter("function_updated_v2").wait(FunctionName=name)
            self.lam.update_function_configuration(FunctionName=name, **cfg)
            self.lam.get_waiter("function_updated_v2").wait(FunctionName=name)
            log(f"updated function {name}")
        except self.lam.exceptions.ResourceNotFoundException:
            for attempt in range(12):  # IAM role propagation
                try:
                    self.lam.create_function(FunctionName=name, Code={"ZipFile": code},
                                             Tags={"project": PREFIX}, **cfg)
                    break
                except ClientError as e:
                    if "cannot be assumed" in str(e) and attempt < 11:
                        time.sleep(5)
                        continue
                    raise
            self.lam.get_waiter("function_active_v2").wait(FunctionName=name)
            log(f"created function {name}")
        return self.lam.get_function(FunctionName=name)["Configuration"]["FunctionArn"]

    def deploy_lambdas(self):
        e = self.entra
        self.state["interceptor_arn"] = self.function(
            f"{PREFIX}-interceptor", self.state["interceptor_role_arn"],
            self.build_zip(os.path.join(ROOT, "lambdas", "interceptor"), with_deps=True),
            {"TENANT_ID": e["tenant_id"], "API_APP_ID": e["api_app_id"],
             "ALLOWED_CLIENT_IDS": e["client_app_id"], "USER_ROLE_ARN": self.state["user_role_arn"],
             "HR_TABLE": self.state["hr_table"], "SESSION_SECONDS": "900"})
        self.state["tool_arn"] = self.function(
            f"{PREFIX}-docs-tool", self.state["tool_role_arn"],
            self.build_zip(os.path.join(ROOT, "lambdas", "data_tool"), with_deps=False),
            {"DATA_BUCKET": self.bucket, "EMPLOYEES_TABLE": self.state["employees_table"]})

    # ------------------------------------------------------------- gateway
    def authorizer(self, with_custom_claims=True):
        e = self.entra
        cfg = {"discoveryUrl": e["discovery_url"], "allowedAudience": [e["api_app_id"]]}
        if with_custom_claims:
            # Entra v2 tokens carry the calling app in `azp`, not `client_id`, so we
            # pin the tenant and the client app with custom claim rules instead of allowedClients.
            cfg["customClaims"] = [
                {"inboundTokenClaimName": "tid", "inboundTokenClaimValueType": "STRING",
                 "authorizingClaimMatchValue": {"claimMatchValue": {"matchValueString": e["tenant_id"]},
                                                "claimMatchOperator": "EQUALS"}},
                {"inboundTokenClaimName": "azp", "inboundTokenClaimValueType": "STRING",
                 "authorizingClaimMatchValue": {"claimMatchValue": {"matchValueString": e["client_app_id"]},
                                                "claimMatchOperator": "EQUALS"}},
            ]
        return {"customJWTAuthorizer": cfg}

    def wait(self, getter, ok, bad, what, **kw):
        for _ in range(90):
            st = getter(**kw)
            status = st.get("status")
            if status in ok:
                return st
            if status in bad:
                sys.exit(f"{what} ended in {status}: {st.get('statusReasons')}")
            time.sleep(5)
        sys.exit(f"Timed out waiting for {what}")

    def find_gateway(self):
        for page in self.ac.get_paginator("list_gateways").paginate():
            for g in page.get("items", []):
                if g.get("name") == f"{PREFIX}-gateway":
                    return self.ac.get_gateway(gatewayIdentifier=g["gatewayId"])
        return None

    def deploy_gateway(self):
        gw = self.find_gateway()
        if gw:
            log(f"gateway exists: {gw['gatewayId']}")
        else:
            base = dict(name=f"{PREFIX}-gateway", roleArn=self.state["gateway_role_arn"],
                        protocolType="MCP", authorizerType="CUSTOM_JWT",
                        description="Entra ID identity propagation lab",
                        protocolConfiguration={"mcp": {"instructions": "Department document tools"}})
            for attempt in range(8):
                try:
                    try:
                        gw = self.ac.create_gateway(authorizerConfiguration=self.authorizer(self.custom_claims), **base)
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "ValidationException" or not self.custom_claims:
                            raise
                        log(f"  gateway rejected customClaims ({e.response['Error']['Message'][:150]}); "
                            "falling back to audience-only. The interceptor still enforces tid and azp.")
                        self.custom_claims = False
                        gw = self.ac.create_gateway(authorizerConfiguration=self.authorizer(False), **base)
                    break
                except ClientError as e:
                    if "assume" in str(e).lower() and attempt < 7:  # role propagation
                        time.sleep(8)
                        continue
                    raise
            log(f"created gateway {gw['gatewayId']}")
        gw = self.wait(self.ac.get_gateway, {"READY"}, {"FAILED"}, "gateway", gatewayIdentifier=gw["gatewayId"])
        self.state.update(gateway_id=gw["gatewayId"], gateway_arn=gw["gatewayArn"], gateway_url=gw["gatewayUrl"])

        targets = self.ac.list_gateway_targets(gatewayIdentifier=gw["gatewayId"]).get("items", [])
        target = next((t for t in targets if t.get("name") == "docs"), None)
        tool_schema = json.load(open(os.path.join(HERE, "tool_schema.json")))
        cfg = dict(gatewayIdentifier=gw["gatewayId"], name="docs",
                   description="Department documents in S3, accessed with the caller's tagged session",
                   targetConfiguration={"mcp": {"lambda": {"lambdaArn": self.state["tool_arn"],
                                                           "toolSchema": {"inlinePayload": tool_schema}}}},
                   credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE"}])
        if target:
            self.ac.update_gateway_target(targetId=target["targetId"], **cfg)
            tid = target["targetId"]
            log("updated gateway target docs")
        else:
            tid = self.ac.create_gateway_target(**cfg)["targetId"]
            log("created gateway target docs")
        self.wait(self.ac.get_gateway_target, {"READY"}, {"FAILED", "UPDATE_UNSUCCESSFUL"}, "gateway target",
                  gatewayIdentifier=gw["gatewayId"], targetId=tid)
        self.state["target_id"] = tid

    def update_gateway(self, interceptors, policy):
        gw = self.ac.get_gateway(gatewayIdentifier=self.state["gateway_id"])
        kw = dict(gatewayIdentifier=gw["gatewayId"], name=gw["name"], roleArn=gw["roleArn"],
                  protocolType="MCP", authorizerType="CUSTOM_JWT",
                  authorizerConfiguration=self.authorizer(self.custom_claims))
        if gw.get("description"):
            kw["description"] = gw["description"]
        if gw.get("protocolConfiguration"):
            kw["protocolConfiguration"] = gw["protocolConfiguration"]
        if interceptors:
            kw["interceptorConfigurations"] = [{
                "interceptor": {"lambda": {"arn": self.state["interceptor_arn"]}},
                "interceptionPoints": ["REQUEST", "RESPONSE"],
                "inputConfiguration": {"passRequestHeaders": True}}]
        if policy:
            kw["policyEngineConfiguration"] = {"arn": self.state["policy_engine_arn"], "mode": self.policy_mode}
        self.ac.update_gateway(**kw)
        self.wait(self.ac.get_gateway, {"READY"}, {"FAILED", "UPDATE_UNSUCCESSFUL"}, "gateway update",
                  gatewayIdentifier=gw["gatewayId"])

    # --------------------------------------------------------------- Cedar
    def deploy_policy(self):
        name = f"{PREFIX}_policy_engine"
        engine = None
        for page in self.ac.get_paginator("list_policy_engines").paginate():
            engine = next((p for p in page.get("policyEngines", []) if p.get("name") == name), engine)
        if not engine:
            engine = self.ac.create_policy_engine(name=name, description="Cedar policies for the agent lab")
            log(f"created policy engine {engine['policyEngineId']}")
        engine = self.wait(self.ac.get_policy_engine, {"ACTIVE"}, {"CREATE_FAILED"}, "policy engine",
                           policyEngineId=engine["policyEngineId"])
        self.state.update(policy_engine_id=engine["policyEngineId"], policy_engine_arn=engine["policyEngineArn"])

        v = dict(self.values, GATEWAY_ARN=self.state["gateway_arn"],
                 POLICY_ENGINE_ARN=engine["policyEngineArn"], POLICY_ENGINE_ID=engine["policyEngineId"])
        perms = render(os.path.join(HERE, "policies", "gateway_policy_engine.json"), **v)
        self.iam.put_role_policy(RoleName=f"{PREFIX}-gateway-role", PolicyName="policy-engine", PolicyDocument=perms)
        time.sleep(10)  # let the new permissions propagate

        existing = {}
        for page in self.ac.get_paginator("list_policies").paginate(policyEngineId=engine["policyEngineId"]):
            existing.update({p["name"]: p for p in page.get("policies", [])})
        # permit_all first (it is intentionally broad, so ignore that finding), then forbids.
        files = sorted(os.listdir(os.path.join(HERE, "cedar")), key=lambda f: (not f.startswith("permit"), f))
        for fn in files:
            pname = fn.replace(".cedar", "")
            stmt = render(os.path.join(HERE, "cedar", fn), GATEWAY_ARN=self.state["gateway_arn"])
            stmt = "\n".join(l for l in stmt.splitlines() if not l.strip().startswith("//")).strip()
            if pname in existing:
                log(f"policy {pname} exists")
                continue
            mode = "IGNORE_ALL_FINDINGS" if fn.startswith("permit") else "FAIL_ON_ANY_FINDINGS"
            try:
                p = self.ac.create_policy(policyEngineId=engine["policyEngineId"], name=pname,
                                          definition={"cedar": {"statement": stmt}}, validationMode=mode)
            except ClientError as e:
                log(f"  {pname}: {e.response['Error']['Message'][:200]}; retrying with IGNORE_ALL_FINDINGS")
                p = self.ac.create_policy(policyEngineId=engine["policyEngineId"], name=pname,
                                          definition={"cedar": {"statement": stmt}},
                                          validationMode="IGNORE_ALL_FINDINGS")
            self.wait(self.ac.get_policy, {"ACTIVE"}, {"CREATE_FAILED"}, f"policy {pname}",
                      policyEngineId=engine["policyEngineId"], policyId=p["policyId"])
            log(f"created Cedar policy {pname}")

    # ----------------------------------------------------------------- run
    def run(self, with_policy):
        log(f"account {self.account}, region {self.region}")
        self.deploy_iam()
        self.deploy_data()
        self.deploy_lambdas()
        self.deploy_gateway()
        if with_policy:
            gw = self.ac.get_gateway(gatewayIdentifier=self.state["gateway_id"])
            if gw.get("interceptorConfigurations"):
                log("detaching interceptor while Cedar policies are created")
                self.update_gateway(interceptors=False, policy=False)
            self.deploy_policy()
        log("attaching interceptor" + (f" and policy engine ({self.policy_mode})" if with_policy else ""))
        self.update_gateway(interceptors=True, policy=with_policy)
        self.state["policy_mode"] = self.policy_mode if with_policy else "NONE"
        self.state["gateway_custom_claims"] = self.custom_claims
        with open(os.path.join(LAB, "aws.json"), "w") as f:
            json.dump(self.state, f, indent=2)
        log(f"done. Gateway URL: {self.state['gateway_url']}")
        log("state saved to .lab/aws.json. Next: python client/run_scenarios.py")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--policy-mode", choices=["ENFORCE", "LOG_ONLY"], default="ENFORCE")
    ap.add_argument("--no-policy", action="store_true", help="skip the Cedar policy engine")
    ap.add_argument("--no-custom-claims", action="store_true",
                    help="troubleshooting: validate only the audience at the gateway (interceptor still checks tid/azp)")
    a = ap.parse_args()
    if not os.path.exists(os.path.join(LAB, "entra.json")):
        sys.exit("Run entra/setup_entra.py first (it writes .lab/entra.json).")
    Deployer(a.region, a.policy_mode, custom_claims=not a.no_custom_claims).run(with_policy=not a.no_policy)


if __name__ == "__main__":
    main()
