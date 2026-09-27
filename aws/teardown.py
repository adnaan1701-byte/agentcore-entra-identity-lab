"""
Delete everything aws/deploy.py created, in dependency order.

  python aws/teardown.py --region us-east-1
"""

import argparse
import json
import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(os.path.dirname(HERE), ".lab")
PREFIX = "agentlab"


def log(m):
    print(f"[teardown] {m}", flush=True)


def quiet(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "NoSuchEntity", "NoSuchBucket", "404",
                        "TrailNotFoundException"):
            log(f"  warning: {fn.__name__}: {code}: {e.response['Error'].get('Message', '')[:150]}")


def gone(getter, **kw):
    for _ in range(60):
        try:
            getter(**kw)
            time.sleep(5)
        except ClientError:
            return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    a = ap.parse_args()
    s = boto3.Session(region_name=a.region)
    account = s.client("sts").get_caller_identity()["Account"]
    ac, iam, lam, ddb, s3 = (s.client(x) for x in
                             ("bedrock-agentcore-control", "iam", "lambda", "dynamodb", "s3"))

    # Gateway: detach interceptor + policy engine, delete targets, then the gateway.
    for page in ac.get_paginator("list_gateways").paginate():
        for g in page.get("items", []):
            if g.get("name") != f"{PREFIX}-gateway":
                continue
            gw = ac.get_gateway(gatewayIdentifier=g["gatewayId"])
            quiet(ac.update_gateway, gatewayIdentifier=gw["gatewayId"], name=gw["name"], roleArn=gw["roleArn"],
                  protocolType="MCP", authorizerType=gw["authorizerType"],
                  authorizerConfiguration=gw["authorizerConfiguration"])
            time.sleep(10)
            for t in ac.list_gateway_targets(gatewayIdentifier=gw["gatewayId"]).get("items", []):
                quiet(ac.delete_gateway_target, gatewayIdentifier=gw["gatewayId"], targetId=t["targetId"])
                gone(ac.get_gateway_target, gatewayIdentifier=gw["gatewayId"], targetId=t["targetId"])
                log(f"deleted target {t['name']}")
            quiet(ac.delete_gateway, gatewayIdentifier=gw["gatewayId"])
            gone(ac.get_gateway, gatewayIdentifier=gw["gatewayId"])
            log(f"deleted gateway {gw['gatewayId']}")

    # Policy engine: delete policies first.
    for page in ac.get_paginator("list_policy_engines").paginate():
        for pe in page.get("policyEngines", []):
            if pe.get("name") != f"{PREFIX}_policy_engine":
                continue
            pid = pe["policyEngineId"]
            for pp in ac.get_paginator("list_policies").paginate(policyEngineId=pid):
                for p in pp.get("policies", []):
                    quiet(ac.delete_policy, policyEngineId=pid, policyId=p["policyId"])
                    gone(ac.get_policy, policyEngineId=pid, policyId=p["policyId"])
                    log(f"deleted policy {p['name']}")
            quiet(ac.delete_policy_engine, policyEngineId=pid)
            log(f"deleted policy engine {pid}")

    for fn in (f"{PREFIX}-interceptor", f"{PREFIX}-docs-tool"):
        quiet(lam.delete_function, FunctionName=fn)
        quiet(s.client("logs").delete_log_group, logGroupName=f"/aws/lambda/{fn}")
        log(f"deleted function {fn}")

    for role in (f"{PREFIX}-user-scoped-role", f"{PREFIX}-interceptor-role",
                 f"{PREFIX}-docs-tool-role", f"{PREFIX}-gateway-role"):
        try:
            for p in iam.list_role_policies(RoleName=role)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role, PolicyName=p)
            for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role, PolicyArn=p["PolicyArn"])
            iam.delete_role(RoleName=role)
            log(f"deleted role {role}")
        except iam.exceptions.NoSuchEntityException:
            pass

    for table in (f"{PREFIX}-hr-attributes", f"{PREFIX}-employees"):
        quiet(ddb.delete_table, TableName=table)
        log(f"deleted table {table}")

    bucket = f"{PREFIX}-data-{account}-{a.region}"
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
        log(f"deleted bucket {bucket}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            log(f"  warning: bucket: {e}")

    # Module V: CloudTrail data-event trail and its log bucket.
    ct = s.client("cloudtrail")
    quiet(ct.stop_logging, Name=f"{PREFIX}-data-trail")
    quiet(ct.delete_trail, Name=f"{PREFIX}-data-trail")
    log_bucket = f"{PREFIX}-trail-{account}-{a.region}"
    for attempt in range(3):  # CloudTrail may drop one last log file just after the trail is deleted
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=log_bucket):
                objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                        for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objs:
                    s3.delete_objects(Bucket=log_bucket, Delete={"Objects": objs})
            s3.delete_bucket(Bucket=log_bucket)
            log(f"deleted trail and log bucket {log_bucket}")
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchBucket":
                break
            if code == "BucketNotEmpty" and attempt < 2:
                time.sleep(30)
                continue
            log(f"  warning: log bucket: {e}")
            break

    # Module C: Macie custom identifier, and Macie itself if the lab turned it on.
    dspm_path = os.path.join(LAB, "dspm.json")
    if os.path.exists(dspm_path):
        dspm = json.load(open(dspm_path))
        macie = s.client("macie2")
        if dspm.get("custom_identifier_id"):
            quiet(macie.delete_custom_data_identifier, id=dspm["custom_identifier_id"])
        if dspm.get("macie_enabled_by_lab"):
            quiet(macie.disable_macie)
            log("disabled Amazon Macie (the lab had enabled it)")
        else:
            log("left Amazon Macie enabled (it was already on before the lab)")

    for name in ("aws.json", "dspm.json", "monitor.json"):
        path = os.path.join(LAB, name)
        if os.path.exists(path):
            os.remove(path)
    log("AWS teardown complete. Run entra/teardown_entra.py to remove the Entra objects.")


if __name__ == "__main__":
    sys.exit(main())
