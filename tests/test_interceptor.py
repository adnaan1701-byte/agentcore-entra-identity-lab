"""
Local tests for the interceptor. No cloud accounts needed.

A throwaway RSA key plays the role of Entra ID: a local HTTP server publishes
its JWKS, and tokens are minted with the same claim shapes Entra v2 uses.
moto fakes STS and DynamoDB.

  pip install -r requirements-dev.txt
  pytest -q
"""

import importlib
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import boto3
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TENANT = "11111111-2222-3333-4444-555555555555"
API_APP = "aaaaaaaa-0000-0000-0000-000000000001"
CLIENT_APP = "cccccccc-0000-0000-0000-000000000002"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
KID = "lab-key-1"
ALICE, BOB, CAROL = (str(uuid.uuid4()) for _ in range(3))

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _JWKS(BaseHTTPRequestHandler):
    def do_GET(self):
        jwk = json.loads(RSAAlgorithm.to_jwk(_key.public_key()))
        jwk.update(kid=KID, use="sig", alg="RS256")
        body = json.dumps({"keys": [jwk]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def jwks_url():
    srv = HTTPServer(("127.0.0.1", 0), _JWKS)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/keys"
    srv.shutdown()


def token(oid=ALICE, roles=("Finance.Analyst",), key=_key, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": API_APP, "azp": CLIENT_APP, "tid": TENANT, "oid": oid,
              "roles": list(roles), "scp": "access_as_user", "ver": "2.0",
              "preferred_username": "alice.agentlab@contoso.example", "iat": now, "nbf": now, "exp": now + 3600}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


@pytest.fixture
def ic(jwks_url, monkeypatch):
    """Fresh interceptor module wired to moto STS/DynamoDB and the local JWKS."""
    env = dict(TENANT_ID=TENANT, API_APP_ID=API_APP, ALLOWED_CLIENT_IDS=CLIENT_APP,
               HR_TABLE="hr", JWKS_URI=jwks_url, SESSION_SECONDS="900",
               AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        iam = boto3.client("iam")
        role = iam.create_role(RoleName="agentlab-user-scoped-role", AssumeRolePolicyDocument="{}")["Role"]["Arn"]
        monkeypatch.setenv("USER_ROLE_ARN", role)
        ddb = boto3.client("dynamodb")
        ddb.create_table(TableName="hr", BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "oid", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "oid", "KeyType": "HASH"}])
        for oid, clr in ((ALICE, "internal"), (BOB, "restr"), (CAROL, "public")):
            ddb.put_item(TableName="hr", Item={"oid": {"S": oid}, "clearance": {"S": clr}})
        sys.path.insert(0, os.path.join(ROOT, "lambdas", "interceptor"))
        import handler
        mod = importlib.reload(handler)
        sys.path.pop(0)
        yield mod


def call_event(tok, tool="docs___read_document", args=None, header="Authorization"):
    headers = {"Content-Type": "application/json"}
    if tok is not None:
        headers[header] = f"Bearer {tok}"
    return {"interceptorInputVersion": "1.0", "mcp": {"gatewayRequest": {
        "path": "/mcp", "httpMethod": "POST", "headers": headers,
        "body": {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                 "params": {"name": tool, "arguments": args if args is not None else {"key": "fin/q3-revenue.csv"}}}}}}


def list_response_event(tok, tools):
    return {"interceptorInputVersion": "1.0", "mcp": {
        "gatewayRequest": {"headers": {"Authorization": f"Bearer {tok}"},
                           "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}},
        "gatewayResponse": {"statusCode": 200, "headers": {},
                            "body": {"jsonrpc": "2.0", "id": 1,
                                     "result": {"tools": [{"name": f"docs___{t}"} for t in tools]}}}}}


def error_of(out):
    resp = out["mcp"].get("transformedGatewayResponse")
    return resp and resp["body"]["error"]["message"]


# ------------------------------------------------------------------ allow path
def test_alice_gets_tagged_session_and_ctx(ic):
    out = ic.lambda_handler(call_event(token()), None)
    assert error_of(out) is None
    req = out["mcp"]["transformedGatewayRequest"]
    ctx = req["body"]["params"]["arguments"]["_ctx"]
    assert (ctx["dept"], ctx["role"], ctx["clr"], ctx["user"]) == ("fin", "analyst", "internal", ALICE)
    assert set(ctx["credentials"]) == {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
    assert req["body"]["params"]["arguments"]["key"] == "fin/q3-revenue.csv"
    assert not any(k.lower() == "authorization" for k in req["headers"]), "token must not be forwarded to the tool"


def test_assume_role_called_with_contract_tags(ic, monkeypatch):
    seen = {}
    real = ic._clients()[0].assume_role

    def spy(**kw):
        seen.update(kw)
        return real(**kw)

    monkeypatch.setattr(ic._clients()[0], "assume_role", spy)
    ic.lambda_handler(call_event(token(oid=BOB, roles=["HR.Manager"])), None)
    assert seen["SourceIdentity"] == BOB
    assert {t["Key"]: t["Value"] for t in seen["Tags"]} == {"dept": "hr", "role": "manager", "clr": "restr", "tenant": TENANT}
    assert set(seen["TransitiveTagKeys"]) == {"dept", "role", "clr", "tenant"}
    assert seen["DurationSeconds"] == 900


def test_lowercase_authorization_header_is_accepted(ic):
    out = ic.lambda_handler(call_event(token(), header="authorization"), None)
    assert error_of(out) is None


def test_forged_ctx_is_replaced(ic):
    forged = {"key": "hr/salaries.csv", "_ctx": {"dept": "hr", "clr": "restr",
                                                 "credentials": {"AccessKeyId": "FAKE"}}}
    out = ic.lambda_handler(call_event(token(), args=forged), None)
    ctx = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]["_ctx"]
    assert ctx["dept"] == "fin" and ctx["clr"] == "internal"
    assert ctx["credentials"]["AccessKeyId"] != "FAKE"


def test_non_call_methods_pass_through(ic):
    ev = {"mcp": {"gatewayRequest": {"headers": {}, "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}}}
    out = ic.lambda_handler(ev, None)
    assert out["mcp"]["transformedGatewayRequest"]["body"]["method"] == "tools/list"


# ------------------------------------------------------------------ deny paths
@pytest.mark.parametrize("desc,tok,expect", [
    ("no token", None, "missing bearer token"),
    ("wrong audience", lambda: token(aud="00000003-0000-0000-c000-000000000000"), "audience"),
    ("v1 issuer", lambda: token(iss=f"https://sts.windows.net/{TENANT}/"), "issuer"),
    ("expired", lambda: token(exp=int(time.time()) - 3600, iat=int(time.time()) - 7200), "expired"),
    ("signed by another key", lambda: token(key=_other_key), "token rejected"),
    ("other tenant", lambda: token(tid="99999999-0000-0000-0000-000000000000"), "another tenant"),
    ("unlisted client app", lambda: token(azp="dddddddd-0000-0000-0000-000000000009"), "not allowlisted"),
    ("v1 token version", lambda: token(ver="1.0"), "v2.0"),
    ("app-only token", lambda: token(oid=None), "no oid"),
    ("no app role", lambda: token(roles=[]), "exactly one"),
    ("two app roles", lambda: token(roles=["Finance.Analyst", "HR.Manager"]), "exactly one"),
    ("unknown role", lambda: token(roles=["Sales.Rep"]), "exactly one"),
    ("no HR record", lambda: token(oid=str(uuid.uuid4())), "no HR record"),
])
def test_denials_fail_closed(ic, desc, tok, expect):
    t = tok() if callable(tok) else tok
    out = ic.lambda_handler(call_event(t), None)
    msg = error_of(out)
    assert msg and msg.startswith("[interceptor]") and expect in msg, f"{desc}: {msg}"
    assert "transformedGatewayRequest" not in out["mcp"], "denied request must not reach the tool"


def test_sts_refusal_fails_closed(ic, monkeypatch):
    from botocore.exceptions import ClientError

    def boom(**kw):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "tag not allowed"}}, "AssumeRole")

    monkeypatch.setattr(ic._clients()[0], "assume_role", boom)
    msg = error_of(ic.lambda_handler(call_event(token()), None))
    assert "STS refused" in msg and "AccessDenied" in msg


def test_bad_clearance_value_in_hr_store(ic):
    boto3.client("dynamodb").put_item(TableName="hr", Item={"oid": {"S": ALICE}, "clearance": {"S": "top-secret"}})
    assert "unrecognised clearance" in error_of(ic.lambda_handler(call_event(token()), None))


# ------------------------------------------------------------ response filtering
TOOLS = ["list_documents", "read_document", "export_all_records", "query_employees",
         "x_amz_bedrock_agentcore_search"]


def shown(out):
    return {t["name"].split("___")[-1] for t in out["mcp"]["transformedGatewayResponse"]["body"]["result"]["tools"]}


def test_manager_sees_export_tool(ic):
    out = ic.lambda_handler(list_response_event(token(oid=BOB, roles=["HR.Manager"]), TOOLS), None)
    assert shown(out) == {"list_documents", "read_document", "export_all_records", "query_employees"}


def test_analyst_sees_directory_but_not_export(ic):
    out = ic.lambda_handler(list_response_event(token(), TOOLS), None)
    assert shown(out) == {"list_documents", "read_document", "query_employees"}


def test_contractor_does_not_see_export_tool(ic):
    out = ic.lambda_handler(list_response_event(token(oid=CAROL, roles=["Finance.Contractor"]), TOOLS), None)
    assert shown(out) == {"list_documents", "read_document"}


def test_invalid_token_sees_no_tools(ic):
    out = ic.lambda_handler(list_response_event(token(key=_other_key), TOOLS), None)
    assert shown(out) == set()


def test_other_responses_pass_through(ic):
    ev = list_response_event(token(), TOOLS)
    ev["mcp"]["gatewayRequest"]["body"]["method"] = "tools/call"
    ev["mcp"]["gatewayResponse"]["body"] = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
    out = ic.lambda_handler(ev, None)
    assert out["mcp"]["transformedGatewayResponse"]["body"]["result"] == {"content": []}
