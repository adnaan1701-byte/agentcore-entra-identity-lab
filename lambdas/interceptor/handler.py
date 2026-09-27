"""
AgentCore Gateway interceptor: Entra ID identity -> STS session tags.

One Lambda handles both interception points:

REQUEST  (tools/call)
  1. Re-validate the Entra ID v2 access token (defense in depth; the gateway
     already validated it): signature, issuer, audience, tenant, calling app.
  2. Map claims to the attribute contract (app role -> dept + role).
  3. Look up the high-risk attribute (clearance) live from the HR store.
  4. Call sts:AssumeRole on the user-scoped role with session tags and
     SourceIdentity = the user's Entra object ID.
  5. Strip any client-supplied `_ctx` and inject the trusted `_ctx`
     (identity + short-lived credentials) into the tool arguments.
  Any failure -> fail closed with a JSON-RPC error.

RESPONSE (tools/list)
  Filter the tool list so each user only sees tools they may call.
  Everything else passes through unchanged.

Tokens and credentials are never logged.
"""

import json
import logging
import os
import time

import boto3
import jwt
from jwt import PyJWKClient

log = logging.getLogger()
log.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Configuration (set by aws/deploy.py as Lambda environment variables)
# ---------------------------------------------------------------------------
TENANT_ID = os.environ.get("TENANT_ID", "")
API_APP_ID = os.environ.get("API_APP_ID", "")  # expected `aud` (v2 tokens)
ALLOWED_CLIENT_IDS = {c for c in os.environ.get("ALLOWED_CLIENT_IDS", "").split(",") if c}
USER_ROLE_ARN = os.environ.get("USER_ROLE_ARN", "")
HR_TABLE = os.environ.get("HR_TABLE", "")
SESSION_SECONDS = int(os.environ.get("SESSION_SECONDS", "900"))
ISSUER = os.environ.get("ISSUER") or f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
JWKS_URI = os.environ.get("JWKS_URI") or f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
LEEWAY_SECONDS = 120

# ---------------------------------------------------------------------------
# Attribute contract (see docs/DESIGN.md). Closed value sets: anything else
# is rejected, never passed through.
# ---------------------------------------------------------------------------
ROLE_CONTRACT = {
    "Finance.Analyst": {"dept": "fin", "role": "analyst"},
    "Finance.Contractor": {"dept": "fin", "role": "contractor"},
    "HR.Manager": {"dept": "hr", "role": "manager"},
}
ALLOWED_CLEARANCE = {"public", "internal", "restr"}

# Tool visibility for tools/list filtering (least knowledge). Cedar policy is
# the enforcement point; this only hides what a user can't use anyway.
TOOL_VISIBLE_TO_ROLES = {
    "export_all_records": {"manager"},
    "query_employees": {"analyst", "manager"},  # contractors are not subscribed (data_policies.json)
}
SYSTEM_TOOLS_HIDDEN = {"x_amz_bedrock_agentcore_search"}

_jwks_client = None
_sts = None
_ddb = None


class Denied(Exception):
    """Raised for any identity or policy failure. Message is safe to return."""

    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def _jwks():
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(JWKS_URI, cache_keys=True, lifespan=3600)
    return _jwks_client


def _clients():
    global _sts, _ddb
    if _sts is None:
        _sts = boto3.client("sts")
        _ddb = boto3.client("dynamodb")
    return _sts, _ddb


# ---------------------------------------------------------------------------
# Token handling
# ---------------------------------------------------------------------------
def _header(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def bearer_token(headers):
    value = _header(headers, "Authorization") or ""
    if not value.lower().startswith("bearer "):
        raise Denied("missing bearer token (is passRequestHeaders enabled?)", 401)
    return value.split(" ", 1)[1].strip()


def validate_entra_token(token):
    """Validate an Entra ID v2 access token. Returns claims or raises Denied."""
    try:
        signing_key = _jwks().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=API_APP_ID,
            issuer=ISSUER,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise Denied("token expired", 401)
    except jwt.InvalidAudienceError:
        raise Denied("token audience is not this gateway API", 401)
    except jwt.InvalidIssuerError:
        raise Denied("token issuer mismatch (v1 token or wrong tenant?)", 401)
    except jwt.PyJWTError as exc:
        raise Denied(f"token rejected: {type(exc).__name__}", 401)

    if claims.get("ver") != "2.0":
        raise Denied("only Entra v2.0 access tokens are accepted", 401)
    if claims.get("tid") != TENANT_ID:
        raise Denied("token is from another tenant", 401)
    if claims.get("azp") not in ALLOWED_CLIENT_IDS:
        raise Denied("calling application is not allowlisted", 403)
    if not claims.get("oid"):
        raise Denied("token has no oid (app-only tokens are not allowed)", 403)
    return claims


# ---------------------------------------------------------------------------
# Attribute contract mapping
# ---------------------------------------------------------------------------
def map_roles(claims):
    roles = claims.get("roles") or []
    mapped = [ROLE_CONTRACT[r] for r in roles if r in ROLE_CONTRACT]
    if len(mapped) != 1:
        # Contract rule: exactly one recognised app role per user.
        raise Denied(f"user must hold exactly one recognised app role (found {len(mapped)})")
    return mapped[0]


def lookup_clearance(oid):
    _, ddb = _clients()
    item = ddb.get_item(TableName=HR_TABLE, Key={"oid": {"S": oid}}, ConsistentRead=True).get("Item")
    if not item or "clearance" not in item:
        raise Denied("no HR record for user (clearance unknown)")
    clearance = item["clearance"]["S"]
    if clearance not in ALLOWED_CLEARANCE:
        raise Denied("HR record has an unrecognised clearance value")
    return clearance


def build_identity(claims):
    attrs = map_roles(claims)
    return {
        "user": claims["oid"],
        "upn": claims.get("preferred_username", ""),
        "tenant": claims["tid"],
        "dept": attrs["dept"],
        "role": attrs["role"],
        "clr": lookup_clearance(claims["oid"]),
    }


def mint_session(identity):
    sts, _ = _clients()
    tags = {k: identity[k] for k in ("dept", "role", "clr", "tenant")}
    try:
        resp = sts.assume_role(
            RoleArn=USER_ROLE_ARN,
            RoleSessionName=f"agentlab-{identity['user'][:8]}-{int(time.time())}",
            SourceIdentity=identity["user"],
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
            TransitiveTagKeys=list(tags),
            DurationSeconds=SESSION_SECONDS,
        )
    except Exception as exc:  # botocore ClientError and friends
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        raise Denied(f"STS refused the tagged session: {code}")
    c = resp["Credentials"]
    return {
        "AccessKeyId": c["AccessKeyId"],
        "SecretAccessKey": c["SecretAccessKey"],
        "SessionToken": c["SessionToken"],
        "Expiration": c["Expiration"].isoformat() if hasattr(c["Expiration"], "isoformat") else str(c["Expiration"]),
    }


# ---------------------------------------------------------------------------
# Output helpers (AgentCore interceptor contract, interceptorOutputVersion 1.0)
# ---------------------------------------------------------------------------
def pass_request(headers, body):
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayRequest": {"headers": headers, "body": body}}}


def deny(body, message, status=403):
    rpc_id = body.get("id") if isinstance(body, dict) else None
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayResponse": {
                "statusCode": status,
                "body": {"jsonrpc": "2.0", "id": rpc_id,
                         "error": {"code": -32001, "message": f"[interceptor] {message}"}}}}}


def pass_response(resp, body=None):
    return {"interceptorOutputVersion": "1.0",
            "mcp": {"transformedGatewayResponse": {
                "statusCode": resp.get("statusCode", 200),
                "headers": resp.get("headers") or {},
                "body": resp.get("body") if body is None else body}}}


def audit(event_type, **fields):
    log.info(json.dumps({"audit": event_type, **fields}))


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def handle_request(req):
    headers = req.get("headers") or {}
    body = req.get("body") or {}
    method = body.get("method")

    if method != "tools/call":
        return pass_request(headers, body)

    tool = (body.get("params") or {}).get("name", "")
    try:
        claims = validate_entra_token(bearer_token(headers))
        identity = build_identity(claims)
        creds = mint_session(identity)
    except Denied as d:
        audit("deny", tool=tool, reason=str(d))
        return deny(body, str(d), d.status)

    params = body.setdefault("params", {})
    args = params.get("arguments") or {}
    forged = "_ctx" in args
    args.pop("_ctx", None)  # never trust identity supplied by the client/model
    args["_ctx"] = {**identity, "credentials": creds}
    params["arguments"] = args

    audit("allow", tool=tool, user=identity["user"], dept=identity["dept"],
          role=identity["role"], clr=identity["clr"], forged_ctx_stripped=forged)
    clean_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
    return pass_request(clean_headers, body)


def handle_response(req, resp):
    body = req.get("body") or {}
    rbody = resp.get("body")
    if body.get("method") != "tools/list" or not isinstance(rbody, dict):
        return pass_response(resp)
    tools = (rbody.get("result") or {}).get("tools")
    if tools is None:
        return pass_response(resp)

    try:
        claims = validate_entra_token(bearer_token(req.get("headers")))
        role = map_roles(claims)["role"]
    except Denied as d:
        audit("tools_list_empty", reason=str(d))
        role = None  # fail closed: show nothing

    visible = []
    for t in tools:
        short = t.get("name", "").split("___")[-1]
        if short in SYSTEM_TOOLS_HIDDEN or role is None:
            continue
        allowed_roles = TOOL_VISIBLE_TO_ROLES.get(short)
        if allowed_roles is None or role in allowed_roles:
            visible.append(t)

    audit("tools_list_filtered", role=role, shown=[t["name"] for t in visible], total=len(tools))
    new_body = {**rbody, "result": {**rbody["result"], "tools": visible}}
    return pass_response(resp, new_body)


def lambda_handler(event, context):
    mcp = event.get("mcp") or {}
    req = mcp.get("gatewayRequest") or {}
    if "gatewayResponse" in mcp and mcp["gatewayResponse"] is not None:
        return handle_response(req, mcp["gatewayResponse"])
    return handle_request(req)
