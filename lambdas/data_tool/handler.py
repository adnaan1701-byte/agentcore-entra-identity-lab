"""
Document tool behind AgentCore Gateway (Lambda target "docs").

This function's own IAM role has NO S3 permissions. Every S3 call uses the
short-lived, tagged credentials the interceptor minted for the human caller,
so S3 ABAC decides what comes back.

Tools:
  list_documents       - list objects in the caller's department prefix
  read_document(key)   - read one object
  export_all_records   - bulk read of the department prefix (managers only,
                         enforced by Cedar policy at the gateway)
  query_employees      - structured query of the employee directory, with
                         Immuta-style row and column policies (data_policy.py)
                         and DynamoDB fine-grained access control underneath
"""

import json
import os

from decimal import Decimal

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

import data_policy

BUCKET = os.environ.get("DATA_BUCKET", "")
EMPLOYEES_TABLE = os.environ.get("EMPLOYEES_TABLE", "")


def _session(ctx):
    c = ctx["credentials"]
    return boto3.session.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
    )


def _denied(layer, detail, **extra):
    return {"status": "DENIED", "layer": layer, "detail": detail, **extra}


def list_documents(s3, ctx):
    prefix = f"{ctx['dept']}/"
    try:
        resp = s3.list_objects_v2(Bucket=BUCKET, Prefix=prefix)
    except ClientError as e:
        return _denied("s3-abac", e.response["Error"]["Code"], prefix=prefix)
    return {"status": "ALLOWED", "prefix": prefix,
            "keys": [o["Key"] for o in resp.get("Contents", [])]}


def read_document(s3, ctx, key):
    if not key:
        return {"status": "ERROR", "detail": "key is required"}
    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
    except ClientError as e:
        return _denied("s3-abac", e.response["Error"]["Code"], key=key)
    return {"status": "ALLOWED", "key": key, "content": obj["Body"].read().decode("utf-8")[:2000]}


def export_all_records(s3, ctx):
    listing = list_documents(s3, ctx)
    if listing["status"] != "ALLOWED":
        return listing
    results = {k: read_document(s3, ctx, k)["status"] for k in listing["keys"]}
    return {"status": "ALLOWED", "exported": [k for k, v in results.items() if v == "ALLOWED"],
            "blocked": [k for k, v in results.items() if v != "ALLOWED"]}


def _plain(v):
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    return v


def query_employees(sess, ctx, requested_dept=None):
    decision = data_policy.evaluate(ctx, requested_dept=requested_dept)
    policy_view = {k: decision[k] for k in ("row_filter", "masked_columns", "notes")}
    if not decision["allowed"]:
        return _denied("data-policy", decision["reason"], data_source=decision["data_source"])

    rf = decision["row_filter"]
    ddb = sess.client("dynamodb")
    try:
        # Ask only for the visible columns. The session's IAM policy refuses
        # sensitive columns unless clr=restr, so this is also enforced by AWS.
        resp = ddb.query(TableName=EMPLOYEES_TABLE,
                         KeyConditionExpression=f"{rf['column']} = :v",
                         ExpressionAttributeValues={":v": {"S": rf["value"]}},
                         ProjectionExpression=", ".join(decision["visible_columns"]),
                         Select="SPECIFIC_ATTRIBUTES")
    except ClientError as e:
        return _denied("dynamodb-fgac", e.response["Error"]["Code"], policy=policy_view)

    des = TypeDeserializer()
    rows = [{k: _plain(des.deserialize(v)) for k, v in item.items()} for item in resp.get("Items", [])]
    columns = data_policy.load_policy()["columns"]
    return {"status": "ALLOWED", "data_source": decision["data_source"], "row_count": len(rows),
            "rows": data_policy.apply_masks(rows, decision, columns), "policy": policy_view}


def lambda_handler(event, context):
    full_name = context.client_context.custom["bedrockAgentCoreToolName"]
    tool = full_name.split("___", 1)[-1]
    ctx = event.get("_ctx")
    if not ctx or "credentials" not in ctx:
        # Direct invocation or interceptor missing: refuse rather than fall back
        # to this function's own identity.
        return _denied("tool", "no trusted identity context; call must come through the gateway interceptor")

    sess = _session(ctx)
    s3 = sess.client("s3")
    acting_as = sess.client("sts").get_caller_identity()["Arn"]

    if tool == "list_documents":
        result = list_documents(s3, ctx)
    elif tool == "read_document":
        result = read_document(s3, ctx, event.get("key", ""))
    elif tool == "export_all_records":
        result = export_all_records(s3, ctx)
    elif tool == "query_employees":
        result = query_employees(sess, ctx, event.get("dept"))
    else:
        result = {"status": "ERROR", "detail": f"unknown tool {tool}"}

    result["acting_as"] = acting_as
    result["on_behalf_of"] = {k: ctx.get(k) for k in ("upn", "dept", "role", "clr")}
    print(json.dumps({"tool": tool, "status": result["status"], "acting_as": acting_as,
                      "user": ctx.get("user")}))
    return result
