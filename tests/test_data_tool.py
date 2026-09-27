"""Local tests for the docs tool Lambda (moto fakes S3/STS; IAM is not enforced by moto,
so AccessDenied is simulated to check the tool reports the S3 ABAC layer correctly)."""

import importlib
import os
import sys
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ctx_for(tool):
    return SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"docs___{tool}"}))


@pytest.fixture
def tool(monkeypatch):
    for k, v in dict(AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="testing",
                     AWS_SECRET_ACCESS_KEY="testing", DATA_BUCKET="lab-bucket").items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="lab-bucket")
        s3.put_object(Bucket="lab-bucket", Key="fin/q3-revenue.csv", Body=b"quarter,revenue\nQ3,1\n")
        s3.put_object(Bucket="lab-bucket", Key="fin/team-handbook.md", Body=b"# handbook\n")
        s3.put_object(Bucket="lab-bucket", Key="hr/salaries.csv", Body=b"secret\n")
        sys.path.insert(0, os.path.join(ROOT, "lambdas", "data_tool"))
        import handler
        mod = importlib.reload(handler)
        sys.path.pop(0)
        yield mod


def identity(dept="fin"):
    creds = boto3.client("sts").assume_role(RoleArn="arn:aws:iam::123456789012:role/x",
                                            RoleSessionName="test")["Credentials"]
    return {"user": "oid-1", "upn": "alice@x", "dept": dept, "role": "analyst", "clr": "internal",
            "credentials": {k: creds[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")}}


def test_refuses_without_trusted_context(tool):
    out = tool.lambda_handler({"key": "fin/q3-revenue.csv"}, ctx_for("read_document"))
    assert out["status"] == "DENIED" and out["layer"] == "tool"


def test_uses_the_callers_session_not_its_own_role(tool, monkeypatch):
    captured = {}
    real = boto3.session.Session

    def spy(**kw):
        captured.update(kw)
        return real(**kw)

    monkeypatch.setattr(tool.boto3.session, "Session", spy)
    ident = identity()
    tool.lambda_handler({"key": "fin/q3-revenue.csv", "_ctx": ident}, ctx_for("read_document"))
    assert captured["aws_access_key_id"] == ident["credentials"]["AccessKeyId"]
    assert captured["aws_session_token"] == ident["credentials"]["SessionToken"]


def test_read_and_list(tool):
    out = tool.lambda_handler({"key": "fin/q3-revenue.csv", "_ctx": identity()}, ctx_for("read_document"))
    assert out["status"] == "ALLOWED" and "revenue" in out["content"]
    assert out["on_behalf_of"]["dept"] == "fin" and "acting_as" in out
    listing = tool.lambda_handler({"_ctx": identity()}, ctx_for("list_documents"))
    assert listing["prefix"] == "fin/" and set(listing["keys"]) == {"fin/q3-revenue.csv", "fin/team-handbook.md"}


def test_access_denied_is_reported_as_s3_abac(tool, monkeypatch):
    monkeypatch.setattr(tool, "read_document",
                        lambda s3, ctx, key: tool._denied("s3-abac", "AccessDenied", key=key))
    out = tool.lambda_handler({"key": "hr/salaries.csv", "_ctx": identity()}, ctx_for("read_document"))
    assert out["status"] == "DENIED" and out["layer"] == "s3-abac"


def test_export_splits_allowed_and_blocked(tool, monkeypatch):
    real = tool.read_document

    def partial(s3, ctx, key):
        if key.endswith(".csv"):
            return tool._denied("s3-abac", "AccessDenied", key=key)
        return real(s3, ctx, key)

    monkeypatch.setattr(tool, "read_document", partial)
    out = tool.lambda_handler({"_ctx": identity()}, ctx_for("export_all_records"))
    assert out["exported"] == ["fin/team-handbook.md"] and out["blocked"] == ["fin/q3-revenue.csv"]
