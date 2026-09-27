"""Immuta-style policy engine (lambdas/data_tool/data_policy.py) and the query_employees tool."""

import copy
import importlib
import json
import os
import sys
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL_DIR = os.path.join(ROOT, "lambdas", "data_tool")
sys.path.insert(0, TOOL_DIR)
import data_policy  # noqa: E402

sys.path.remove(TOOL_DIR)

ALICE = {"dept": "fin", "role": "analyst", "clr": "internal"}
BOB = {"dept": "hr", "role": "manager", "clr": "restr"}
CAROL = {"dept": "fin", "role": "contractor", "clr": "public"}


# ------------------------------------------------------------------ engine
def test_policy_file_is_valid_and_masks_only_known_columns():
    p = data_policy.load_policy()
    masked = {c for d in p["data_policies"] if d["type"] == "mask" for c in d["columns"]}
    assert masked <= set(p["columns"])
    fgac = json.load(open(os.path.join(ROOT, "aws", "policies", "user_scoped_dynamodb_fgac.json")))
    iam_visible = set(fgac["Statement"][1]["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"])
    # The IAM backstop must allow exactly the columns the policy leaves unmasked for non-restricted users.
    assert iam_visible == set(p["columns"]) - masked


def test_analyst_gets_own_rows_with_pay_masked():
    d = data_policy.evaluate(ALICE)
    assert d["allowed"] and d["row_filter"] == {"column": "dept_code", "value": "fin"}
    assert d["masked_columns"] == ["bank_last4", "salary_usd"]
    assert "salary_usd" not in d["visible_columns"]


def test_manager_with_restricted_clearance_sees_everything():
    d = data_policy.evaluate(BOB)
    assert d["allowed"] and d["row_filter"]["value"] == "hr" and d["masked_columns"] == []


def test_contractor_is_not_subscribed():
    d = data_policy.evaluate(CAROL)
    assert not d["allowed"] and "subscription policy" in d["reason"]


def test_requested_department_cannot_widen_the_row_filter():
    d = data_policy.evaluate(ALICE, requested_dept="hr")
    assert d["row_filter"]["value"] == "fin" and "ignored" in d["notes"][0]


@pytest.mark.parametrize("user", [
    {"role": "analyst", "clr": "restr"},              # no dept -> no row filter possible
    {"dept": "fin", "clr": "restr"},                   # no role -> not subscribed
])
def test_missing_attributes_fail_closed(user):
    assert not data_policy.evaluate(user)["allowed"]


def test_missing_clearance_masks_rather_than_reveals():
    d = data_policy.evaluate({"dept": "fin", "role": "analyst"})
    assert d["allowed"] and d["masked_columns"] == ["bank_last4", "salary_usd"]


def test_unknown_policy_type_fails_closed():
    p = copy.deepcopy(data_policy.load_policy())
    p["data_policies"].append({"type": "something_new"})
    assert not data_policy.evaluate(ALICE, policy=p)["allowed"]


# -------------------------------------------------------------------- tool
def ctx_for(tool):
    return SimpleNamespace(client_context=SimpleNamespace(custom={"bedrockAgentCoreToolName": f"docs___{tool}"}))


@pytest.fixture
def tool(monkeypatch):
    for k, v in dict(AWS_DEFAULT_REGION="us-east-1", AWS_ACCESS_KEY_ID="testing",
                     AWS_SECRET_ACCESS_KEY="testing", DATA_BUCKET="lab-bucket",
                     EMPLOYEES_TABLE="emp").items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        ddb = boto3.client("dynamodb")
        ddb.create_table(TableName="emp", BillingMode="PAY_PER_REQUEST",
                         AttributeDefinitions=[{"AttributeName": "dept_code", "AttributeType": "S"},
                                               {"AttributeName": "employee_id", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "dept_code", "KeyType": "HASH"},
                                    {"AttributeName": "employee_id", "KeyType": "RANGE"}])
        for r in json.load(open(os.path.join(ROOT, "data", "structured", "employees.json"))):
            ddb.put_item(TableName="emp", Item={k: ({"N": str(v)} if isinstance(v, int) else {"S": v})
                                               for k, v in r.items()})
        sys.path.insert(0, TOOL_DIR)
        import handler
        mod = importlib.reload(handler)
        sys.path.pop(0)
        yield mod


def with_creds(attrs):
    creds = boto3.client("sts").assume_role(RoleArn="arn:aws:iam::123456789012:role/x",
                                            RoleSessionName="test")["Credentials"]
    return {**attrs, "user": "oid", "upn": "u@x",
            "credentials": {k: creds[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")}}


def test_alice_query_returns_fin_rows_with_masks(tool):
    out = tool.lambda_handler({"_ctx": with_creds(ALICE)}, ctx_for("query_employees"))
    assert out["status"] == "ALLOWED" and out["row_count"] == 4
    assert {r["dept_code"] for r in out["rows"]} == {"fin"}
    assert all(r["salary_usd"] == "REDACTED" and r["bank_last4"] == "REDACTED" for r in out["rows"])
    assert all(r["full_name"].startswith("Sample") for r in out["rows"])


def test_alice_asking_for_hr_still_gets_fin(tool):
    out = tool.lambda_handler({"dept": "hr", "_ctx": with_creds(ALICE)}, ctx_for("query_employees"))
    assert {r["dept_code"] for r in out["rows"]} == {"fin"} and out["policy"]["notes"]


def test_bob_query_returns_hr_rows_unmasked(tool):
    out = tool.lambda_handler({"_ctx": with_creds(BOB)}, ctx_for("query_employees"))
    assert out["row_count"] == 3 and {r["dept_code"] for r in out["rows"]} == {"hr"}
    assert all(isinstance(r["salary_usd"], int) for r in out["rows"])


def test_masked_columns_are_never_requested(tool, monkeypatch):
    seen = {}
    real = boto3.session.Session

    class Spy:
        def __init__(self, **kw):
            self._s = real(**kw)

        def client(self, name, **kw):
            c = self._s.client(name, **kw)
            if name == "dynamodb":
                orig = c.query

                def q(**params):
                    seen.update(params)
                    return orig(**params)
                c.query = q
            return c

    monkeypatch.setattr(tool.boto3.session, "Session", Spy)
    tool.lambda_handler({"_ctx": with_creds(ALICE)}, ctx_for("query_employees"))
    assert "salary_usd" not in seen["ProjectionExpression"] and seen["Select"] == "SPECIFIC_ATTRIBUTES"


def test_carol_denied_before_any_data_access(tool, monkeypatch):
    monkeypatch.setattr(tool, "EMPLOYEES_TABLE", "does-not-exist")  # would error if queried
    out = tool.lambda_handler({"_ctx": with_creds(CAROL)}, ctx_for("query_employees"))
    assert out["status"] == "DENIED" and out["layer"] == "data-policy"


def test_iam_refusal_is_reported_as_fgac_layer(tool, monkeypatch):
    monkeypatch.setattr(tool, "EMPLOYEES_TABLE", "does-not-exist")
    out = tool.lambda_handler({"_ctx": with_creds(ALICE)}, ctx_for("query_employees"))
    assert out["status"] == "DENIED" and out["layer"] == "dynamodb-fgac"
