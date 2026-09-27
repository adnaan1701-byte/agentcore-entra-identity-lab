"""Varonis-style access report (monitor/access_report.py): parsing and alert rules. No AWS calls."""

import os
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "monitor"))
import access_report as ar  # noqa: E402

sys.path.pop(0)

ALICE, BOB, CAROL = "a1b2c3d4-0000-0000-0000-000000000001", "b1b2c3d4-0000-0000-0000-000000000002", \
    "c1b2c3d4-0000-0000-0000-000000000003"
PEOPLE = {o: {"name": n, "upn": f"{n}@x", "oid": o} for o, n in ((ALICE, "alice"), (BOB, "bob"), (CAROL, "carol"))}
T0 = datetime(2026, 9, 27, 3, 0, 0, tzinfo=timezone.utc)


def rec(oid, key, seconds, error=None, action="GetObject", source_identity=True):
    ctx = {"sourceIdentity": oid} if source_identity else {}
    r = {"eventCategory": "Data", "eventName": action,
         "eventTime": (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "userIdentity": {"type": "AssumedRole", "sessionContext": ctx,
                          "arn": f"arn:aws:sts::1:assumed-role/agentlab-user-scoped-role/agentlab-{oid[:8]}-123"},
         "requestParameters": {"bucketName": "b", "key": key}}
    if error:
        r["errorCode"] = error
    return ar.parse_record(r, PEOPLE)


def test_source_identity_names_the_human():
    e = rec(ALICE, "fin/q3-revenue.csv", 0)
    assert e["who"] == "alice" and e["kind"] == "human via agent" and not e["denied"]


def test_session_name_is_a_fallback_when_source_identity_missing():
    assert rec(BOB, "hr/salaries.csv", 0, source_identity=False)["who"] == "bob"


def test_macie_and_admin_are_not_humans_via_agent():
    macie = ar.parse_record({"eventName": "GetObject", "eventTime": "2026-09-27T03:00:00Z",
                             "userIdentity": {"type": "AssumedRole", "arn":
                                              "arn:aws:sts::1:assumed-role/AWSServiceRoleForAmazonMacie/x"},
                             "requestParameters": {"key": "fin/a"}}, PEOPLE)
    admin = ar.parse_record({"eventName": "PutObject", "eventTime": "2026-09-27T03:00:00Z",
                             "userIdentity": {"type": "IAMUser", "userName": "agentlab-admin", "arn": "x"},
                             "requestParameters": {"key": "fin/a"}}, PEOPLE)
    assert macie["kind"] == "service" and admin["kind"] == "admin"


def test_rules_fire_for_the_expected_people():
    events = [
        rec(BOB, "hr/salaries.csv", 0), rec(BOB, "hr/salaries.csv", 20), rec(BOB, "hr/holiday-calendar.csv", 21),
        rec(ALICE, "fin/q3-revenue.csv", 0),
        rec(ALICE, "fin/payroll-bank-details.csv", 5, "AccessDenied"),
        rec(ALICE, "hr/salaries.csv", 6, "AccessDenied"), rec(ALICE, "hr/salaries.csv", 7, "AccessDenied"),
        rec(CAROL, "fin/vendor-payments-export.csv", 30), rec(CAROL, "fin/team-handbook.md", 31),
    ]
    sensitivity = {"hr/salaries.csv": "restr", "hr/holiday-calendar.csv": "internal", "fin/q3-revenue.csv": "internal",
                   "fin/vendor-payments-export.csv": "restr", "fin/team-handbook.md": "public"}
    clearance = {"alice": "internal", "bob": "restr", "carol": "public"}
    humans, alerts = ar.analyze(events, sensitivity, clearance)
    fired = {(rule, who) for _, rule, who, _, _ in alerts}
    assert fired == {("BULK_READ", "bob"), ("PROBING", "alice"), ("EXPOSURE", "carol")}
    assert alerts[0][0] == "HIGH" and alerts[0][1] == "EXPOSURE"
    assert set(humans) == {"alice", "bob", "carol"}


def test_slow_reads_and_scattered_denials_do_not_alert():
    events = [rec(BOB, "hr/salaries.csv", i * 300) for i in range(4)] + \
             [rec(ALICE, "hr/salaries.csv", i * 900, "AccessDenied") for i in range(3)]
    _, alerts = ar.analyze(events, {"hr/salaries.csv": "restr"}, {"alice": "internal", "bob": "restr"})
    assert alerts == []


def test_dynamodb_item_events_use_the_table_name():
    # PutItem/GetItem put the item's key in requestParameters.key as a dict (seen live).
    e = ar.parse_record({"eventName": "PutItem", "eventTime": "2026-09-27T03:00:00Z",
                         "userIdentity": {"type": "IAMUser", "userName": "agentlab-admin", "arn": "x"},
                         "requestParameters": {"tableName": "agentlab-employees",
                                               "key": {"dept_code": "fin", "employee_id": "E1001"}}}, PEOPLE)
    assert e["target"] == "agentlab-employees"
    ar.analyze([e], {}, {})  # must not raise
