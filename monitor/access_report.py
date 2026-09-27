"""
Module V (Varonis-style), step 2: who touched what data, and is it normal?

Reads the CloudTrail data events recorded by monitor/enable_data_events.py and
turns them into a per-human report. It works because every agent session
carries SourceIdentity = the Entra object ID: without it, every read would
belong to one IAM role and there would be nobody to alert on.

  python monitor/access_report.py            # last 6 hours
  python monitor/access_report.py --hours 2

Alert rules (simple versions of the behaviour models a tool like Varonis runs):
  BULK_READ   one person reads 3+ objects within 2 minutes
  PROBING     one person is denied 3+ times within 10 minutes
  EXPOSURE    one person read an object whose label is NOW above their
              clearance (for example after DSPM relabelled it)

Writes evidence/access_report.md.
"""

import argparse
import gzip
import io
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, ".lab")
OUT = os.path.join(ROOT, "evidence", "access_report.md")

LEVELS = ["public", "internal", "restr"]
READ_ACTIONS = {"GetObject", "Query"}
BULK_COUNT, BULK_WINDOW = 3, timedelta(minutes=2)
PROBE_COUNT, PROBE_WINDOW = 3, timedelta(minutes=10)


# ------------------------------------------------------------------ parsing
def parse_record(r, people):
    """Turn one CloudTrail record into a flat event, or None if it is not a data event we care about."""
    if r.get("eventCategory") not in (None, "Data"):
        return None
    ui = r.get("userIdentity") or {}
    ctx = ui.get("sessionContext") or {}
    arn = ui.get("arn", "")
    oid = ctx.get("sourceIdentity") or ""
    person = people.get(oid)
    if not person and "/agentlab-user-scoped-role/agentlab-" in arn:  # fall back to the session name
        prefix = arn.rsplit("/", 1)[-1].split("-")[1]
        person = next((p for o, p in people.items() if o.startswith(prefix)), None)
        oid = oid or (person or {}).get("oid", "")
    if person:
        who, kind = person["name"], "human via agent"
    elif ui.get("type") == "AWSService" or "AmazonMacie" in arn or ui.get("invokedBy") == "macie.amazonaws.com":
        who, kind = "Amazon Macie (DSPM scanner)", "service"
    elif ui.get("type") == "IAMUser":
        who, kind = f"IAM user {ui.get('userName', arn.rsplit('/', 1)[-1])}", "admin"
    else:
        who, kind = arn.rsplit("/", 1)[-1] or ui.get("type", "unknown"), "other"
    rp = r.get("requestParameters") or {}
    # S3 puts the object name in "key" (a string); DynamoDB item calls put the item's
    # primary key there as a dict, so for those use the table name instead.
    key = rp.get("key") if isinstance(rp.get("key"), str) else ""
    target = key or rp.get("tableName") or (str(rp.get("prefix", "")) + "*" if "prefix" in rp else "")
    if not target:
        target = next((x.get("ARN", "").split(":::")[-1] for x in r.get("resources") or [] if x.get("ARN")), "")
    if not isinstance(target, str):
        target = str(target)
    return {"time": datetime.strptime(r["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
            "who": who, "kind": kind, "oid": oid, "action": r.get("eventName", ""),
            "target": target, "denied": bool(r.get("errorCode")), "error": r.get("errorCode", "")}


def load_events(session, account, region, log_bucket, since, people):
    s3 = session.client("s3")
    events, day = [], since.date()
    while day <= datetime.now(timezone.utc).date():
        prefix = f"AWSLogs/{account}/CloudTrail/{region}/{day:%Y/%m/%d}/"
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=log_bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                if obj["LastModified"] < since:
                    continue
                raw = s3.get_object(Bucket=log_bucket, Key=obj["Key"])["Body"].read()
                for r in json.load(gzip.GzipFile(fileobj=io.BytesIO(raw))).get("Records", []):
                    e = parse_record(r, people)
                    if e and e["time"] >= since:
                        events.append(e)
        day += timedelta(days=1)
    return sorted(events, key=lambda e: e["time"])


# ----------------------------------------------------------------- analysis
def _burst(times, count, window):
    """Largest number of events inside any sliding window, and when it started."""
    best, start, j = 0, None, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        if i - j + 1 > best:
            best, start = i - j + 1, times[j]
    return (best, start) if best >= count else (0, None)


def analyze(events, sensitivity, clearance):
    """events: parsed events; sensitivity: {object key: label}; clearance: {person name: label}."""
    humans = defaultdict(list)
    for e in events:
        if e["kind"] == "human via agent":
            humans[e["who"]].append(e)
    alerts = []
    for who, evs in humans.items():
        reads = [e["time"] for e in evs if e["action"] == "GetObject" and not e["denied"]]
        n, t0 = _burst(reads, BULK_COUNT, BULK_WINDOW)
        if n:
            alerts.append(("MEDIUM", "BULK_READ", who, f"{n} object reads within {BULK_WINDOW.seconds // 60} min "
                           "(agent over-collection or bulk export?)", t0))
        denials = [e["time"] for e in evs if e["denied"]]
        n, t0 = _burst(denials, PROBE_COUNT, PROBE_WINDOW)
        if n:
            alerts.append(("MEDIUM", "PROBING", who, f"{n} access denials within {PROBE_WINDOW.seconds // 60} min "
                           "(someone, or a prompt-injected agent, testing boundaries?)", t0))
        clr = clearance.get(who)
        seen = set()
        for e in evs:
            label = sensitivity.get(e["target"])
            if (e["action"] == "GetObject" and not e["denied"] and label in LEVELS and clr in LEVELS
                    and LEVELS.index(label) > LEVELS.index(clr) and e["target"] not in seen):
                seen.add(e["target"])
                alerts.append(("HIGH", "EXPOSURE", who, f"read {e['target']} which is now labelled '{label}' "
                               f"but their clearance is '{clr}': review what was exposed", e["time"]))
    return humans, sorted(alerts, key=lambda a: (a[0] != "HIGH", a[4]))


# ------------------------------------------------------------------- output
def write_report(events, humans, alerts, sensitivity, clearance, people_by_name, hours):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    agent_events = [e for e in events if e["kind"] == "human via agent"]
    fmt = lambda t: t.strftime("%H:%M:%S") if t else ""  # noqa: E731
    with open(OUT, "w") as f:
        f.write("# Data access report (Varonis-style, built from CloudTrail data events)\n\n")
        f.write(f"Window: last {hours:g} h | generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} | "
                f"{len(events)} data events, {len(agent_events)} made by agent sessions\n\n")
        f.write(f"All {len(agent_events)} agent events used **one** IAM role (agentlab-user-scoped-role). "
                f"SourceIdentity resolves them to **{len(humans)} named people**. Without identity "
                "propagation, this report could only say \"the agent did it\".\n\n")
        f.write("## Alerts\n\n| Severity | Rule | Person | Detail | First seen (UTC) |\n|---|---|---|---|---|\n")
        for sev, rule, who, detail, t in alerts:
            f.write(f"| {sev} | {rule} | {who} | {detail} | {fmt(t)} |\n")
        if not alerts:
            f.write("| - | - | - | no alerts in this window | - |\n")

        f.write("\n## Per-person activity through the agent\n\n"
                "| Person | Entra UPN | Clearance now | Reads allowed | Denied | Distinct objects | "
                "Most sensitive data read | Last activity (UTC) |\n|---|---|---|---|---|---|---|---|\n")
        for who, evs in sorted(humans.items()):
            ok = [e for e in evs if not e["denied"] and e["action"] in READ_ACTIONS]
            labels = [sensitivity.get(e["target"]) for e in ok if sensitivity.get(e["target"]) in LEVELS]
            top = max(labels, key=LEVELS.index) if labels else "-"
            f.write(f"| {who} | {people_by_name.get(who, {}).get('upn', '')} | {clearance.get(who, '?')} | "
                    f"{len(ok)} | {sum(e['denied'] for e in evs)} | {len({e['target'] for e in evs})} | {top} | "
                    f"{fmt(evs[-1]['time'])} |\n")

        f.write("\n## Who touched each object\n\n| Object | Label now | Read by | Denied to |\n|---|---|---|---|\n")
        by_obj = defaultdict(lambda: (Counter(), Counter()))
        for e in agent_events:
            by_obj[e["target"]][1 if e["denied"] else 0][e["who"]] += 1
        for obj, (ok, no) in sorted(by_obj.items()):
            j = lambda c: ", ".join(f"{k} ({v})" for k, v in sorted(c.items())) or "-"  # noqa: E731
            f.write(f"| {obj} | {sensitivity.get(obj, '-')} | {j(ok)} | {j(no)} |\n")

        others = Counter((e["who"], e["action"]) for e in events if e["kind"] != "human via agent")
        f.write("\n## Other principals (not through the agent)\n\n| Principal | Action | Events |\n|---|---|---|\n")
        for (who, action), n in sorted(others.items()):
            f.write(f"| {who} | {action} | {n} |\n")
        if not others:
            f.write("| - | - | 0 |\n")


def main():
    import boto3
    from botocore.exceptions import ClientError

    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=6)
    a = ap.parse_args()
    try:
        aws, entra, mon = (json.load(open(os.path.join(LAB, f"{n}.json"))) for n in ("aws", "entra", "monitor"))
    except FileNotFoundError as e:
        sys.exit(f"Missing {e.filename}. Run monitor/enable_data_events.py first.")
    people = {u["oid"]: {"name": name, "upn": u.get("upn", ""), "oid": u["oid"]} for name, u in entra["users"].items()}
    people_by_name = {p["name"]: p for p in people.values()}
    session = boto3.Session(region_name=aws["region"])
    since = datetime.now(timezone.utc) - timedelta(hours=a.hours)

    events = load_events(session, aws["account"], aws["region"], mon["log_bucket"], since, people)
    if not events:
        print("No data events delivered yet. CloudTrail delivers every ~5 minutes; wait and rerun.")
        return

    s3, ddb = session.client("s3"), session.client("dynamodb")
    sensitivity = {}
    for key in {e["target"] for e in events if e["action"] == "GetObject"}:
        try:
            tags = s3.get_object_tagging(Bucket=aws["bucket"], Key=key)["TagSet"]
            sensitivity[key] = next((t["Value"] for t in tags if t["Key"] == "sensitivity"), "-")
        except ClientError:
            sensitivity[key] = "(deleted)"
    clearance = {}
    for p in people.values():  # live HR attribute, same source the interceptor uses
        item = ddb.get_item(TableName=aws["hr_table"], Key={"oid": {"S": p["oid"]}}).get("Item") or {}
        clearance[p["name"]] = item.get("clearance", {}).get("S", "?")

    humans, alerts = analyze(events, sensitivity, clearance)
    write_report(events, humans, alerts, sensitivity, clearance, people_by_name, a.hours)
    print(f"{len(events)} data events; {len(humans)} people acted through the agent; {len(alerts)} alerts")
    for sev, rule, who, detail, _ in alerts:
        print(f"  [{sev}] {rule:10} {who:6} {detail}")
    print(f"Wrote {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
