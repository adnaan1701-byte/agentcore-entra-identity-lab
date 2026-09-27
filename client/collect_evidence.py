"""
Pull the audit trail that proves identity propagation:

  * CloudTrail AssumeRole events for the user-scoped role: SourceIdentity
    (the Entra object ID) and the session tags on every tagged session.
  * The interceptor's structured allow/deny audit log from CloudWatch.

  python client/collect_evidence.py [--hours 3]

CloudTrail event history can lag 5-15 minutes behind your test run.
Writes evidence/audit_trail.md.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import boto3

sys.path.insert(0, os.path.dirname(__file__))
from common import ROOT, load  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=3)
    a = ap.parse_args()
    aws, entra = load("aws"), load("entra")
    who = {u["oid"]: name for name, u in entra["users"].items()}
    session = boto3.Session(region_name=aws["region"])
    start = datetime.now(timezone.utc) - timedelta(hours=a.hours)

    ct = session.client("cloudtrail")
    rows = []
    for page in ct.get_paginator("lookup_events").paginate(
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}],
            StartTime=start):
        for e in page["Events"]:
            d = json.loads(e["CloudTrailEvent"])
            rp = d.get("requestParameters") or {}
            if not str(rp.get("roleArn", "")).endswith(f"role/{aws['prefix']}-user-scoped-role"):
                continue
            tags = {t["key"]: t["value"] for t in rp.get("tags", [])}
            sid = rp.get("sourceIdentity", "")
            rows.append((d["eventTime"], who.get(sid, "?"), sid, rp.get("roleSessionName", ""),
                         ", ".join(f"{k}={v}" for k, v in sorted(tags.items()) if k != "tenant"),
                         d.get("errorCode", "success")))
    rows.sort()

    logs = session.client("logs")
    audit = []
    try:
        kwargs = dict(logGroupName=f"/aws/lambda/{aws['prefix']}-interceptor",
                      startTime=int(start.timestamp() * 1000), filterPattern='"audit"')
        while True:
            r = logs.filter_log_events(**kwargs)
            for ev in r["events"]:
                msg = ev["message"]
                try:
                    audit.append(json.loads(msg[msg.index("{"):]))
                except ValueError:
                    pass
            if not r.get("nextToken"):
                break
            kwargs["nextToken"] = r["nextToken"]
            time.sleep(0.2)
    except logs.exceptions.ResourceNotFoundException:
        pass

    out = os.path.join(ROOT, "evidence", "audit_trail.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write("# Audit trail\n\n## CloudTrail: tagged sessions minted for humans\n\n")
        f.write("| Time (UTC) | Persona | SourceIdentity (Entra oid) | Session name | Session tags | Result |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in rows:
            f.write("| " + " | ".join(r) + " |\n")
        if not rows:
            f.write("\n_No events yet. CloudTrail event history can take 5-15 minutes; rerun shortly._\n")
        f.write("\n## Interceptor decisions (CloudWatch Logs)\n\n| Decision | Tool | Persona | dept | role | clr | Detail |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for e in audit:
            detail = e.get("reason") or ("forged _ctx stripped" if e.get("forged_ctx_stripped") else "")
            if e.get("audit") == "tools_list_filtered":
                detail = f"tools shown: {', '.join(s.split('___')[-1] for s in e.get('shown', []))}"
            f.write(f"| {e.get('audit')} | {e.get('tool', '')} | {who.get(e.get('user', ''), '')} | {e.get('dept', '')} | "
                    f"{e.get('role', '')} | {e.get('clr', '')} | {detail} |\n")
    print(f"{len(rows)} CloudTrail AssumeRole events, {len(audit)} interceptor audit records -> {out}")


if __name__ == "__main__":
    main()
