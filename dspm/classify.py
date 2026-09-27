"""
Module C (Cyera-style): let data classification drive the ABAC tags.

In production a DSPM tool (Cyera, or Varonis' classification) scans the data
stores and labels what it finds. Here Amazon Macie plays that role, and this
script is the adapter that turns classification results into the S3 object
tag (`sensitivity`) that the user-scoped role's ABAC policy already checks.

  python dspm/classify.py plant    # upload a sensitive file that is WRONGLY tagged public
  python dspm/classify.py scan     # run a Macie job on the lab bucket and propose new labels
  python dspm/classify.py apply    # apply the proposals (labels only ever go UP)

`scan` takes 10-25 minutes (Macie job start-up). If you stop it with Ctrl+C,
run it again: it resumes the same job. `scan --new` starts a fresh job.

All values in the planted file are fake (test card numbers, invented SSNs).
"""

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, ".lab")
STATE = os.path.join(LAB, "dspm.json")
EVIDENCE = os.path.join(ROOT, "evidence", "dspm_findings.md")
PLANTED_KEY = "fin/vendor-payments-export.csv"
CUSTOM_ID_NAME = "agentlab-employee-id"

LEVELS = ["public", "internal", "restr"]
RESTRICTED_CATEGORIES = {"FINANCIAL_INFORMATION", "CREDENTIALS"}
RETRYABLE = {"ValidationException", "ResourceNotFoundException", "ConflictException", "ThrottlingException"}
RESTRICTED_TYPE_HINTS = ("SOCIAL_SECURITY", "PASSPORT", "TAX", "DRIVERS_LICENSE", "HEALTH", "BANK_ACCOUNT",
                         "CREDIT_CARD")


def log(m):
    print(f"[dspm] {m}", flush=True)


def load(name, required=True):
    p = os.path.join(LAB, f"{name}.json")
    if not os.path.exists(p):
        if required:
            sys.exit(f"Missing {p}. Deploy the lab first.")
        return {}
    return json.load(open(p))


def save_state(state):
    with open(STATE, "w") as f:
        json.dump(state, f, indent=2, default=str)


# ------------------------------------------------------------ classification
def proposed_label(summary):
    """Map one object's classification summary to a sensitivity label.

    summary = {"severity": "High"|"Medium"|"Low",
               "detections": [{"category": ..., "type": ..., "count": n}, ...]}
    """
    label = "public"
    for d in summary.get("detections", []):
        cat, typ = d.get("category", ""), d.get("type", "")
        if cat in RESTRICTED_CATEGORIES or any(h in typ for h in RESTRICTED_TYPE_HINTS):
            return "restr"
        label = "internal"  # anything else sensitive (names, addresses, our custom employee IDs)
    if summary.get("severity") == "High":
        return "restr"
    return label


def raise_only(current, proposed):
    """Automation may tighten a label, never loosen it."""
    cur = current if current in LEVELS else "restr"  # unknown current label: treat as most sensitive
    return proposed if LEVELS.index(proposed) > LEVELS.index(cur) else cur


def summarize_finding(f):
    res = (f.get("classificationDetails") or {}).get("result") or {}
    dets = []
    for item in res.get("sensitiveData") or []:
        for d in item.get("detections") or []:
            dets.append({"category": item.get("category", ""), "type": d.get("type", ""), "count": d.get("count", 0)})
    for d in (res.get("customDataIdentifiers") or {}).get("detections") or []:
        dets.append({"category": "CUSTOM_IDENTIFIER", "type": d.get("name", ""), "count": d.get("count", 0)})
    return {"key": f["resourcesAffected"]["s3Object"]["key"],
            "severity": (f.get("severity") or {}).get("description", ""),
            "finding_type": f.get("type", ""), "detections": dets}


# ------------------------------------------------------------------- AWS bits
def object_tags(s3, bucket, key):
    try:
        return {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    except ClientError:
        return None


def ensure_macie(macie, state):
    try:
        status = macie.get_macie_session()["status"]
        if status != "ENABLED":
            sys.exit(f"Macie is {status} in this region. Resume it in the Macie console and rerun.")
        state.setdefault("macie_enabled_by_lab", False)
        log("Macie is already enabled in this account/region")
    except ClientError:
        macie.enable_macie(status="ENABLED", findingPublishingFrequency="FIFTEEN_MINUTES")
        state["macie_enabled_by_lab"] = True
        save_state(state)
        log("enabled Amazon Macie (teardown will disable it again)")
        time.sleep(20)
        try:  # we only want our one-time job, not ongoing account-wide sampling
            macie.update_automated_discovery_configuration(status="DISABLED")
            log("turned off Macie automated discovery (only our one-time job runs)")
        except ClientError as e:
            log(f"  note: could not turn off automated discovery ({e.response['Error']['Code']}); harmless")


def ensure_custom_identifier(macie, state):
    for attempt in range(6):  # right after enabling, Macie can take a moment to accept requests
        try:
            for page in macie.get_paginator("list_custom_data_identifiers").paginate():
                for c in page.get("items", []):
                    if c["name"] == CUSTOM_ID_NAME:
                        state["custom_identifier_id"] = c["id"]
                        return c["id"]
            cid = macie.create_custom_data_identifier(
                clientToken=str(uuid.uuid4()), name=CUSTOM_ID_NAME,
                description="Lab employee IDs (E + 4 digits) near an employee_id keyword, like a custom classifier.",
                regex="E[0-9]{4}", keywords=["employee_id", "employee id"], maximumMatchDistance=50,
                severityLevels=[{"occurrencesThreshold": 1, "severity": "MEDIUM"}])["customDataIdentifierId"]
            break
        except ClientError as e:
            if attempt == 5:
                raise
            log(f"  Macie not ready yet ({e.response['Error']['Code']}); retrying in 20s")
            time.sleep(20)
    state["custom_identifier_id"] = cid
    save_state(state)
    log(f"created custom data identifier {CUSTOM_ID_NAME}")
    return cid


def start_job(macie, account, bucket, cid):
    name = f"agentlab-dspm-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    for attempt in range(20):  # a freshly enabled Macie needs a few minutes to see the bucket
        try:
            return macie.create_classification_job(
                clientToken=str(uuid.uuid4()), name=name, jobType="ONE_TIME",
                s3JobDefinition={"bucketDefinitions": [{"accountId": account, "buckets": [bucket]}]},
                customDataIdentifierIds=[cid], managedDataIdentifierSelector="ALL",
                samplingPercentage=100)["jobId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in RETRYABLE or attempt == 19:
                raise
            log(f"  Macie not ready yet ({code}); retrying in 30s")
            time.sleep(30)
            continue


def wait_for_job(macie, job_id):
    t0 = time.time()
    last = None
    while True:
        j = macie.describe_classification_job(jobId=job_id)
        st = j["jobStatus"]
        if st != last:
            log(f"job {job_id}: {st}")
            last = st
        if st == "COMPLETE":
            err = (j.get("lastRunErrorStatus") or {}).get("code")
            if err == "ERROR":
                log("  the job reported errors for some objects; check the job in the Macie console")
            return
        if st in ("CANCELLED", "USER_PAUSED", "PAUSED"):
            sys.exit(f"Macie job is {st}. Check it in the Macie console (Jobs), then run scan --new.")
        mins = (time.time() - t0) / 60
        if mins > 50:
            sys.exit("Still running after 50 minutes. Run `python dspm/classify.py scan` later to resume.")
        print(f"    ... waiting ({mins:.0f} min so far; Macie jobs usually take 10-25 minutes)", flush=True)
        time.sleep(60)


def fetch_findings(macie, job_id):
    for attempt in range(12):  # findings are published a little after the job completes
        ids = []
        kw = {"findingCriteria": {"criterion": {"classificationDetails.jobId": {"eq": [job_id]}}}}
        for page in macie.get_paginator("list_findings").paginate(**kw):
            ids += page.get("findingIds", [])
        if ids:
            out = []
            for i in range(0, len(ids), 50):
                out += macie.get_findings(findingIds=ids[i:i + 50])["findings"]
            return [summarize_finding(f) for f in out]
        log("  no findings published yet; checking again in 30s")
        time.sleep(30)
    return []


# ------------------------------------------------------------------- commands
def cmd_plant(s3, bucket):
    body = open(os.path.join(ROOT, "data", "planted", "vendor-payments-export.csv"), "rb").read()
    s3.put_object(Bucket=bucket, Key=PLANTED_KEY, Body=body, Tagging="dept=fin&sensitivity=public")
    log(f"uploaded s3://{bucket}/{PLANTED_KEY} with tags dept=fin, sensitivity=public  <- the mistake")
    log("Carol (clearance public) can now read card numbers and SSNs. Prove it:")
    log(f"  python client/call_tool.py carol read_document key={PLANTED_KEY}")


def cmd_scan(session, aws, state, new):
    macie, s3 = session.client("macie2"), session.client("s3")
    ensure_macie(macie, state)
    cid = ensure_custom_identifier(macie, state)
    if new or not state.get("job_id"):
        state["job_id"] = start_job(macie, aws["account"], aws["bucket"], cid)
        state.pop("findings", None)
        save_state(state)
        log(f"started Macie classification job {state['job_id']} on s3://{aws['bucket']}")
    else:
        log(f"resuming job {state['job_id']} (use --new to start a fresh one)")
    wait_for_job(macie, state["job_id"])
    findings = fetch_findings(macie, state["job_id"])
    rows = []
    for f in findings:
        tags = object_tags(s3, aws["bucket"], f["key"]) or {}
        cur = tags.get("sensitivity", "(none)")
        f["current"] = cur
        f["proposed"] = raise_only(cur, proposed_label(f))
        rows.append(f)
    state["findings"] = rows
    save_state(state)
    print_table(rows)
    write_evidence(rows, applied=False, job_id=state["job_id"])
    log("Next: python dspm/classify.py apply")


def cmd_apply(session, aws, state):
    if not state.get("findings"):
        sys.exit("No findings saved yet. Run: python dspm/classify.py scan")
    s3 = session.client("s3")
    for f in state["findings"]:
        tags = object_tags(s3, aws["bucket"], f["key"])
        if tags is None:
            log(f"{f['key']}: object no longer exists, skipped")
            continue
        cur = tags.get("sensitivity", "(none)")
        new = raise_only(cur, proposed_label(f))
        if new == cur:
            log(f"{f['key']}: stays {cur}")
            f["result"] = "unchanged"
            continue
        tags.update(sensitivity=new, classified_by="macie")
        s3.put_object_tagging(Bucket=aws["bucket"], Key=f["key"],
                              Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]})
        log(f"{f['key']}: sensitivity {cur} -> {new}")
        f["result"] = f"{cur} -> {new}"
    save_state(state)
    write_evidence(state["findings"], applied=True, job_id=state["job_id"])
    log("Carol's next call is checked against the new label. Try:")
    log(f"  python client/call_tool.py carol read_document key={PLANTED_KEY}")


def print_table(rows):
    if not rows:
        log("Macie reported no sensitive data. On a freshly enabled Macie the first job can run before the")
        log("bucket is in Macie's inventory and scan nothing. Wait 5 minutes, then: python dspm/classify.py scan --new")
        return
    print(f"\n{'object':38} {'severity':8} {'detected':60} {'label now':10} proposed")
    for r in rows:
        det = ", ".join(f"{d['type']} x{d['count']}" for d in r["detections"])[:60]
        print(f"{r['key']:38} {r['severity']:8} {det:60} {r['current']:10} {r['proposed']}")
    print()


def write_evidence(rows, applied, job_id):
    os.makedirs(os.path.dirname(EVIDENCE), exist_ok=True)
    with open(EVIDENCE, "w") as f:
        f.write("# DSPM classification -> ABAC tags (Amazon Macie as the classifier)\n\n")
        f.write(f"Macie job `{job_id}` | written {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} | "
                f"labels applied: {'yes' if applied else 'not yet'}\n\n")
        f.write("| Object | Severity | Detected | Label before | Label after | Result |\n|---|---|---|---|---|---|\n")
        for r in rows:
            det = ", ".join(f"{d['type']} x{d['count']}" for d in r["detections"])
            f.write(f"| {r['key']} | {r['severity']} | {det} | {r['current']} | {r['proposed']} | "
                    f"{r.get('result', 'proposed')} |\n")
        f.write("\nRule: automation only raises a label, never lowers it. Unknown labels count as restricted.\n")
    log(f"wrote {os.path.relpath(EVIDENCE, ROOT)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["plant", "scan", "apply"])
    ap.add_argument("--new", action="store_true", help="scan: start a new Macie job instead of resuming")
    a = ap.parse_args()
    aws = load("aws")
    state = load("dspm", required=False)
    session = boto3.Session(region_name=aws["region"])
    if a.command == "plant":
        cmd_plant(session.client("s3"), aws["bucket"])
    elif a.command == "scan":
        cmd_scan(session, aws, state, a.new)
    else:
        cmd_apply(session, aws, state)


if __name__ == "__main__":
    main()
