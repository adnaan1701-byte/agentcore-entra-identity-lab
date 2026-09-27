"""
Run the persona x tool test matrix against the live gateway and record evidence.

  python client/run_scenarios.py

Needs cached tokens for alice, bob and carol (run client/get_token.py all first).
Writes evidence/results.md (a table for your write-up) and evidence/results.json
(raw responses).
"""

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from common import ROOT, Gateway, decode_claims, get_token, load, tool_payload  # noqa: E402

EVIDENCE = os.path.join(ROOT, "evidence")


def scenarios(policy_mode):
    cedar_deny = "DENY:cedar-policy" if policy_mode == "ENFORCE" else "ALLOW"
    note = "" if policy_mode == "ENFORCE" else f" (policy engine mode={policy_mode})"
    S = []
    add = lambda *a: S.append(dict(zip(("id", "persona", "kind", "args", "expect", "why"), a)))  # noqa: E731
    add("S01", "alice", "list", None, {"list_documents", "read_document", "query_employees"},
        "analyst does not see the manager-only tool")
    add("S02", "bob", "list", None, {"list_documents", "read_document", "export_all_records", "query_employees"},
        "manager sees all tools")
    add("S03", "carol", "list", None, {"list_documents", "read_document"},
        "contractor sees neither the manager-only tool nor the employee directory")
    add("S04", "alice", ("list_documents", {}), None, "ALLOW", "ListBucket limited to her dept prefix fin/")
    add("S05", "alice", ("read_document", {"key": "fin/q3-revenue.csv"}), None, "ALLOW", "own dept, internal, clearance internal")
    add("S06", "alice", ("read_document", {"key": "fin/payroll-bank-details.csv"}), None, "DENY:s3-abac", "restricted doc, clearance only internal")
    add("S07", "alice", ("read_document", {"key": "hr/salaries.csv"}), None, "DENY:s3-abac", "other department")
    add("S08", "alice", ("read_document", {"key": "hr/salaries.csv",
                                           "_ctx": {"dept": "hr", "role": "manager", "clr": "restr"}}),
        None, "DENY:s3-abac", "forged _ctx in the request is stripped by the interceptor")
    add("S09", "alice", ("export_all_records", {}), None, cedar_deny, "Cedar forbids bulk export for non-managers" + note)
    add("S10", "bob", ("read_document", {"key": "hr/salaries.csv"}), None, "ALLOW", "own dept, restricted, clearance restr")
    add("S11", "bob", ("read_document", {"key": "fin/q3-revenue.csv"}), None, "DENY:s3-abac", "other department")
    add("S12", "bob", ("export_all_records", {}), None, "ALLOW", "manager may export")
    add("S13", "carol", ("read_document", {"key": "fin/team-handbook.md"}), None, "ALLOW", "public doc in own dept")
    add("S14", "carol", ("read_document", {"key": "fin/q3-revenue.csv"}), None, "DENY:s3-abac", "internal doc, clearance only public")
    add("S15", "carol", ("export_all_records", {}), None, cedar_deny, "Cedar forbids bulk export for contractors" + note)
    add("S16", None, ("list_documents", {}), "none", "DENY:gateway-auth", "no bearer token")
    add("S17", "alice", ("list_documents", {}), "tampered", "DENY:gateway-auth", "signature tampered")
    add("S18", "alice", ("list_documents", {}), "graph", "DENY:gateway-auth", "valid Entra token for the wrong audience (Microsoft Graph)")
    # Immuta-style row/column policies on structured data (module I)
    add("S19", "alice", ("query_employees", {}), None, "ALLOW",
        "row filter: fin rows only; salary and bank columns masked (clearance internal)")
    add("S20", "alice", ("query_employees", {"dept": "hr"}), None, "ALLOW",
        "asking for HR rows changes nothing: the row filter still returns fin only")
    add("S21", "bob", ("query_employees", {}), None, "ALLOW",
        "hr rows, nothing masked (clearance restr)")
    add("S22", "carol", ("query_employees", {}), None, "DENY:data-policy",
        "subscription policy: contractors may not use the employee directory (hidden is not the same as blocked)")
    return S


# Extra checks on the rows that came back (module I). Each returns (ok, summary).
def _rows_check(dept, masked):
    def check(payload):
        rows = payload.get("rows") or []
        depts = {r.get("dept_code") for r in rows}
        got_masked = set((payload.get("policy") or {}).get("masked_columns") or [])
        redacted_ok = all(r.get(c) == "REDACTED" for r in rows for c in masked)
        ok = bool(rows) and depts == {dept} and got_masked == set(masked) and redacted_ok
        return ok, f"rows={len(rows)} dept={','.join(sorted(depts)) or '-'} masked={','.join(sorted(got_masked)) or 'none'}"
    return check


CHECKS = {
    "S19": _rows_check("fin", ["bank_last4", "salary_usd"]),
    "S20": _rows_check("fin", ["bank_last4", "salary_usd"]),
    "S21": _rows_check("hr", []),
}


def classify(status, resp):
    """Return (decision, layer, message).

    Fingerprints observed on a live AgentCore Gateway:
      gateway inbound auth -> HTTP 401 "Missing Bearer token" / HTTP 403 "insufficient_scope ..."
      interceptor          -> JSON-RPC error prefixed "[interceptor]"
      Cedar policy         -> HTTP 200, "Tool call not allowed due to policy enforcement [...<policy>...]"
      S3 ABAC              -> tool result {"status": "DENIED", "layer": "s3-abac"}
    """
    if isinstance(resp, dict) and "error" in resp:
        msg = str(resp["error"].get("message", resp["error"]))
        low = msg.lower()
        if "[interceptor]" in msg:
            return "DENY", "interceptor", msg
        if "policy enforcement" in low or "policy evaluation" in low:
            return "DENY", "cedar-policy", msg
        if status in (401, 403) or "insufficient_scope" in low or "bearer" in low or "invalid_token" in low:
            return "DENY", "gateway-auth", msg
        return "DENY", "gateway-other", msg
    if not isinstance(resp, dict):
        return "DENY", "gateway-other", str(resp)[:200]
    if status >= 400:
        return "DENY", "gateway-auth", str(resp)[:200]
    payload = tool_payload(resp) or {}
    if payload.get("status") == "DENIED":
        return "DENY", payload.get("layer", "tool"), payload.get("detail", "")
    if (resp.get("result") or {}).get("isError"):
        return "DENY", "tool-error", json.dumps(payload)[:200]
    return "ALLOW", "-", ""


def main():
    aws = load("aws")
    policy_mode = aws.get("policy_mode", "NONE")
    gw = Gateway()
    tokens = {}
    for p in ("alice", "bob", "carol"):
        tokens[p] = get_token(p)

    rows, raw = [], []
    for s in scenarios(policy_mode):
        persona, token = s["persona"], None
        if s["args"] == "none":
            token = None
        elif s["args"] == "tampered":
            t = tokens[persona]
            token = t[:-6] + ("AAAAAA" if not t.endswith("AAAAAA") else "BBBBBB")
        elif s["args"] == "graph":
            token = get_token(persona, scopes=["User.Read"])
            assert decode_claims(token).get("aud") != load("entra")["api_app_id"]
        else:
            token = tokens[persona]

        if s["kind"] == "list":
            status, resp = gw.list_tools(token)
            names = {t["name"].split("___")[-1] for t in (resp.get("result") or {}).get("tools", [])} \
                if isinstance(resp, dict) else set()
            passed = names == s["expect"]
            got = ", ".join(sorted(names)) or "(none)"
            expect = ", ".join(sorted(s["expect"]))
        else:
            tool, args = s["kind"]
            status, resp = gw.call_tool(tool, dict(args), token)
            decision, layer, msg = classify(status, resp)
            got = decision if decision == "ALLOW" else f"DENY:{layer}"
            expect = s["expect"]
            passed = got == expect
            payload = tool_payload(resp) if isinstance(resp, dict) else None
            if passed and s["id"] in CHECKS:
                ok, summary = CHECKS[s["id"]](payload or {})
                passed = ok
                got += f" [{summary}]"
            if payload and payload.get("on_behalf_of"):
                got += f" (as {payload['on_behalf_of'].get('dept')}/{payload['on_behalf_of'].get('clr')})"

        mark = "PASS" if passed else "FAIL"
        print(f"{mark}  {s['id']} {persona or '-':6} {s['kind'] if s['kind'] == 'list' else s['kind'][0]:20} "
              f"expect={expect}  got={got}")
        rows.append((s["id"], persona or "-", "tools/list" if s["kind"] == "list" else s["kind"][0],
                     json.dumps(s["kind"][1]) if s["kind"] != "list" and s["kind"][1] else "",
                     expect, got, mark, s["why"]))
        raw.append({"scenario": s["id"], "http_status": status, "response": resp})

    os.makedirs(EVIDENCE, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    passed = sum(1 for r in rows if r[6] == "PASS")
    with open(os.path.join(EVIDENCE, "results.md"), "w") as f:
        f.write(f"# Test matrix results\n\nRun: {stamp} | Gateway: {aws['gateway_url']} | "
                f"Cedar policy mode: {policy_mode}\n\n**{passed}/{len(rows)} scenarios passed.**\n\n")
        f.write("| ID | Persona | Tool | Arguments | Expected | Actual | Result | Why |\n|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            f.write("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |\n")
    with open(os.path.join(EVIDENCE, "results.json"), "w") as f:
        json.dump(raw, f, indent=2, default=str)
    print(f"\n{passed}/{len(rows)} passed. Wrote evidence/results.md and evidence/results.json")


if __name__ == "__main__":
    main()
