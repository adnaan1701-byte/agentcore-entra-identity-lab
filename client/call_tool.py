"""
Call one tool through the gateway as one persona and show what came back.

  python client/call_tool.py carol read_document key=fin/vendor-payments-export.csv
  python client/call_tool.py alice query_employees
  python client/call_tool.py alice query_employees dept=hr
  python client/call_tool.py bob list_documents

Arguments are key=value pairs. Uses the cached token (sign in first with get_token.py).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from common import Gateway, get_token, tool_payload  # noqa: E402
from run_scenarios import classify  # noqa: E402


def table(rows):
    if not rows:
        return "  (no rows)"
    cols = list(rows[0])
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    line = lambda r: "  " + "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols)  # noqa: E731
    return "\n".join([line({c: c for c in cols}), "  " + "  ".join("-" * widths[c] for c in cols)]
                     + [line(r) for r in rows])


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    persona, tool = sys.argv[1], sys.argv[2]
    args = {}
    for a in sys.argv[3:]:
        k, _, v = a.partition("=")
        args[k] = v
    status, resp = Gateway().call_tool(tool, args, get_token(persona))
    decision, layer, msg = classify(status, resp)
    payload = tool_payload(resp) if isinstance(resp, dict) else None

    print(f"\n{persona} -> {tool} {json.dumps(args) if args else ''}")
    print(f"DECISION: {decision}" + (f"  (layer: {layer})" if decision == "DENY" else ""))
    if msg:
        print(f"detail:   {msg[:300]}")
    if not payload:
        return
    who = payload.get("on_behalf_of")
    if who:
        print(f"on behalf of: {who.get('upn')}  dept={who.get('dept')} role={who.get('role')} clr={who.get('clr')}")
    if "rows" in payload:
        pol = payload.get("policy") or {}
        rf = pol.get("row_filter") or {}
        print(f"policy:   row filter {rf.get('column')} = {rf.get('value')};  "
              f"masked: {', '.join(pol.get('masked_columns') or []) or 'none'}")
        for n in pol.get("notes") or []:
            print(f"note:     {n}")
        print(table(payload["rows"]))
    elif "content" in payload:
        print("content:\n  " + payload["content"][:600].replace("\n", "\n  "))
    elif "keys" in payload:
        print("keys:\n  " + "\n  ".join(payload["keys"]))
    elif "exported" in payload:
        print(f"exported: {payload['exported']}\nblocked:  {payload['blocked']}")


if __name__ == "__main__":
    main()
