"""
Immuta-style policy decision point for structured data.

Policies live in data_policies.json and are written once for the data source.
The same attributes that travel from Entra ID into the STS session tags
(dept, role, clr) decide, per user:

  subscription policy -> may this user use the data source at all?
  row filter          -> which rows (here: only the user's own department)
  column masking      -> which columns come back redacted

Design rules:
  * Fail closed: a missing attribute never unlocks anything.
  * Masked columns are never fetched. The query asks only for visible
    columns, and IAM (dynamodb:Attributes) refuses sensitive columns for
    sessions without restricted clearance, so masking is enforced twice.
"""

import json
import os

MASK = "REDACTED"
_POLICY = None


def load_policy(path=None):
    global _POLICY
    if path:
        with open(path) as f:
            return json.load(f)
    if _POLICY is None:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_policies.json")) as f:
            _POLICY = json.load(f)
    return _POLICY


def _matches(rule, user):
    value = user.get(rule["attribute"])
    return value is not None and value in rule["in"]


def evaluate(user, requested_dept=None, policy=None):
    """Return the decision for this user as a dict.

    {"allowed": bool, "reason": str, "row_filter": {"column", "value"} | None,
     "visible_columns": [...], "masked_columns": [...], "notes": [...]}
    """
    policy = policy or load_policy()
    decision = {"data_source": policy["data_source"], "allowed": False, "reason": "",
                "row_filter": None, "visible_columns": [], "masked_columns": [], "notes": []}

    sub = policy["subscription_policy"]
    if not _matches(sub["allow_when"], user):
        decision["reason"] = (f"subscription policy: role '{user.get('role')}' may not use data source "
                              f"'{policy['data_source']}' ({sub['description']})")
        return decision

    masked, row_filter = set(), None
    for p in policy["data_policies"]:
        if p["type"] == "row_filter":
            value = user.get(p["equals_user_attribute"])
            if not value:
                decision["reason"] = f"row filter needs attribute '{p['equals_user_attribute']}', which is missing"
                return decision
            row_filter = {"column": p["column"], "value": value}
        elif p["type"] == "mask":
            if not _matches(p["unless"], user):
                masked.update(p["columns"])
        else:
            decision["reason"] = f"unknown policy type '{p['type']}'"  # fail closed on anything unexpected
            return decision

    if row_filter is None:
        decision["reason"] = "no row filter defined; refusing to return every row"
        return decision

    if requested_dept and requested_dept != row_filter["value"]:
        decision["notes"].append(f"requested dept '{requested_dept}' ignored: row filter "
                                 f"{row_filter['column']} = {row_filter['value']} applies")

    decision.update(allowed=True, reason="subscribed", row_filter=row_filter,
                    visible_columns=[c for c in policy["columns"] if c not in masked],
                    masked_columns=sorted(masked))
    return decision


def apply_masks(rows, decision, columns):
    """Put the masked columns back into each row as REDACTED, keeping column order."""
    out = []
    for r in rows:
        out.append({c: (MASK if c in decision["masked_columns"] else r.get(c)) for c in columns})
    return out
