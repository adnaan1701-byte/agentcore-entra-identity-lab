# DSPM classification -> ABAC tags (Amazon Macie as the classifier)

Macie job `be018e3ab2861e43d3511caaf271211a` | written 2026-09-27 04:00 UTC | labels applied: yes

| Object | Severity | Detected | Label before | Label after | Result |
|---|---|---|---|---|---|
| fin/payroll-bank-details.csv | Medium | agentlab-employee-id x2 | restr | restr | unchanged |
| hr/salaries.csv | Medium | agentlab-employee-id x2 | restr | restr | unchanged |
| fin/vendor-payments-export.csv | High | BANK_ACCOUNT_NUMBER x5, USA_SOCIAL_SECURITY_NUMBER x5, agentlab-employee-id x5 | public | restr | public -> restr |

Rule: automation only raises a label, never lowers it. Unknown labels count as restricted.
