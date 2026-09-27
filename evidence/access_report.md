# Data access report (Varonis-style, built from CloudTrail data events)

Window: last 6 h | generated 2026-09-27 04:09 UTC | 78 data events, 20 made by agent sessions

All 20 agent events used **one** IAM role (agentlab-user-scoped-role). SourceIdentity resolves them to **3 named people**. Without identity propagation, this report could only say "the agent did it".

## Alerts

| Severity | Rule | Person | Detail | First seen (UTC) |
|---|---|---|---|---|
| HIGH | EXPOSURE | carol | read fin/vendor-payments-export.csv which is now labelled 'restr' but their clearance is 'public': review what was exposed | 03:39:37 |
| MEDIUM | PROBING | alice | 3 access denials within 10 min (someone, or a prompt-injected agent, testing boundaries?) | 03:37:13 |
| MEDIUM | BULK_READ | bob | 3 object reads within 2 min (agent over-collection or bulk export?) | 03:37:20 |

## Per-person activity through the agent

| Person | Entra UPN | Clearance now | Reads allowed | Denied | Distinct objects | Most sensitive data read | Last activity (UTC) |
|---|---|---|---|---|---|---|---|
| alice | alice.agentlab@<TENANT_DOMAIN> | internal | 5 | 3 | 5 | internal | 03:43:07 |
| bob | bob.agentlab@<TENANT_DOMAIN> | restr | 5 | 1 | 5 | restr | 03:43:16 |
| carol | carol.agentlab@<TENANT_DOMAIN> | public | 2 | 2 | 3 | restr | 04:00:38 |

## Who touched each object

| Object | Label now | Read by | Denied to |
|---|---|---|---|
| agentlab-employees | - | alice (4), bob (2) | - |
| fin/* | - | alice (1) | - |
| fin/payroll-bank-details.csv | restr | - | alice (1) |
| fin/q3-revenue.csv | internal | alice (1) | bob (1), carol (1) |
| fin/team-handbook.md | public | carol (1) | - |
| fin/vendor-payments-export.csv | restr | carol (1) | carol (1) |
| hr/* | - | bob (1) | - |
| hr/holiday-calendar.csv | internal | bob (1) | - |
| hr/salaries.csv | restr | bob (2) | alice (2) |

## Other principals (not through the agent)

| Principal | Action | Events |
|---|---|---|
| Amazon Macie (DSPM scanner) | GetObject | 6 |
| Amazon Macie (DSPM scanner) | GetObjectAcl | 6 |
| Amazon Macie (DSPM scanner) | GetObjectTagging | 6 |
| Amazon Macie (DSPM scanner) | HeadObject | 6 |
| Amazon Macie (DSPM scanner) | ListObjects | 1 |
| IAM user agentlab-admin | GetObjectTagging | 18 |
| IAM user agentlab-admin | HeadBucket | 1 |
| IAM user agentlab-admin | PutItem | 7 |
| IAM user agentlab-admin | PutObject | 6 |
| IAM user agentlab-admin | PutObjectTagging | 1 |
