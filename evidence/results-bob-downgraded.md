# Test matrix results

Run: 2026-09-27 00:07 UTC | Gateway: https://<GATEWAY_ID>.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp | Cedar policy mode: ENFORCE

**17/18 scenarios passed.**

| ID | Persona | Tool | Arguments | Expected | Actual | Result | Why |
|---|---|---|---|---|---|---|---|
| S01 | alice | tools/list |  | list_documents, read_document | list_documents, read_document | PASS | analyst does not see the manager-only tool |
| S02 | bob | tools/list |  | export_all_records, list_documents, read_document | export_all_records, list_documents, read_document | PASS | manager sees all tools |
| S03 | carol | tools/list |  | list_documents, read_document | list_documents, read_document | PASS | contractor does not see the manager-only tool |
| S04 | alice | list_documents |  | ALLOW | ALLOW (as fin/internal) | PASS | ListBucket limited to her dept prefix fin/ |
| S05 | alice | read_document | {"key": "fin/q3-revenue.csv"} | ALLOW | ALLOW (as fin/internal) | PASS | own dept, internal, clearance internal |
| S06 | alice | read_document | {"key": "fin/payroll-bank-details.csv"} | DENY:s3-abac | DENY:s3-abac (as fin/internal) | PASS | restricted doc, clearance only internal |
| S07 | alice | read_document | {"key": "hr/salaries.csv"} | DENY:s3-abac | DENY:s3-abac (as fin/internal) | PASS | other department |
| S08 | alice | read_document | {"key": "hr/salaries.csv", "_ctx": {"dept": "hr", "role": "manager", "clr": "restr"}} | DENY:s3-abac | DENY:s3-abac (as fin/internal) | PASS | forged _ctx in the request is stripped by the interceptor |
| S09 | alice | export_all_records |  | DENY:cedar-policy | DENY:cedar-policy | PASS | Cedar forbids bulk export for non-managers |
| S10 | bob | read_document | {"key": "hr/salaries.csv"} | ALLOW | DENY:s3-abac (as hr/internal) | FAIL | own dept, restricted, clearance restr |
| S11 | bob | read_document | {"key": "fin/q3-revenue.csv"} | DENY:s3-abac | DENY:s3-abac (as hr/internal) | PASS | other department |
| S12 | bob | export_all_records |  | ALLOW | ALLOW (as hr/internal) | PASS | manager may export |
| S13 | carol | read_document | {"key": "fin/team-handbook.md"} | ALLOW | ALLOW (as fin/public) | PASS | public doc in own dept |
| S14 | carol | read_document | {"key": "fin/q3-revenue.csv"} | DENY:s3-abac | DENY:s3-abac (as fin/public) | PASS | internal doc, clearance only public |
| S15 | carol | export_all_records |  | DENY:cedar-policy | DENY:cedar-policy | PASS | Cedar forbids bulk export for contractors |
| S16 | - | list_documents |  | DENY:gateway-auth | DENY:gateway-auth | PASS | no bearer token |
| S17 | alice | list_documents |  | DENY:gateway-auth | DENY:gateway-auth | PASS | signature tampered |
| S18 | alice | list_documents |  | DENY:gateway-auth | DENY:gateway-auth | PASS | valid Entra token for the wrong audience (Microsoft Graph) |
