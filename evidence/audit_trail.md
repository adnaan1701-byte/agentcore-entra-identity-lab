# Audit trail

## CloudTrail: tagged sessions minted for humans

| Time (UTC) | Persona | SourceIdentity (Entra oid) | Session name | Session tags | Result |
|---|---|---|---|---|---|
| 2026-09-26T23:13:55Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790464435 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:13:58Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790464438 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:14:00Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790464440 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:14:02Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790464442 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:14:03Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790464443 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:14:05Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790464445 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:14:05Z | bob | <BOB_OID> | agentlab-<BOB_OID8>-1790464445 | clr=restr, dept=hr, role=manager | success |
| 2026-09-26T23:14:09Z | bob | <BOB_OID> | agentlab-<BOB_OID8>-1790464449 | clr=restr, dept=hr, role=manager | success |
| 2026-09-26T23:14:10Z | bob | <BOB_OID> | agentlab-<BOB_OID8>-1790464450 | clr=restr, dept=hr, role=manager | success |
| 2026-09-26T23:14:12Z | carol | <CAROL_OID> | agentlab-<CAROL_OID8>-1790464452 | clr=public, dept=fin, role=contractor | success |
| 2026-09-26T23:14:14Z | carol | <CAROL_OID> | agentlab-<CAROL_OID8>-1790464454 | clr=public, dept=fin, role=contractor | success |
| 2026-09-26T23:14:15Z | carol | <CAROL_OID> | agentlab-<CAROL_OID8>-1790464455 | clr=public, dept=fin, role=contractor | success |
| 2026-09-26T23:26:12Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790465172 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:26:15Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790465175 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:26:16Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790465176 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:26:18Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790465178 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:26:20Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790465180 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:26:22Z | alice | <ALICE_OID> | agentlab-<ALICE_OID8>-1790465182 | clr=internal, dept=fin, role=analyst | success |
| 2026-09-26T23:26:22Z | bob | <BOB_OID> | agentlab-<BOB_OID8>-1790465182 | clr=restr, dept=hr, role=manager | success |
| 2026-09-26T23:26:25Z | bob | <BOB_OID> | agentlab-<BOB_OID8>-1790465185 | clr=restr, dept=hr, role=manager | success |
| 2026-09-26T23:26:27Z | bob | <BOB_OID> | agentlab-<BOB_OID8>-1790465187 | clr=restr, dept=hr, role=manager | success |
| 2026-09-26T23:26:29Z | carol | <CAROL_OID> | agentlab-<CAROL_OID8>-1790465189 | clr=public, dept=fin, role=contractor | success |
| 2026-09-26T23:26:30Z | carol | <CAROL_OID> | agentlab-<CAROL_OID8>-1790465190 | clr=public, dept=fin, role=contractor | success |
| 2026-09-26T23:26:32Z | carol | <CAROL_OID> | agentlab-<CAROL_OID8>-1790465192 | clr=public, dept=fin, role=contractor | success |

## Interceptor decisions (CloudWatch Logs)

| Decision | Tool | Persona | dept | role | clr | Detail |
|---|---|---|---|---|---|---|
| tools_list_filtered |  |  |  | analyst |  | tools shown: list_documents, read_document |
| tools_list_filtered |  |  |  | manager |  | tools shown: export_all_records, list_documents, read_document |
| tools_list_filtered |  |  |  | contractor |  | tools shown: list_documents, read_document |
| allow | docs___list_documents | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal | forged _ctx stripped |
| allow | docs___export_all_records | alice | fin | analyst | internal |  |
| allow | docs___read_document | bob | hr | manager | restr |  |
| allow | docs___read_document | bob | hr | manager | restr |  |
| allow | docs___export_all_records | bob | hr | manager | restr |  |
| allow | docs___read_document | carol | fin | contractor | public |  |
| allow | docs___read_document | carol | fin | contractor | public |  |
| allow | docs___export_all_records | carol | fin | contractor | public |  |
| tools_list_filtered |  |  |  | analyst |  | tools shown: list_documents, read_document |
| tools_list_filtered |  |  |  | manager |  | tools shown: export_all_records, list_documents, read_document |
| tools_list_filtered |  |  |  | contractor |  | tools shown: list_documents, read_document |
| allow | docs___list_documents | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal |  |
| allow | docs___read_document | alice | fin | analyst | internal | forged _ctx stripped |
| allow | docs___export_all_records | alice | fin | analyst | internal |  |
| allow | docs___read_document | bob | hr | manager | restr |  |
| allow | docs___read_document | bob | hr | manager | restr |  |
| allow | docs___export_all_records | bob | hr | manager | restr |  |
| allow | docs___read_document | carol | fin | contractor | public |  |
| allow | docs___read_document | carol | fin | contractor | public |  |
| allow | docs___export_all_records | carol | fin | contractor | public |  |
