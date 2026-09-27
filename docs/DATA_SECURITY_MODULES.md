# Data security modules: where Cyera, Varonis and Immuta fit

The core lab answers **"who is asking?"**: the Entra ID identity travels into STS session tags,
and S3 ABAC compares those tags with the data's tags. These three modules cover the other half
of the job, **the data side**, which is what DSPM and data-security platforms do.

> **Honesty note.** Cyera, Varonis and Immuta are enterprise platforms sold through demos and
> proofs of concept; there is no self-serve tier to connect to a personal lab. Each module builds
> the *same control* with AWS-native parts (Amazon Macie, CloudTrail data events, a policy engine
> and DynamoDB fine-grained access) and documents exactly where the real product plugs in.
> Describe it that way on a resume: "prototyped", "modelled on", never "implemented Cyera".

```
Entra (who) -> Gateway -> Interceptor -> STS tags: dept / role / clr ---+
                                                                       +--> S3 ABAC / DynamoDB FGAC
Module C: Macie classifies data -> object tags: dept / sensitivity ----+
Module I: same attributes -> row filter + column masking (policy as code)
Module V: CloudTrail data events + SourceIdentity -> per-person report and alerts
```

| Module | Stands in for | Question it answers | What you build |
|---|---|---|---|
| **C** | Cyera (DSPM), Varonis classification | *What is this data, how sensitive?* | Macie job + custom identifier -> adapter that raises the `sensitivity` tag ABAC already uses |
| **I** | Immuta | *Which rows and columns may this person see?* | `query_employees` tool: subscription policy, row filter, column masking, with DynamoDB fine-grained access control as the AWS backstop |
| **V** | Varonis (activity, UEBA) | *Who touched what, and is it normal?* | CloudTrail data-event trail + report with BULK_READ, PROBING and EXPOSURE alerts |

## Run order (about 1.5 to 2 hours, most of it waiting for Macie and CloudTrail)

Run everything from the lab folder with the venv active.

### 0. Update and test locally

```powershell
pytest -q                                    # 56 passed
```

### 1. Start recording data access (module V, step 1)

Do this **first**: CloudTrail only records from the moment the trail exists.

```powershell
python monitor/enable_data_events.py
```

### 2. Redeploy (adds the employees table, the fine-grained IAM policy and the new tool)

```powershell
python aws/deploy.py --region us-east-1
python client/run_scenarios.py               # 22/22 (S19-S22 are new)
```

Look for `Access Analyzer: user-scoped DynamoDB FGAC has no findings` (warnings are fine; an
ERROR stops the deploy), `created table agentlab-employees` and `seeded 7 employee rows`.

### 3. Module I: row and column policies (Immuta-style)

```powershell
python client/call_tool.py alice query_employees           # fin rows, salary + bank REDACTED
python client/call_tool.py alice query_employees dept=hr   # still fin rows: the row filter wins
python client/call_tool.py bob query_employees             # hr rows, nothing masked
python client/call_tool.py carol query_employees           # DENY (data-policy): not subscribed
```

What is happening:
- The policy is **written once** in `lambdas/data_tool/data_policies.json` (subscription policy,
  row filter on `dept_code = user.dept`, mask `salary_usd` and `bank_last4` unless `clr = restr`).
- The attributes come from the same place as everything else: Entra app role -> dept/role,
  HR store -> clearance, carried in the tagged session.
- **Masking is enforced twice.** The tool never asks DynamoDB for a masked column, and the session's
  IAM policy (`dynamodb:LeadingKeys` for rows, `dynamodb:Attributes` for columns) would refuse it
  anyway. A bug in the tool cannot reveal salaries to Alice.
- Carol does not even see `query_employees` in `tools/list`, and calling it directly is still
  refused. Hidden is not the same as blocked; the scenario matrix tests both.

**Where real Immuta plugs in:** Immuta syncs user attributes from the identity provider (Entra),
you author subscription and data policies once, and Immuta enforces them natively in Snowflake,
Databricks, Redshift, or S3 (through S3 Access Grants). For an agent, the key requirement is the
same as in this lab: the query must run **as the end user** (propagated identity), not as a
shared service account, or the per-user policies never apply.

### 4. Module C: classification drives the tags (Cyera-style)

```powershell
python dspm/classify.py plant                                                       # the mistake
python client/call_tool.py carol read_document key=fin/vendor-payments-export.csv   # ALLOW: card numbers leak
python dspm/classify.py scan                                                        # Macie, 10-25 min
python dspm/classify.py apply                                                       # public -> restr
python client/call_tool.py carol read_document key=fin/vendor-payments-export.csv   # DENY (s3-abac)
```

What is happening:
- `plant` uploads a file with fake card numbers and SSNs, **tagged `public`** by mistake. Identity
  controls are all correct, yet Carol (clearance `public`) can read it. A wrong data label defeats
  correct identity controls. That is the problem DSPM exists to solve.
- `scan` enables Macie (if needed), adds a custom data identifier for the lab's employee IDs (like a
  Cyera custom classifier), runs a one-time job on the bucket and proposes labels.
- `apply` raises the `sensitivity` tag. **Labels only go up, never down**: automation that could
  downgrade a label is itself a data-leak path. Unknown labels count as restricted.
- No policy changed. Carol is blocked because the data is now described correctly.
- While the job runs, open the Macie console -> Jobs, then Findings, for screenshots.

**Where real Cyera plugs in:** Cyera connects agentlessly (a read-only cross-account role),
discovers and classifies S3, RDS, DynamoDB and SaaS data, and maps which identities can reach
sensitive data. In this design its labels feed the resource tags (or a catalog the interceptor or
Immuta reads), replacing `dspm/classify.py`'s Macie adapter. Cyera has also published an
integration with IAM Access Analyzer that produces a "who can access restricted data" matrix.

### 5. Module V: who touched what, and is it normal (Varonis-style)

Wait about 10 minutes after the last activity (CloudTrail delivers log files every ~5 minutes), then:

```powershell
python monitor/access_report.py
notepad evidence\access_report.md
```

Expected alerts from the activity above:
- `BULK_READ bob`: the export reads several HR files in seconds.
- `PROBING alice`: S06-S08 are three denials in a row.
- `EXPOSURE carol` (HIGH): she read `vendor-payments-export.csv` while it was mislabelled; it is now
  `restr` and her clearance is `public`. This joins module C (classification) with activity history
  to answer the incident question: *who saw it before we fixed the label?*

The report's first line is the point of the whole lab: every agent event used **one** IAM role,
and SourceIdentity resolves them to named people. Without identity propagation, a tool like Varonis
could only say "the agent did it".

**Where real Varonis plugs in:** Varonis ingests AWS activity (CloudTrail) and Entra ID events,
classifies data, maps identities to data ("blast radius"), runs behaviour-based threat models
(unusual access, mass downloads, privilege escalation) and can remediate automatically. Identity
propagation is what lets it attribute an agent's actions to the human behind them.

## Screenshots for your evidence folder

| File | What |
|---|---|
| `18-query-employees-masking.png` | Alice's masked rows next to Bob's unmasked rows |
| `19-macie-finding.png` | Macie console finding for `vendor-payments-export.csv` (crop account ID) |
| `20-dspm-relabel.png` | `classify.py apply` output + Carol ALLOW before / DENY after |
| `21-access-report-alerts.png` | The alerts table from `evidence/access_report.md` |

## Cost and cleanup

- Macie: a sensitive-data job on a few KB costs a fraction of a cent (new accounts get a 30-day
  Macie trial for bucket monitoring). `aws/teardown.py` disables Macie if the lab enabled it.
- CloudTrail data events: $0.10 per 100,000 events. Teardown deletes the trail and log bucket.
- DynamoDB on-demand: effectively $0 at this volume. Teardown deletes the table.

## Talk track (60 seconds)

> "Identity propagation answers who is asking. The data side answers what the data is, what each
> person may see inside it, and what they actually did. I prototyped all three with AWS-native
> pieces. Macie classification drives the same S3 tags my ABAC policy checks, so a mislabelled file
> became unreadable to a contractor without touching any policy, and automation can only raise a
> label. An Immuta-style policy, written once, filters rows and masks columns from the same Entra
> attributes, with DynamoDB fine-grained access as a second enforcement point. And because every
> session carries the Entra object ID as SourceIdentity, CloudTrail data events turn into a
> per-person report with bulk-read, probing and exposure alerts. In a client environment, Cyera,
> Immuta and Varonis replace those three pieces; the identity contract underneath stays the same."
