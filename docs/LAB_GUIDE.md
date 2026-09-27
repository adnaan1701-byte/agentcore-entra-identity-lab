# Lab guide: identity propagation from Entra ID through AgentCore Gateway to STS session tags

Plan on **6–7 hours** including the "break it" exercises and write-up. Every step ends with a
checkpoint, so you know it worked before moving on. Commands are shown for macOS/Linux; on
Windows use PowerShell and `.venv\Scripts\activate`.

| Step | What you do | Time |
|---|---|---|
| 0 | Install tools, check accounts | 30 min |
| 1 | Run the local tests (no cloud) | 10 min |
| 2 | Create the Entra ID side | 30 min |
| 3 | Sign in as each persona, inspect the tokens | 20 min |
| 4 | Deploy the AWS side | 30–45 min |
| 5 | Run the test matrix | 15 min |
| 6 | Collect audit evidence | 30 min |
| 7 | Break-it exercises (your interview stories) | 90 min |
| 8 | Screenshots, GitHub, resume | 60 min |
| 9 | Tear down | 15 min |

---

## Step 0: Prerequisites (30 min)

**Accounts**

- **Entra ID tenant where you are Global Administrator** (or Application Administrator + User
  Administrator). A free Azure account's "Default Directory" works. Don't use an employer tenant.
- **AWS account** with an IAM identity that can manage IAM, Lambda, S3, DynamoDB, Bedrock
  AgentCore, and read CloudTrail and CloudWatch Logs. Use a sandbox account.
- **Region:** `us-east-1` (or another region where Bedrock AgentCore Gateway *and* Policy are
  available: check the AgentCore console).

**Tools**

- Python 3.10+
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az version`)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), configured (`aws sts get-caller-identity`)

```bash
cd agentcore-entra-identity-lab
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

✅ **Checkpoint:** `aws sts get-caller-identity` shows your sandbox account, and `az version` works.

---

## Step 1: Local tests (10 min)

```bash
pytest -q
```

✅ **Checkpoint:** `29 passed` (55 once you add the data-side modules in DATA_SECURITY_MODULES.md). These tests stand up a fake Entra (a local signing key + JWKS),
fake STS/DynamoDB/S3 (moto) and prove the interceptor fails closed on 15 kinds of bad token,
attribute or STS refusal: wrong audience, v1 issuer, other tenant, unlisted app, expired, forged signature,
missing role, and more. Read `tests/test_interceptor.py`: the test names are a good interview
checklist.

---

## Step 2: Entra ID setup (30 min)

```bash
az login --tenant <YOUR_TENANT_ID> --allow-no-subscriptions
python entra/setup_entra.py
```

What the script creates, via Microsoft Graph:

| Object | Detail | Why |
|---|---|---|
| App registration `agentlab-gateway-api` | Exposes `api://<appId>/access_as_user`; `requestedAccessTokenVersion = 2`; app roles `Finance.Analyst`, `Finance.Contractor`, `HR.Manager` | Represents the tools behind the gateway. v2 tokens have the issuer AgentCore expects |
| Enterprise app for it | `appRoleAssignmentRequired = true` | Users without a role can't get a token at all (Dave) |
| App registration `agentlab-agent-client` | Public client (device code), pre-authorised on the API scope | The "agent" the user signs in to |
| Users alice, bob, carol, dave | Random passwords, no forced change | Personas |
| App role assignments | alice→Finance.Analyst, bob→HR.Manager, carol→Finance.Contractor | Become the `roles` claim |

✅ **Checkpoint:** the script prints four users and writes `.lab/entra.json`. In the Entra admin
center → **Enterprise applications → agentlab-gateway-api → Users and groups**, you see three
assignments. **Take a screenshot** (`evidence/screenshots/01-entra-app-roles.png`).

> Look at **App registrations → agentlab-gateway-api → Manifest** and find
> `"requestedAccessTokenVersion": 2`. You will break this on purpose in exercise B1.

---

## Step 3: Tokens (20 min)

```bash
python client/get_token.py all
```

For each persona the script prints a device code and the user's password. Open
<https://microsoft.com/devicelogin> in a **private/incognito window**, enter the code and sign in
as that user. If Entra asks to set up MFA (security defaults), you can register the Authenticator
app or choose "Skip for now" if it is offered.

✅ **Checkpoint:** for alice, bob and carol you see claims like:

```
iss                  https://login.microsoftonline.com/<tenant>/v2.0
aud                  <api app id>          <- v2 tokens use the app ID GUID as audience
azp                  <client app id>       <- the calling app (NOT client_id)
tid                  <tenant id>
oid                  <user object id>      <- becomes STS SourceIdentity
roles                ['Finance.Analyst']
scp                  access_as_user
ver                  2.0
```

For **dave** you should get an error like `AADSTS50105 ... not assigned to a role for the
application`. That is a **pass**: the first control layer stopped him before a token existed.

Paste alice's raw token into <https://jwt.ms> and screenshot the claims
(`02-token-claims.png`). Tokens are cached in `.lab/tokens/`, which is git-ignored.

---

## Step 4: AWS deploy (30–45 min, mostly waiting)

```bash
python aws/deploy.py --region us-east-1
```

What happens, in order:

1. **IAM** (each policy is validated with IAM Access Analyzer first)
   - `agentlab-interceptor-role`: may *only* `AssumeRole` + `TagSession` + `SetSourceIdentity` on
     the user-scoped role, and read the HR table.
   - `agentlab-user-scoped-role`: trust policy accepts only the interceptor, only the four
     allowlisted tag keys with allowlisted values, only your tenant, and requires a SourceIdentity.
     Its permission policy is the S3 ABAC policy.
   - `agentlab-docs-tool-role`: logs only. **No S3.**
   - `agentlab-gateway-role`: invoke the two Lambdas, evaluate Cedar policies.
2. **Data:** S3 bucket with five objects tagged `dept` + `sensitivity`; DynamoDB HR table with
   each user's clearance.
3. **Lambdas:** interceptor (with PyJWT, packaged for Linux automatically) and the docs tool.
4. **Gateway:** `CUSTOM_JWT` inbound auth with your tenant's v2 discovery URL, allowed audience =
   API app ID, custom claim rules `tid == your tenant` and `azp == client app`.
5. **Target** `docs` with three tools.
6. **Policy engine** + Cedar policies (`permit_all`, then `forbid_export_unless_manager`).
7. **Attach** the interceptor (REQUEST + RESPONSE, `passRequestHeaders = true`) and the policy
   engine in `ENFORCE` mode. (Policies are created before the interceptor is attached, because
   Cedar validation calls the gateway without a user token.)

✅ **Checkpoint:** `done. Gateway URL: https://...` and `.lab/aws.json` exists. In the AWS console →
**Bedrock AgentCore → Gateways → agentlab-gateway**, screenshot the inbound auth and
interceptor configuration (`03-gateway-config.png`), and the Cedar policies
(`04-cedar-policies.png`).

---

## Step 5: Run the test matrix (15 min)

```bash
python client/run_scenarios.py
```

You should see 18 scenarios, for example:

```
PASS  S05 alice  read_document   expect=ALLOW              got=ALLOW (as fin/internal)
PASS  S06 alice  read_document   expect=DENY:s3-abac       got=DENY:s3-abac
PASS  S08 alice  read_document   expect=DENY:s3-abac       got=DENY:s3-abac   <- forged _ctx ignored
PASS  S09 alice  export_all_records expect=DENY:cedar-policy got=DENY:cedar-policy
PASS  S18 alice  list_documents  expect=DENY:gateway-auth  got=DENY:gateway-auth <- Graph token
```

✅ **Checkpoint:** `18/18 passed` and `evidence/results.md` exists. (With the data-side modules deployed the matrix has 22 scenarios; see DATA_SECURITY_MODULES.md.)

If a Cedar scenario shows `DENY:tool-error` or similar instead of `DENY:cedar-policy`, open
`evidence/results.json`, find S09 and read the actual message. The gateway's deny format may
differ slightly from what the classifier expects. What matters is that the call was denied, and
by which layer. Note what you see; it's a good detail to mention in an interview.

---

## Step 6: Audit evidence (30 min)

Wait about 10 minutes after step 5 (CloudTrail event history lags), then:

```bash
python client/collect_evidence.py
```

✅ **Checkpoint:** `evidence/audit_trail.md` contains rows like:

| Persona | SourceIdentity (Entra oid) | Session tags | Result |
|---|---|---|---|
| alice | 3f1c…-… | clr=internal, dept=fin, role=analyst | success |
| bob | 9a2e…-… | clr=restr, dept=hr, role=manager | success |

Also open **CloudTrail → Event history**, filter *Event name = AssumeRole*, open one event and
screenshot `sourceIdentity` and `tags` in the JSON (`05-cloudtrail-assumerole.png`). Then open
**CloudWatch → Log groups → /aws/lambda/agentlab-interceptor** and screenshot an `"audit": "deny"`
line (`06-interceptor-audit.png`).

---

## Step 7: Break-it exercises (90 min)

Each exercise gives you a concrete "I broke it, saw the symptom, understood the cause" story.
Rerun `python client/run_scenarios.py` after each change, then revert.

**B1: The v1/v2 token trap (Entra).** In the API app's **Manifest**, set
`"requestedAccessTokenVersion": null` and save. Delete `.lab/tokens/alice.cache.bin` and run
`python client/get_token.py alice`: `iss` is now `https://sts.windows.net/<tenant>/` and `ver` is
`1.0`. The matrix now fails at the gateway with 401 for alice. *Why:* the discovery URL is v2, so
the issuer doesn't match. Revert to `2`, delete the cache, get a new token.

**B2: Missing `sts:TagSession`.** In IAM, edit the trust policy of `agentlab-user-scoped-role`
and remove `"sts:TagSession"`. Alice's calls now fail with
`[interceptor] STS refused the tagged session: AccessDenied`. *Why:* passing session tags is its
own permission. Note that the system **failed closed**. Revert by re-running
`python aws/deploy.py`.

**B3: Live attribute change without a new token.** In DynamoDB, open table
`agentlab-hr-attributes` and change bob's `clearance` from `restr` to `internal`. Without signing
bob in again, rerun the matrix: S10 (bob reads `hr/salaries.csv`) is now denied by S3 ABAC.
*Why:* clearance is looked up live on every call, so a downgrade takes effect immediately. Set it
back to `restr`.

**B4: Revocation lag for token-borne attributes.** In Entra, remove carol's app role assignment.
Rerun the matrix right away: carol still works, because her cached access token still carries
`roles`. Delete `.lab/tokens/carol.cache.bin` and try `get_token.py carol`: she can no longer get
a token. *Lesson:* attributes in tokens are only as fresh as the token (about 60–90 minutes), so
keep high-risk attributes on live lookups and STS sessions short (this lab uses 15 minutes).
Re-add the assignment.

**B5: Cedar in LOG_ONLY.** Run `python aws/deploy.py --policy-mode LOG_ONLY`, then the matrix.
Alice's export (S09) is now *allowed by Cedar*, but look at what she actually got: S3 ABAC still
blocked the restricted file (`blocked: ["fin/payroll-bank-details.csv"]`). That is defense in
depth in action. Check the gateway's CloudWatch logs for the would-deny decision. Redeploy with
the default `ENFORCE` mode.

**B6: Bypass the gateway.** Invoke the tool directly:

```bash
aws lambda invoke --function-name agentlab-docs-tool \
  --client-context $(echo -n '{"custom":{"bedrockAgentCoreToolName":"docs___read_document"}}' | base64) \
  --cli-binary-format raw-in-base64-out --payload '{"key":"hr/salaries.csv"}' out.json && cat out.json
```

It refuses with *no trusted identity context*. Even if it didn't, the tool role has no S3
permissions. *Lesson:* the tool trusts nothing except credentials minted for a human.

---

## Step 8: Screenshots, GitHub, resume (60 min)

1. Check `evidence/screenshots/` has 01–06.
2. Add a **Results** section to the README: paste the pass count and a few rows from
   `evidence/results.md` and `evidence/audit_trail.md`. **Redact** tenant IDs, account IDs and
   object IDs (replace with `<tenant>` etc.).
3. `git init && git add . && git status`. **Confirm `.lab/` is not listed**, then commit and push
   to a public GitHub repo.
4. Open [INTERVIEW_PREP.md](INTERVIEW_PREP.md) and fill in the resume bullets with your real
   numbers.

---

## Step 9: Teardown (15 min)

```bash
python aws/teardown.py --region us-east-1
python entra/teardown_entra.py
```

✅ **Checkpoint:** in the AgentCore console no `agentlab-gateway` remains; in Entra the four users
and two app registrations are gone. Check **Billing** the next day.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `az account get-access-token` fails | Not logged in, or no subscription | `az login --tenant <id> --allow-no-subscriptions` |
| Graph 403 creating users or apps | Not an admin in this tenant | Use a tenant where you are Global Administrator |
| `AADSTS65001` consent required | Pre-authorisation not yet replicated | Wait 2 minutes, retry; or grant admin consent on the client app in the portal |
| `AADSTS50105` for alice/bob/carol | Role assignment missing or not replicated | Check Enterprise app → Users and groups; wait 2 minutes |
| `AADSTS50076` / MFA prompt | Security defaults | Complete MFA registration or skip if offered |
| Every call returns 401 | Issuer or audience mismatch | Decode the token: `iss` must end in `/v2.0` and `aud` must equal the API app ID. Still failing? `python aws/deploy.py --no-custom-claims` (the interceptor still checks `tid`/`azp`) |
| `[interceptor] missing bearer token` | Headers not passed to interceptor | Re-run deploy; check `passRequestHeaders` on the gateway |
| `[interceptor] STS refused ... AccessDenied` | Trust policy conditions (tag value, tenant, SourceIdentity) | Compare the tags in the interceptor log with `aws/policies/user_scoped_trust.json` |
| `[interceptor] no HR record` | DynamoDB not seeded for this user | Re-run deploy (it re-seeds from `.lab/entra.json`) |
| Tool says "no trusted identity context" | Interceptor not attached | Re-run deploy; check the gateway's interceptor configuration |
| Cedar policy creation fails | Validation findings or region support | Read the message; deploy with `--no-policy` to continue and fix later |
| `AccessDeniedException` from bedrock-agentcore | Your IAM user lacks AgentCore permissions, or region unsupported | Add permissions / switch region |
| `collect_evidence.py` shows 0 events | CloudTrail lag | Wait 10–15 minutes, rerun |
