# Interview prep: turning the lab into resume lines and stories

**Be precise about what this is: a personal lab you designed, built and tested end to end.** That
is a strong, honest claim, especially with real evidence (test matrix, CloudTrail) you can show.
Only use numbers you actually got.

## Resume: project entry

**Identity propagation for AI agents: Entra ID → Amazon Bedrock AgentCore Gateway → AWS STS** *(personal lab, [Month Year])* · github.com/<you>/agentcore-entra-identity-lab

Pick 3–4 bullets:

- Built an end-to-end lab that carries a user's Microsoft Entra ID identity through Amazon Bedrock AgentCore Gateway into AWS STS session tags, so AI-agent tool calls run with the human caller's permissions, not the agent's.
- Configured Entra ID (app registrations, app roles, v2 tokens, assignment-required enterprise app) and an AgentCore CUSTOM_JWT authorizer pinned to audience, tenant (`tid`) and calling app (`azp`).
- Wrote a Python gateway interceptor that re-validates Entra tokens, maps claims through an attribute contract, looks up clearance live, and mints 15-minute STS sessions with transitive tags and SourceIdentity; it fails closed on [15] negative cases covered by unit tests.
- Enforced least privilege in four layers (gateway JWT validation, interceptor, Cedar policy, S3 ABAC on `aws:PrincipalTag` vs object tags); passed [18/18] persona-by-tool scenarios, including forged-identity and wrong-audience attacks.
- Produced audit evidence linking every AWS action to an Entra user via CloudTrail SourceIdentity and session tags; validated all IAM policies with IAM Access Analyzer.
- Prototyped the data-security side with AWS-native stand-ins mapped to Cyera, Immuta and Varonis: Macie classification that raises ABAC tags on mislabelled data, Immuta-style row filtering and column masking backed by DynamoDB fine-grained access control, and CloudTrail data-event analytics with per-person bulk-read, probing and exposure alerts.

**Skills line:** Microsoft Entra ID · OAuth 2.0/OIDC · JWT validation · AWS IAM/STS session tags · ABAC · Amazon Bedrock AgentCore (Gateway, Policy/Cedar, interceptors) · MCP · Python/boto3 · CloudTrail · Amazon Macie (DSPM concepts) · DynamoDB fine-grained access control

## 60-second pitch

> "The role is about making sure an AI agent acts as the person who asked. I built a lab to prove
> I can do that end to end. A user signs in with Entra ID. The agent calls AgentCore Gateway with
> the user's v2 access token, and the gateway validates it: audience, tenant, and the calling app
> via the `azp` claim, since Entra tokens don't carry `client_id`. A request interceptor then
> re-validates the token, maps the app role to department and role through an attribute contract,
> looks up clearance live, and calls STS AssumeRole with those values as session tags, plus the
> user's object ID as SourceIdentity. Downstream, Cedar blocks the bulk-export tool for
> non-managers, and S3 ABAC compares the session tags with object tags. I tested 18 scenarios,
> including a forged identity in the tool arguments and a Graph token replayed at the gateway,
> and CloudTrail shows every session tied to a named user."

## STAR stories from the break-it exercises

**1. The v1/v2 token trap (B1): troubleshooting across Microsoft and AWS**
- *S/T:* Tokens that looked valid got 401 at the gateway.
- *A:* Decoded the token: `iss` was `sts.windows.net/...` and `ver` was `1.0`, while the gateway
  trusted the v2 discovery URL. Traced it to `requestedAccessTokenVersion` on the API app.
- *R:* Fixed it on the Entra side, not by relaxing validation. Lesson: always debug from a
  decoded real token, with the identity team in the room.

**2. Missing `sts:TagSession` (B2): least privilege and failing closed**
- *A:* Removed `sts:TagSession` from the trust policy; the interceptor got AccessDenied and
  returned an explicit error.
- *R:* No request reached the data untagged. Passing tags is a separate permission, and a broker
  must fail closed.

**3. Freshness (B3 vs B4): token attributes vs live attributes**
- *A:* Downgraded Bob's clearance in the HR store: blocked on the next call. Removed Carol's app
  role in Entra: her cached token kept working until expiry.
- *R:* Designed the contract so low-risk attributes come from the token and high-risk ones via
  live lookup, with 15-minute STS sessions. This is exactly the conversation to have with a
  client's identity team about joiner/mover/leaver timing.

**4. Defense in depth (B5)**
- *A:* Put Cedar into LOG_ONLY; the bulk export ran, but S3 ABAC still blocked the restricted
  file.
- *R:* No single control is load-bearing. Start new Cedar policies in LOG_ONLY, compare the
  decisions against the test matrix, then enforce.

**5. The bypass attempt (B6): the tool refuses to act without a trusted identity**
- *A:* Invoked the tool Lambda directly, skipping the gateway, then with forged credentials in `_ctx`.
- *R:* No trusted context -> explicit DENIED; forged credentials -> rejected by STS. Hardening I'd
  add: a Lambda resource policy so only the gateway role can invoke it, and catching credential
  errors to return a clean denial instead of a stack trace.

**6. Mislabelled data (module C): correct identity controls, wrong data label**
- *S/T:* A file with card numbers and SSNs was uploaded tagged `public`; the contractor could read it.
- *A:* Ran a Macie classification job (with a custom identifier, like a Cyera custom classifier)
  and an adapter that turns findings into the `sensitivity` tag. Labels can only go up.
- *R:* The contractor's next read was denied with no policy change. Then the activity report
  raised an EXPOSURE alert naming who had read it before the fix: that is the incident answer.

**7. Row and column policies (module I): Immuta's model on AWS**
- *A:* One policy file: contractors not subscribed, rows filtered to the user's department, pay
  columns masked unless clearance is restricted. The tool never requests masked columns, and
  DynamoDB `LeadingKeys`/`Attributes` conditions refuse them in IAM too.
- *R:* Alice asking for HR rows still got only finance rows, with salaries redacted.

## Questions you should expect, and your lab-backed answers

**"How would you work with a client's Entra team?"** Start from the attribute contract: which
attributes exist, who owns them, how clean they are, how fast changes land. Decode a real token
together. Ask for app roles over groups (overage), v2 tokens, "assignment required", and a
pre-authorised client app.

**"Why not just forward the user's JWT to every tool?"** Impersonation: every tool gets a token
it can replay. I stop the JWT at the interceptor and give the tool a 15-minute credential for one
role (act-on-behalf).

**"Why the broker instead of AssumeRoleWithWebIdentity?"** STS reads tags from a nested
`https://aws.amazon.com/tags` claim that Entra doesn't emit natively. The broker is simpler and
fully controlled, but privileged, so its target role's trust policy independently enforces tag
keys, values, tenant and SourceIdentity.

**"What if the model is prompt-injected?"** It can choose tools and arguments, never identity. I
tested a forged `_ctx` in the arguments: the interceptor discards it, and S3 still decides using
the real session tags.

**"How do you audit this?"** SourceIdentity (Entra `oid`, not email) is immutable and appears in
CloudTrail for every action in the session, alongside the tags. The interceptor logs each
allow/deny decision without tokens or credentials.

**"Where do Varonis, Cyera and Immuta fit?"** (Say you prototyped each with AWS-native parts;
see DATA_SECURITY_MODULES.md.) They supply and enforce the *data* side of the same
comparison. Cyera or Varonis discover and classify data, which drives the `sensitivity` and `dept`
resource tags I set by hand. Varonis also right-sizes entitlements and flags abnormal access per
human, which only works because identity is propagated. Immuta applies row/column rules in
Snowflake or Databricks using the same attribute vocabulary, and its agentic data access vends
temporary, task-scoped roles, the same act-on-behalf idea.

**"What would you change for production?"** See DESIGN.md → *Production gaps*: IaC with review,
an authoritative HR/IGA attribute source, SCPs, CAE/shorter token lifetimes, per-target outbound
credentials, and monitoring on interceptor denies and broker-role use.

## Show-and-tell checklist for Monday

- [ ] GitHub repo public, `.lab/` not committed, IDs redacted in the README results
- [ ] `evidence/results.md` (18/18) open in a tab
- [ ] Screenshot: token claims in jwt.ms (`aud`, `azp`, `roles`, `ver`)
- [ ] Screenshot: CloudTrail AssumeRole with `sourceIdentity` and `tags`
- [ ] Screenshot: gateway inbound auth + interceptor config
- [ ] Be ready to draw the sequence diagram from memory in 2 minutes
