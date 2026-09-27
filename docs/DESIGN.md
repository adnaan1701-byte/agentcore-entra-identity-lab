# Design notes

## Attribute contract

Every downstream decision depends on this table. Values are closed sets: anything outside them is
rejected by the interceptor **and** by the user-scoped role's trust policy (two independent checks).

| Source (Entra / HR) | Token claim | Session tag | Allowed values | Freshness | Why this source |
|---|---|---|---|---|---|
| User object ID | `oid` | **SourceIdentity** (immutable, survives role chaining) | GUID | per token | Stable, non-PII audit key |
| Tenant | `tid` | `tenant` | your tenant ID only | per token | Blocks cross-tenant tokens at three points |
| App role assignment | `roles` (exactly one) | `dept` + `role` | fin, hr / analyst, manager, contractor | token lifetime (~60–90 min) | Low-risk, stable, app-scoped, no groups-overage problem |
| HR clearance | *(not in token)* | `clr` | public, internal, restr | **live lookup every call** | High-risk attribute: a downgrade must take effect immediately |
| Calling app | `azp` | *(checked, not tagged)* | the agent client app ID | per token | Only the sanctioned agent may call |

Resource side (S3 object tags): `dept` ∈ {fin, hr}, `sensitivity` ∈ {public, internal, restr}.
Same vocabulary as the session tags. This is what makes ABAC work.

Access rule (S3 ABAC): `object.dept == session.dept` **and**
(`sensitivity == public`, or `sensitivity == internal` with `clr ∈ {internal, restr}`, or
`sensitivity == restr` with `clr == restr`).

## Key decisions

**1. Broker pattern (interceptor calls `sts:AssumeRole`) instead of `AssumeRoleWithWebIdentity`.**
STS reads session tags from a nested `https://aws.amazon.com/tags` claim, which Entra doesn't
emit natively. It would need a custom claims provider or an intermediate token service. The broker
validates the Entra token and sets tags explicitly. The cost is a highly privileged component,
so it is locked down: it may assume exactly one role, and that role's trust policy independently
enforces tag keys, tag values, the tenant and a mandatory SourceIdentity.

**2. `customClaims` for `tid` and `azp`, not `allowedClients`.** Entra v2 access tokens name the
calling app in `azp`. They don't include `client_id`, which is what a client allowlist usually
checks. So the gateway pins `aud` (API app ID), `tid` and `azp` with custom claim rules, and the
interceptor re-checks all three as defense in depth.

**3. Act-on-behalf, not impersonation.** The user's JWT stops at the interceptor (the
Authorization header is stripped before the tool). The tool receives a 15-minute credential scoped
to one role, plus identity context for logging. A compromised tool can't replay the user's token
elsewhere.

**4. The tool has no data permissions of its own.** Its role has only CloudWatch Logs. Missing or
forged context means no data, rather than falling back to a service identity.

**5. Credentials travel in the tool payload.** This mirrors AWS's own lakehouse sample. The
alternative, letting the tool mint the session from identity fields, would mean anyone able to
invoke the tool Lambda could claim any identity. Trade-off: credentials pass through the gateway
payload. They are short-lived and never logged by the lab code. Don't enable DEBUG exception level
on the gateway in production.

**6. Cedar for tool-level rules, ABAC for data-level rules, interceptor for dynamic work.** Cedar
is deterministic, audited and changeable without redeploying code (an emergency `forbid` takes
effect via API). It can't call STS or DynamoDB, so enrichment and credential vending live in the
interceptor. S3 ABAC is the last line: even with Cedar in LOG_ONLY, data access stays bounded.

**7. Tool-list filtering is UX, not enforcement.** The RESPONSE interceptor hides tools a user
can't use (least knowledge, and a smaller tool list helps the model choose correctly). Cedar is
what actually blocks the call.

## Threat model → where it is tested

| Threat | Control | Evidence |
|---|---|---|
| Unauthenticated calls | Gateway CUSTOM_JWT | S16 |
| Token for another API (e.g. Graph) | Pinned `aud` | S18 |
| Tampered / foreign-signed token | JWKS signature check (gateway + interceptor) | S17, unit tests |
| Cross-tenant token | `tid` rule at gateway, interceptor, and trust-policy tag | unit tests |
| Rogue client app | `azp` rule + interceptor allowlist | unit tests |
| User with no role | Entra "assignment required"; interceptor requires exactly one role | Dave, unit tests |
| Identity forged in tool arguments (prompt injection) | Interceptor strips `_ctx`; tool trusts only minted credentials | S08, unit tests |
| Over-privileged broker | Broker may assume one role; trust policy allowlists keys and values | B2 exercise |
| Stale privilege after a change | Live clearance lookup; 15-minute sessions | B3, B4 exercises |
| Lateral data access | S3 ABAC on dept + sensitivity | S06, S07, S11, S14 |
| Tool bypass | Tool has no S3 permissions, refuses without context | B6 exercise |
| Unattributed actions | SourceIdentity + tags in CloudTrail; interceptor audit log | audit_trail.md |

## Production gaps (say these out loud in an interview)

- **Attribute source.** Clearance lives in a demo DynamoDB table. In production it comes from HR
  or IGA (e.g. provisioned via SCIM, or an Entra custom claims provider), with an owner, a change
  process and monitoring.
- **Token freshness.** Tokens carrying roles can outlive a revocation. Consider Continuous Access
  Evaluation where supported, shorter lifetimes for the agent's API, and live checks for high-risk
  attributes.
- **Infrastructure as code.** The boto3 scripts are good for learning; production would use
  CloudFormation/CDK/Terraform with review, drift detection and SCPs (e.g. deny tagging actions
  on data, deny gateways with authorizer `NONE`).
- **Credential handling.** Evaluate a per-target outbound credential provider, or per-target
  scoped roles, instead of passing credentials in the payload.
- **Scale.** One role per user population and ABAC keeps role count flat. Watch the packed session
  size if more tags are added.
- **Data classification.** Tags here are set by hand. In production a DSPM such as Cyera or a
  platform such as Varonis classifies data and drives resource tags, and Immuta (or Lake
  Formation) applies row/column rules for warehouse data using the same attribute vocabulary.
- **Monitoring.** Alert on interceptor denies per user, STS AccessDenied spikes, and any use of the
  broker role outside the interceptor.
