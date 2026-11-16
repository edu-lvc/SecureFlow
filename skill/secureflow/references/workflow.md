# SecureFlow Workflow

This reference expands the six phases in `SKILL.md`. Use it for non-trivial changes. The goal is
not paperwork; it is to make security decisions visible and verifiable.

## Phase 0: Scope and context

Collect:

- Repository root and revision.
- Languages, frameworks, and runtime versions.
- Entry points: HTTP routes, message consumers, scheduled jobs, CLI commands, webhooks.
- Data stores and external services.
- Identity model: anonymous, cookie, bearer token, API key, service account, mTLS.
- Deployment: container, serverless, VM, desktop, CI-only.
- Existing controls: gateway auth, WAF, framework middleware, centralized policy.
- Existing tests and how to run them.

Output a short scope note:

```text
In scope: src/Api/**, src/Domain/**, appsettings*.json
Out of scope: infrastructure repository, third-party SaaS configuration
Assumptions: TLS terminates at the ingress; identity provider validates MFA
Unknowns: production secret rotation schedule (UNVERIFIED)
```

If the agent cannot inspect a component, list it as out of scope or `UNVERIFIED`. Do not infer
that a control exists because it usually exists in similar projects.

## Phase 1: Risk identification

For each entry point and data flow, ask:

1. What can the attacker control? Body, query, path, headers, cookies, filenames, URLs,
   message payloads, environment, uploaded content, tenant identifiers.
2. What is the worst outcome? Data disclosure, modification, deletion, privilege escalation,
   account takeover, remote code execution, fraud, denial of service.
3. Where does trust change? Browser to API, API to database, API to OS, service to service,
   CI to registry, developer to production.
4. What is the existing control? Authentication, authorization, validation, encoding,
   parameterization, sandboxing, rate limit, audit log.
5. What evidence would prove the control works?

Risk ranking can be qualitative:

- **Critical**: unauthenticated remote code execution, authentication bypass, mass data access.
- **High**: authorization bypass, SQL injection, command injection, secret exposure with reach.
- **Medium**: stored XSS in an admin view, missing rate limit on sensitive action.
- **Low**: verbose error detail without sensitive data, missing defense-in-depth header.

Record assumptions explicitly. A wrong assumption is a finding waiting to happen.

## Phase 2: Requirements and threat model

Write requirements that a test can verify. Examples:

```text
REQ-INJ-001: Order search uses a parameterized SQLite command. Evidence: SqliteParameter usage.
REQ-AUTHN-001: The API registers authentication and invokes UseAuthentication before endpoints.
REQ-AUTHZ-001: Every POST/PUT/PATCH/DELETE endpoint requires an authenticated principal unless
              explicitly documented as public.
REQ-AUTHZ-002: Reading or mutating an order requires owner or administrator authorization.
REQ-SEC-001: No credential value is present in tracked source or configuration.
REQ-VAL-001: Invalid order quantities are rejected before persistence.
```

For each requirement, capture:

- Control category and requirement ID.
- Trust boundary.
- Threat and abuse case.
- Verification method: static inspection, unit test, integration test, gate rule, manual review.
- Evidence location.
- Owner and status.

Use `assets/security-requirements-template.md`.

Threat modeling does not need a full formal method. See `threat-modeling.md` for a lightweight
STRIDE-based approach that fits a coding session.

## Phase 3: Implementation

Order of preference:

1. Use a framework primitive that is already reviewed.
2. Use a well-maintained library for cryptography, token validation, and password hashing.
3. Write small, testable code with a single trusted enforcement point.
4. Avoid custom parsers, custom crypto, string-built queries, and string-built shell commands.

Implementation checklist:

- Validate at the server boundary and again at the domain boundary if the domain is reused.
- Use allowlists for enumerated values and ranges for numeric values.
- Reject unknown fields where mass assignment is a risk.
- Authenticate before authorizing. Authorize every object access, not only the route.
- Deny by default. Require an explicit policy for protected resources.
- Load secrets from a provider. Never commit values, even in tests or examples.
- Parameterize queries. Use ORM query composition, not concatenation.
- Execute processes with an argument vector and a fixed executable.
- Add negative tests: unauthenticated, wrong user, invalid input, injection payload.
- Log security decisions without logging secrets or full tokens.

## Phase 4: Review

Review in two passes.

### Pass A: Change-focused

- What new input reaches what sink?
- What new identity or permission decision was added?
- What new secret or configuration was added?
- What new dependency or external call was added?
- What error path leaks data or fails open?

### Pass B: Control-focused

Use `checklists.md`. For each baseline control, record `PASS`, `FAIL`, `UNVERIFIED`, or
`NOT_APPLICABLE` with evidence. Do not accept "the framework handles it" without identifying
the framework mechanism and where it is enabled.

Review the negative path:

- Missing authentication header.
- Authenticated but unauthorized user.
- Invalid and boundary input.
- Injection metacharacters.
- Missing or malformed secret.
- Database or downstream failure.

## Phase 5: Verification

Run tests and the gate. Verification hierarchy:

1. **Executed test evidence** — strongest for behavior.
2. **Deterministic static evidence** — strong for configuration and sink analysis.
3. **Code inspection by a human or agent** — useful but weaker.
4. **Assertion without evidence** — not evidence.

Gate usage:

```bash
# Static scan; exit 0 PASS, 1 FAIL, 2 UNVERIFIED when configured, 3 error
python skill/secureflow/scripts/secureflow-gate.py scan --root . --profile csharp-aspnetcore

# Write JSON and Markdown reports
python skill/secureflow/scripts/secureflow-gate.py scan --root . \
  --profile csharp-aspnetcore \
  --report artifacts/secureflow-report.json \
  --markdown artifacts/secureflow-report.md

# Audit agent claims; claims cannot improve the gate result
python skill/secureflow/scripts/secureflow-gate.py scan --root . \
  --profile csharp-aspnetcore \
  --claims secureflow-claims.json \
  --report artifacts/secureflow-report.json

# Verify report integrity later
python skill/secureflow/scripts/secureflow-gate.py verify-report \
  --report artifacts/secureflow-report.json --root .

# Optional compile check (executes the .NET SDK, not the application)
python skill/secureflow/scripts/secureflow-gate.py scan --root . \
  --profile csharp-aspnetcore --build
```

Resolve results:

- `FAIL`: fix the code or add a time-bound policy suppression with a reason. Suppressions are
  audited and never remove the finding from the report.
- `UNVERIFIED`: add evidence or document why verification is not possible.
- `NOT_APPLICABLE`: confirm the surface is genuinely absent. Do not use it to avoid work.
- `PASS`: retain the evidence in the report.

## Phase 6: Reporting and handoff

A report must answer:

- What was in scope?
- Which controls were verified, and with what evidence?
- Which controls failed, and what is the impact?
- Which controls are unverified, and what is the residual risk?
- What changed as a result?
- What remains before release?

Use precise language:

- Say "authorization for mutating endpoints is enforced by `[Authorize]` on the controller and
  verified at lines 12–48", not "authorization is implemented".
- Say "SQL injection sink at OrdersController.cs:57 uses string concatenation; parameterization
  is absent", not "the app may have SQL injection".
- Say "the gate did not evaluate object-level authorization; residual risk remains", not "all
  authorization is secure".

## Scaling the workflow

| Change | Minimum workflow |
| --- | --- |
| Copy edit, comment, documentation | No security phase; do not claim security |
| UI-only change with no data/identity | Phase 1 and 4 light review |
| New read endpoint | Phases 1, 2, 3, 4, 5 |
| New write endpoint | All phases; authorization and input tests |
| Auth, permissions, secrets, SQL, OS command | All phases; gate plus manual object-level review |
| Release or security sign-off | All phases; gate report, limitations, residual risk |

## Anti-patterns

- Writing a threat model after implementation to justify the code.
- Treating a passing build as security evidence.
- Treating a scanner's silence as proof of security.
- Suppressing a finding without owner, reason, and expiry.
- Adding `[AllowAnonymous]` to make an authorization check pass.
- Disabling certificate validation or HTTPS metadata checks to make tests pass.
- Storing a secret in a test fixture because "it is only a test".
- Reporting `PASS` for a control that was not inspected.
