# Security Review Checklists

Use these checklists during Phase 4 and as a manual supplement to the gate. Each item should be
marked `PASS`, `FAIL`, `UNVERIFIED`, or `NOT_APPLICABLE` with evidence.

## Universal pre-implementation

- [ ] Assets and sensitive data are identified.
- [ ] Trust boundaries and attacker-controlled inputs are listed.
- [ ] Threats and abuse cases are recorded.
- [ ] Security requirements are testable and mapped to controls.
- [ ] Assumptions and out-of-scope components are explicit.
- [ ] The framework and libraries are supported versions.

## Input validation

- [ ] Validation runs on the server at a trusted layer.
- [ ] Types, lengths, ranges, formats, and allowed values are constrained.
- [ ] Unknown fields are rejected or ignored safely where mass assignment matters.
- [ ] Validation failure returns an error and stops processing.
- [ ] Automatic validation is not globally suppressed.
- [ ] Validation attributes are backed by an active validation mechanism.
- [ ] File uploads validate size, type, content, and storage path.
- [ ] Business rules and cross-field constraints are checked.
- [ ] Negative tests cover missing, malformed, boundary, and oversized input.

## Authentication

- [ ] Authentication middleware is registered and invoked.
- [ ] Cookie settings are `HttpOnly`, `Secure`, and `SameSite` appropriate.
- [ ] Tokens validate signature, issuer, audience, and lifetime.
- [ ] HTTPS metadata is required.
- [ ] No default or hardcoded credentials.
- [ ] Password storage uses a modern password hash (Argon2id, scrypt, bcrypt, or PBKDF2 with
      appropriate parameters).
- [ ] Login responses do not reveal whether an account exists.
- [ ] Brute-force and credential-stuffing controls exist.
- [ ] MFA is available or enforced for high-risk accounts.
- [ ] Session rotation and logout invalidation are implemented.
- [ ] Authentication failures are logged without credentials.

## Authorization

- [ ] Every mutating endpoint requires authentication or an explicit public decision.
- [ ] A fallback policy or global filter denies by default.
- [ ] Every object read and write enforces ownership, tenant, or policy.
- [ ] Admin functions require administrative permission.
- [ ] Roles and permissions are derived from trusted server-side data.
- [ ] Tenant identifiers are not trusted from the request body or query.
- [ ] Unauthorized object access returns a non-enumerating response.
- [ ] Authorization is enforced in the service or data layer, not only the route.
- [ ] Tests cover anonymous, wrong user, wrong tenant, and wrong role.
- [ ] `[AllowAnonymous]` usages are reviewed and documented.

## Secrets management

- [ ] No credentials, keys, tokens, or private keys in source or configuration.
- [ ] No credentials in tests, fixtures, examples, scripts, or CI files.
- [ ] Secrets come from a vault, environment, or user-secrets for local development.
- [ ] Example configuration contains empty placeholders, not realistic values.
- [ ] Secrets are not logged, returned in errors, or placed in URLs.
- [ ] Secret access follows least privilege.
- [ ] Rotation and ownership are documented.
- [ ] Repository history is checked for previously committed secrets.
- [ ] Found secrets are rotated, not only deleted from the current revision.

## Injection prevention

- [ ] SQL uses parameters, ORM composition, or safe stored procedures.
- [ ] Raw SQL is used only when necessary and is parameterized.
- [ ] Dynamic identifiers use an allowlist.
- [ ] Dapper calls use parameter objects.
- [ ] OS commands use a fixed executable and `ArgumentList`.
- [ ] Shell invocation is avoided.
- [ ] File paths are canonicalized and confined to an allowed root.
- [ ] Template engines, LDAP, XPath, and regex inputs are escaped or parameterized.
- [ ] Output is encoded for its context (HTML, attribute, URL, JavaScript, CSS).
- [ ] Tests include SQL and command-injection payloads.

## Security logging

- [ ] A logging infrastructure (`ILogger`, Serilog, NLog, etc.) is registered and injected.
- [ ] Authentication success, authentication failure, and authorization denials are logged.
- [ ] Administrative and data-mutating actions are logged with context.
- [ ] Logs do not contain passwords, tokens, session identifiers, or raw personal data.
- [ ] Event IDs or `LoggerMessage.Define` make security events easy to alert on.
- [ ] Log sinks, retention, and remote forwarding are configured.
- [ ] Time is synchronized (NTP) so event timelines are reliable.
- [ ] The gate's finding is `PASS` only when infrastructure and explicit security events are
      present; `UNVERIFIED` is acceptable while logs are being instrumented.

## Error handling and logging

- [ ] Production errors are generic to the client.
- [ ] Stack traces and SQL are not returned.
- [ ] Sensitive values are redacted from logs.
- [ ] Authentication, authorization, and admin actions are auditable.
- [ ] Failures do not fail open.
- [ ] Correlation IDs allow investigation without exposing internals.

## Configuration and transport

- [ ] HTTPS is enforced outside local development.
- [ ] HSTS is enabled for production web apps.
- [ ] CORS is restricted and does not combine wildcard origins with credentials.
- [ ] Antiforgery protection exists for cookie-authenticated state changes.
- [ ] Security headers are configured where applicable.
- [ ] Debug and developer exception pages are disabled in production.
- [ ] Request limits and timeouts are configured.
- [ ] Default accounts and sample endpoints are removed.
- [ ] Dependencies are pinned and monitored.

## Release gate

- [ ] Gate report generated for the release revision.
- [ ] No unsuppressed `FAIL`.
- [ ] Every `UNVERIFIED` is resolved or disclosed as residual risk.
- [ ] Suppressions have owner, reason, and expiry.
- [ ] Security tests were executed and their output retained.
- [ ] The report's file inventory matches the revision being released.
- [ ] A human reviewed high-risk findings, object-level authorization, and architecture.
- [ ] The report does not claim the application is secure beyond the verified controls.

## Evidence quality

Good evidence:

```text
src/OrdersController.cs:14  [Authorize]
src/Program.cs:23           app.UseAuthentication();
src/Program.cs:24           app.UseAuthorization();
tests/OrdersTests.cs:88     unauthenticated POST returns 401 (executed)
```

Weak evidence:

```text
"The controller is probably protected."
"ASP.NET Core handles SQL injection."
"The scanner found nothing."
"The code looks safe."
```

Weak evidence maps to `UNVERIFIED`, not `PASS`.
