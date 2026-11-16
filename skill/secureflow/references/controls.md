# Baseline Security Controls

This reference defines the five controls verified by SecureFlow Gate 0.1 for C# and ASP.NET
Core. Each control has requirements, positive evidence, common failures, and the exact static
checks implemented by the gate. Static checks are evidence, not a complete security proof.

Mappings use:

- OWASP ASVS 5.0 (published 30 May 2025).
- OWASP Top 10:2025.
- CWE Top 25 2025.
- NIST SP 800-218 SSDF v1.1.

## 1. Input validation

**Goal:** untrusted input is constrained to expected structure, type, range, length, and allowed
values at a trusted layer before it influences business logic or sinks.

Requirements:

- `REQ-VAL-001`: Server-side validation exists for externally supplied data.
- `REQ-VAL-002`: Validation failure is rejected, not ignored.
- `REQ-VAL-003`: Validation is not disabled globally or bypassed by mass assignment.
- `REQ-VAL-004`: Validation rules express business limits (length, range, format, allowlist).

Positive evidence:

- ASP.NET Core `[ApiController]` with automatic model-state validation enabled.
- `ModelState.IsValid` checked before use.
- FluentValidation validators registered and executed.
- Data annotation attributes combined with an active validation mechanism.
- Manual validation with explicit rejection and no suppression.

Negative evidence / failures:

- `SuppressModelStateInvalidFilter = true` with no manual validation.
- Validation attributes on a model that is never validated.
- Validation only in JavaScript or only in the browser.
- Catching validation errors and continuing with default or partial data.
- `[Bind]` / mass assignment allowing security-relevant properties.

Verification:

| ASVS 5.0 | OWASP Top 10:2025 | CWE | SSDF |
| --- | --- | --- | --- |
| V2.2.1, V2.2.2 | A06 Insecure Design, A05 Injection | CWE-20 | PW.5, PW.7 |

Gate checks:

- `SF-VAL-001` — automatic validation suppressed without manual validation (`FAIL`).
- Detection of `[ApiController]`, `ModelState.IsValid`, FluentValidation, and
  `Validator.TryValidateObject`.
- No endpoint surface: `NOT_APPLICABLE`.
- Endpoint surface without a verification mechanism: `UNVERIFIED`.

Limitations: the gate does not prove that every property has a correct rule, that business
limits are right, or that all paths call validation. It detects mechanism presence and a known
global bypass. Manual review is still required.

## 2. Authentication

**Goal:** identity is established with a secure mechanism, middleware is active, and session or
token settings resist theft and tampering.

Requirements:

- `REQ-AUTHN-001`: Authentication services are registered and the authentication middleware is
  invoked before authorization and endpoints.
- `REQ-AUTHN-002`: Cookies are `HttpOnly`, `Secure`, and use an appropriate `SameSite` policy.
- `REQ-AUTHN-003`: Token validation requires HTTPS metadata and validates issuer, audience,
  lifetime, and signature.
- `REQ-AUTHN-004`: No default, demo, or hardcoded credentials.
- `REQ-AUTHN-005`: Failed authentication does not reveal whether an account exists.

Positive evidence:

- `AddAuthentication`, a scheme such as `AddCookie` / `AddJwtBearer` / `AddOpenIdConnect`, and
  `UseAuthentication`.
- Cookie options with `HttpOnly = true`, `SecurePolicy = Always` (or `SameAsRequest` behind
  enforced HTTPS), and `SameSite = Strict` or `Lax`.
- JWT bearer options with `RequireHttpsMetadata = true` (default) and explicit authority.

Negative evidence / failures:

- Authentication registered but `UseAuthentication` missing.
- Cookie `HttpOnly = false`.
- Cookie `SecurePolicy = None` in a production path.
- `RequireHttpsMetadata = false`.
- JWT validation with signature, issuer, audience, or lifetime checks disabled.
- Default admin/admin or demo credentials.
- Authentication implemented only in client code.

Verification:

| ASVS 5.0 | OWASP Top 10:2025 | CWE | SSDF |
| --- | --- | --- | --- |
| V6.3.1, V6.3.2, V6.3.8, V7 | A07 Authentication Failures | CWE-287, CWE-384, CWE-798 | PW.5, PW.9 |

Gate checks:

- `SF-AUTH-001` — authentication registered but middleware missing (`FAIL`).
- `SF-AUTH-003` — `HttpOnly = false` on cookie authentication (`FAIL`).
- `SF-AUTH-004` — `CookieSecurePolicy.None` (`FAIL`).
- `SF-AUTH-005` — `RequireHttpsMetadata = false` (`FAIL`).
- No authentication mechanism with endpoints present: `UNVERIFIED`.
- No endpoint or authentication surface: `NOT_APPLICABLE`.

Limitations: the gate does not verify identity provider configuration, password policy,
credential stuffing defenses, MFA, token revocation, or login logic. Those require tests and
manual review.

## 3. Authorization

**Goal:** every sensitive operation and object access requires explicit permission; default is
deny.

Requirements:

- `REQ-AUTHZ-001`: Every mutating endpoint (POST, PUT, PATCH, DELETE) requires authentication
  or an explicit, documented public decision.
- `REQ-AUTHZ-002`: Object access checks ownership, tenant, or policy, not just route access.
- `REQ-AUTHZ-003`: Administrative functions require administrative authorization.
- `REQ-AUTHZ-004`: Deny-by-default is configured for unmatched or newly added endpoints.
- `REQ-AUTHZ-005`: Authorization is enforced at the server, never only in the UI.

Positive evidence:

- `[Authorize]` on the controller or action.
- Fallback policy requiring an authenticated user.
- Global `AuthorizeFilter`.
- Minimal API `.RequireAuthorization()` or group-level authorization.
- Explicit policy checks in the service layer for object access.

Negative evidence / failures:

- Mutating endpoint without `[Authorize]`, fallback policy, or global filter.
- `[AllowAnonymous]` on a sensitive action without a documented reason.
- Route-level authorization with no object-level check (IDOR/BOLA).
- Trusting a client-supplied role, tenant, or user identifier.
- Authorization decisions based on UI visibility.

Verification:

| ASVS 5.0 | OWASP Top 10:2025 | CWE | SSDF |
| --- | --- | --- | --- |
| V8.2.1, V8.2.2, V8.3.1, V8.4.1 | A01 Broken Access Control | CWE-862, CWE-863, CWE-639 | PW.1, PW.5, PW.7 |

Gate checks:

- `SF-AUTHZ-001` — mutating endpoint with no route/class authorization and no fallback (`FAIL`).
- Explicit `[AllowAnonymous]` mutating endpoints are excluded from this static check and listed
  as a limitation; they still require manual review.
- GET-only surface with no mutating endpoints: `UNVERIFIED` because object-level authorization
  is not statically proven.
- No endpoints: `NOT_APPLICABLE`.

Limitations: the gate verifies function-level protection, not object-level authorization. An
endpoint with `[Authorize]` can still be vulnerable to IDOR. The report says so explicitly.

## 4. Secrets management

**Goal:** credentials, keys, and tokens are stored in a managed secret store, never in source,
configuration, build artifacts, logs, or reports.

Requirements:

- `REQ-SEC-001`: No hardcoded password, API key, token, private key, or connection-string
  credential in tracked files.
- `REQ-SEC-002`: Secrets are loaded from a secret provider, environment, user-secrets for local
  development, or a managed vault.
- `REQ-SEC-003`: Secret values are redacted from logs, errors, and reports.
- `REQ-SEC-004`: Secrets have an owner, rotation process, and least-privilege access.

Positive evidence:

- `IConfiguration` / `builder.Configuration` binding to a value supplied outside source.
- `Environment.GetEnvironmentVariable`.
- `AddUserSecrets` for local development only.
- Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, or equivalent.
- Empty placeholders in example configuration with deployment-time injection.

Negative evidence / failures:

- Literal passwords, API keys, bearer tokens, or private keys.
- Connection strings with `Password=` or `Pwd=`.
- Known token formats such as AWS access key IDs, GitHub tokens, or Stripe live keys.
- Secrets in test fixtures, CI files, Dockerfiles, or committed `.env` files.
- Secrets written to logs or returned in errors.

Verification:

| ASVS 5.0 | OWASP Top 10:2025 | CWE | SSDF |
| --- | --- | --- | --- |
| V13.3.1, V13.3.2 | A02 Security Misconfiguration, A04 Cryptographic Failures | CWE-798, CWE-259, CWE-321 | PS.1, PW.9 |

Gate checks:

- `SF-SEC-001` — hardcoded credential assignment (`FAIL`).
- `SF-SEC-002` — PEM private key (`FAIL`).
- `SF-SEC-003` — recognizable access token (`FAIL`).
- `SF-SEC-004` — connection string credential (`FAIL`).
- Secret values are masked in snippets; the report never contains the raw value.
- Sensitive surface present but no secret provider: `UNVERIFIED`.
- No sensitive surface: `NOT_APPLICABLE`.

Limitations: pattern matching cannot detect every secret shape, encoded secrets, secrets in
history, secrets in external systems, or weak secret management process. Rotate any exposed
credential; removing it from the current revision is not enough.

## 5. Injection prevention

**Goal:** untrusted data cannot change the structure of a database query, OS command, or other
interpreter.

Requirements:

- `REQ-INJ-001`: SQL and database queries use parameters, ORM composition, or safe stored
  procedures.
- `REQ-INJ-002`: OS processes use a fixed executable and an argument vector; shell
  interpretation is avoided.
- `REQ-INJ-003`: Dynamic SQL built from identifiers uses an allowlist, not concatenation.
- `REQ-INJ-004`: No user input reaches `Process.Start`, shell strings, or raw SQL text.

Positive evidence:

- `FromSqlInterpolated` / `ExecuteSqlInterpolated`.
- `SqlParameter`, `SqliteParameter`, `Parameters.Add`, `AddWithValue`.
- Dapper parameter objects or anonymous parameter types.
- `ProcessStartInfo.ArgumentList.Add` with a constant `FileName`.
- Fixed command and validated enumerated arguments.

Negative evidence / failures:

- `FromSqlRaw` / `ExecuteSqlRaw` with interpolation or concatenation.
- `new SqlCommand("..." + input)` or `new SqliteCommand($"...")`.
- Dapper query strings built with interpolation or concatenation.
- `Process.Start("cmd.exe", "/c " + input)`.
- `ProcessStartInfo.Arguments = $"..."` or concatenated arguments.
- Shell invocation with untrusted input, even if "escaped" manually.

Verification:

| ASVS 5.0 | OWASP Top 10:2025 | CWE | SSDF |
| --- | --- | --- | --- |
| V1.2.4, V1.2.5 | A05 Injection | CWE-89, CWE-78, CWE-77 | PW.5, PW.7, PW.8 |

Gate checks:

- SQL sink analysis for raw SQL, `SqlCommand`, `SqliteCommand`, and Dapper.
- OS command analysis for `Process.Start` and `ProcessStartInfo`.
- Safe parameterization or `ArgumentList` evidence downgrades a candidate to `PASS` only when
  the evidence is in the same statement or process configuration.
- Dynamic sink without mitigation: `FAIL`.
- Unresolved dynamic query variable: `UNVERIFIED` review.
- No sink: `NOT_APPLICABLE`.

Limitations: static matching does not prove exploitability. It can miss reflection, dynamic
dispatch, custom data access layers, stored procedure bodies, and framework-specific APIs. It is
intentionally conservative: an unresolved case becomes `UNVERIFIED`, not `PASS`.

## Control status aggregation

```text
if any unsuppressed finding for control:       FAIL
else if no applicable surface:                 NOT_APPLICABLE
else if any required check is UNVERIFIED:      UNVERIFIED
else:                                          PASS
```

Suppressed findings remain visible in the report and are counted. A suppression never deletes
evidence.

## NIST SSDF mapping summary

| SSDF practice | SecureFlow phase |
| --- | --- |
| PW.1 Design software to meet security requirements | Phases 1–2 |
| PW.2 Review the software design | Phase 2 |
| PW.4 Reuse secure components | Phase 3 |
| PW.5 Create source code securely | Phase 3 |
| PW.6 Configure build to be secure | Phase 5 |
| PW.7 Review and analyze code | Phase 4–5 |
| PW.8 Test executable code | Phase 5 |
| PW.9 Configure software with secure defaults | Phase 3–5 |

SecureFlow does not implement organizational practices from the PO, PS, and RV groups. See the
SSDF for those.
