# Lightweight Threat Modeling

Use this method for a feature, service, or change. It should take minutes for a small change and
a few hours for a new system. The output is a set of assets, trust boundaries, threats, and
testable requirements.

## 1. Define the system

Capture:

- Purpose and users.
- Components and data stores.
- Entry points.
- External dependencies.
- Identity and authorization model.
- Deployment and trust assumptions.

A simple diagram is enough:

```text
Browser --HTTPS--> API --SQL--> Database
                     |
                     +--HTTPS--> External payment service
                     |
                     +--process--> Local report generator
```

Mark every boundary where data or control crosses a trust level.

## 2. Identify assets

| Asset | Why it matters | Protection |
| --- | --- | --- |
| Customer orders | Privacy, business data | Authn, authz, TLS, retention |
| Session cookie | Account takeover | HttpOnly, Secure, SameSite, rotation |
| Database credentials | Full data access | Secret store, least privilege, rotation |
| Admin actions | Integrity, fraud | Strong auth, authorization, audit |
| Report files | Possible data disclosure | Path confinement, access control |

## 3. Identify actors and entry points

- Anonymous internet user.
- Authenticated customer.
- Administrator.
- Internal service or job.
- CI/CD pipeline.
- Malicious insider.
- Compromised dependency.

Entry points include HTTP routes, headers, cookies, file uploads, webhooks, queue messages,
scheduled jobs, configuration, environment variables, and command-line arguments.

## 4. Apply STRIDE

For each trust boundary and entry point:

| Threat | Question | Typical control |
| --- | --- | --- |
| Spoofing | Can someone pretend to be another user or service? | Strong authentication, token validation, mTLS |
| Tampering | Can data or code be modified in transit or at rest? | TLS, signatures, integrity checks, authorization |
| Repudiation | Can a sensitive action be denied later? | Security audit logs with identity and outcome |
| Information disclosure | Can data leak through responses, errors, logs, or timing? | Authorization, redaction, generic errors, TLS |
| Denial of service | Can a cheap request exhaust expensive resources? | Limits, quotas, timeouts, rate limiting |
| Elevation of privilege | Can a user gain permissions or execute code? | Deny-by-default authz, least privilege, parameterization, sandboxing |

Add abuse cases:

- Change an object ID in a request.
- Add an unexpected JSON field.
- Send SQL or shell metacharacters.
- Replay an old token or request.
- Upload a file with a misleading extension.
- Trigger an error to learn internals.
- Call an admin endpoint directly.
- Use a valid low-privilege account against another tenant.

## 5. Rank and select

Use likelihood and impact:

```text
Risk = plausible attack path x impact
```

Prioritize:

1. Unauthenticated paths to sensitive data or code execution.
2. Authenticated paths that cross tenant or ownership boundaries.
3. Secret exposure and weak credential handling.
4. Injection and unsafe deserialization.
5. Availability and abuse controls.

Not every theoretical threat needs a control in the first release. Record accepted risk.

## 6. Write requirements and tests

Each threat becomes one or more requirements:

```text
Threat: A customer changes orderId and reads another customer's order.
Requirement: REQ-AUTHZ-002 — order read requires owner or administrator.
Implementation: policy check in OrderService.GetForUser.
Test: user A requests user B's order, expects 404/403 and no body data.
Gate: mutating endpoints protected; object-level check remains manual/UNVERIFIED.
```

The gate cannot prove every object-level rule. That is why the report distinguishes verified
function-level protection from unverified data-level authorization.

## 7. Review triggers

Revisit the threat model when:

- A new entry point or data store is added.
- The identity or permission model changes.
- A new external integration or outbound request is added.
- File upload, import, export, or process execution is added.
- A secret or key management mechanism changes.
- A release changes the deployment boundary.

## Minimal template

Use `assets/threat-model-template.md`. Keep it in the repository next to the design document, or
in `docs/security/`. A threat model that nobody updates is documentation debt, not a control.

## Common mistakes

- Modeling only the happy path.
- Treating the browser as a trust boundary for authorization.
- Forgetting service-to-service and CI/CD boundaries.
- Listing threats without a requirement, test, or accepted-risk decision.
- Assuming the framework protects an operation without identifying the mechanism.
- Omitting residual risk from the final report.
