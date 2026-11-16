# Evidence-Based Reporting

A SecureFlow report is an argument backed by inspectable evidence. It must distinguish what was
verified from what was assumed, what failed, and what remains unknown.

## Required sections

1. **Scope and revision** — repository, commit or tree hash, profile, date, exclusions.
2. **Summary** — overall status and counts for `PASS`, `FAIL`, `UNVERIFIED`, `NOT_APPLICABLE`.
3. **Controls** — one subsection per control with status, reason, and evidence.
4. **Findings** — failures with location, impact, remediation, and CWE/ASVS/OWASP mapping.
5. **Unverified items** — what could not be established and why.
6. **Suppressed findings** — accepted risk with owner, reason, expiry.
7. **Claims audit** — agent claims compared with independent results.
8. **Adapters** — build result if requested.
9. **Limitations** — what the method does not cover.
10. **Residual risk and next actions** — owner and priority.

## Status language

Use the exact statuses:

- `PASS` — verified with positive evidence.
- `FAIL` — evidence of a missing or broken control.
- `UNVERIFIED` — insufficient evidence; not a pass.
- `NOT_APPLICABLE` — no applicable surface.

Avoid:

- "Secure" as an unqualified conclusion.
- "No vulnerabilities" based on a static scan.
- "Should be safe", "looks good", "probably protected".
- Treating a passing build as a security pass.

Prefer:

- "Function-level authorization for mutating endpoints is `PASS`: all three POST/PUT endpoints
  inherit `[Authorize]` from `OrdersController` (`src/OrdersController.cs:12`)."
- "Object-level authorization is `UNVERIFIED`: the controller authorizes the route, but the
  repository query does not show an owner filter. Residual risk: IDOR/BOLA."
- "SQL injection prevention is `FAIL`: `src/OrdersController.cs:57` concatenates `customerId`
  into `SqliteCommand.CommandText`; no parameter is used."

## Evidence format

Every finding and positive check should include:

```json
{
  "path": "src/OrdersController.cs",
  "line": 57,
  "column": 16,
  "snippet": "command.CommandText = \"SELECT ... '\" + customerId + \"'\";",
  "snippet_sha256": "...",
  "rule_id": "SF-INJ-001",
  "control": "injection-prevention",
  "severity": "high",
  "confidence": "high",
  "cwe": ["CWE-89"],
  "asvs": ["V1.2.4"],
  "owasp": ["A05:2025"],
  "remediation": "Use a parameterized command and bind customerId as a parameter."
}
```

Paths are relative to the scanned root and use forward slashes in the report. Lines are 1-based.
Snippets are the original line trimmed, except secret values, which are masked.

## Severity and confidence

Severity describes impact if the finding is real:

- **Critical**: unauthenticated code execution, auth bypass, mass data compromise.
- **High**: SQL/command injection, broken object authorization, high-impact secret exposure.
- **Medium**: limited disclosure, missing hardening with a plausible path.
- **Low**: defense-in-depth gap, low-impact misconfiguration.
- **Info**: observation without a demonstrated security impact.

Confidence describes the static evidence:

- **High**: direct sink or configuration, unambiguous.
- **Medium**: framework-dependent or partially resolved.
- **Low**: heuristic or requires runtime confirmation.

Do not inflate confidence to make a report look stronger. `UNVERIFIED` is an honest result.

## Claims audit wording

| Gate | Claim | Wording |
| --- | --- | --- |
| `FAIL` | `PASS` | "Claim contradicted: gate found a failing control at ...; the claim is overstated." |
| `UNVERIFIED` | `PASS` | "Claim is not supported by evidence; the gate remains `UNVERIFIED`." |
| `PASS` | `FAIL` | "Claim is more pessimistic than the gate; the gate remains `PASS`, discrepancy recorded." |
| `PASS` | `PASS` | "Claim confirmed by independent evidence." |

Claims never change the gate result. They are an audit trail of what the agent asserted.

## Manual review section

The gate cannot prove everything. Add a manual review section for:

- Object-level authorization and tenant isolation.
- Business logic abuse.
- Authentication flows, MFA, recovery, and session lifecycle.
- Cryptographic design.
- File upload and path handling.
- Deserialization and template injection.
- Dependency and supply-chain risk.
- Logging, monitoring, and incident response.

Mark each as `PASS`, `FAIL`, `UNVERIFIED`, or `NOT_APPLICABLE` with evidence. A manual `PASS`
needs a path/line or an executed test, just like a gate check.

## Residual risk statement

Example:

```text
Residual risk:
- Data-level authorization is UNVERIFIED. The route requires authentication, but object
  ownership is not proven by the gate. Manual test: user A requesting user B's order returns 404.
- Secret rotation is outside the repository and was not inspected.
- Dependency vulnerability scanning was not performed.
- The scan covered src/Api and src/Domain only; infrastructure configuration is out of scope.
```

## Final conclusion template

```markdown
## Conclusion

Overall gate status: FAIL (2 controls failed, 1 unverified, 2 passed).

Verified:
- Input validation: PASS — ...
- Injection prevention: PASS — ...

Failed:
- Authorization: FAIL — ...
- Secrets management: FAIL — ...

Unverified:
- Authentication: UNVERIFIED — ...

This report does not establish that the application is secure. It establishes the status of the
five baseline controls for the scanned revision, with the evidence above. The residual risks in
the manual review section remain open.
```

## Machine-readable output

The JSON report is the source of truth. The Markdown report is a rendering of it. Do not edit one
without regenerating the other. Keep both under the same revision. Use `verify-report` before
relying on an older report.
