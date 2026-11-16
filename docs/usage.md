# Usage

## Start with the skill

Invoke `secureflow` through your agent before changing security-relevant code. The agent should:

1. Establish scope and assets.
2. Identify attacker-controlled input and trust boundaries.
3. Write testable requirements and a lightweight threat model.
4. Implement the controls.
5. Review the change against the checklists.
6. Run the gate and report evidence.

The complete instructions are in `skill/secureflow/SKILL.md` and its references.

## Gate commands

### Scan

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root . \
  --profile csharp-aspnetcore \
  --report secureflow-report.json \
  --markdown secureflow-report.md
```

Options:

| Option | Meaning |
| --- | --- |
| `--root PATH` | Repository or project to scan. Default `.`. |
| `--profile NAME` | Rule profile. Currently `csharp-aspnetcore` (default) and `base`. |
| `--report PATH` | Write machine-readable JSON. |
| `--markdown PATH` | Write human-readable Markdown. |
| `--claims PATH` | Audit agent claims. |
| `--policy PATH` | Apply time-bounded suppressions. |
| `--fail-on fail` | Exit `1` on `FAIL` (default). |
| `--fail-on unverified` | Exit `2` when the result is `UNVERIFIED` and there is no `FAIL`. |
| `--fail-on never` | Always exit `0` if the scan completes. |
| `--build` | Run the optional `dotnet build` adapter. |

The gate does not execute target code unless `--build` is explicitly set. `--build` compiles a
`.sln` or the shallowest `.csproj`; it is not a sandbox.

### Explain a rule

```bash
python skill/secureflow/scripts/secureflow-gate.py explain --rule SF-INJ-001
```

The command prints the rule metadata as JSON: control, severity, confidence, CWE, ASVS, OWASP,
message, and remediation.

### Verify a report

```bash
python skill/secureflow/scripts/secureflow-gate.py verify-report \
  --report secureflow-report.json
```

Verification fails with exit `4` if the report hash is invalid, a listed file changed or is
missing, or a new file appeared in the scanned root. Use `--root` only when the project moved
and you intentionally want to verify the same report against a new location.

### Initialize a policy

```bash
python skill/secureflow/scripts/secureflow-gate.py init-policy --output secureflow-policy.json
```

The generated policy has no suppressions. Add exceptions deliberately.

## Claims

Claims are optional. They are useful when an agent wants to state what it believes it
implemented. The gate validates the evidence and records whether the claim is confirmed or
contradicts the independent result.

```json
{
  "schema_version": "secureflow.claims/v1",
  "claims": [
    {
      "control": "authorization",
      "status": "PASS",
      "summary": "Orders require authentication and the controller has a class-level policy.",
      "evidence": [
        {
          "path": "Controllers/OrdersController.cs",
          "line": 9,
          "snippet": "[Authorize]",
          "sha256": "<optional SHA-256 of the trimmed snippet>"
        }
      ]
    }
  ]
}
```

Rules:

- `PASS` and `FAIL` claims require at least one evidence item.
- Paths must be relative to the scan root and cannot escape it.
- The trimmed snippet must match the line exactly.
- An optional `sha256` must match the trimmed snippet.
- A claim never upgrades a gate status.
- `PASS` against gate `FAIL` is `contradiction_overstated`.
- `FAIL` against gate `PASS` is `contradiction_understated`; the gate remains `PASS`.
- Invalid claims are rejected, not silently dropped.

Run with claims:

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root . \
  --claims secureflow-claims.json \
  --report secureflow-report.json
```

## Policy suppressions

A suppression is an audited, time-bounded exception. It cannot hide a finding from the report;
it moves the finding to `suppressed_findings` with its justification.

```json
{
  "schema_version": "secureflow.policy/v1",
  "suppressions": [
    {
      "rule_id": "SF-SEC-001",
      "path": "tests/Fixtures/FakeCredential.cs",
      "reason": "Synthetic credential used only by the negative-path test suite.",
      "owner": "security@example.invalid",
      "expires": "2027-12-31"
    }
  ]
}
```

- All four fields `rule_id`, `path`, `reason`, and `expires` are required.
- `path` may be an exact relative path or a supported glob.
- Expired and malformed suppressions are ignored and reported as warnings.
- Only `FAIL` checks whose rule IDs are fully suppressed can become `PASS`.
- An `UNVERIFIED` control cannot be upgraded by suppression.

## Reference examples

### Secure application

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-secure/SecureOrders.Api \
  --report secure-report.json \
  --markdown secure-report.md
```

Expected: all five controls `PASS`, overall `PASS`, exit `0`.

Build and run it:

```bash
dotnet build examples/csharp-secure/SecureOrders.Api/SecureOrders.Api.csproj
dotnet run --project examples/csharp-secure/SecureOrders.Api --urls http://localhost:5080
```

Smoke checks from another terminal:

```bash
curl -i http://localhost:5080/health          # 200
curl -i http://localhost:5080/api/orders/1    # 401 without an authenticated cookie
```

The secure example is a reference implementation, not a production template. It does not
include a production identity provider, database migration strategy, rate limiting, or
observability stack.

### Vulnerable application

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-vulnerable/VulnerableOrders.Api
```

Expected: all five controls `FAIL`, overall `FAIL`, exit `1`, with findings for input
validation, authentication, authorization, secrets, SQL injection, and OS command injection.

The vulnerable application is intentionally insecure. Do not deploy it, expose it to a network,
or reuse its code.

## Interpreting results

- **PASS** means the detected surface satisfied the configured checks. It does not prove the
  absence of vulnerabilities.
- **FAIL** means evidence of a missing or broken control was found. Fix it or document a
  time-bounded exception.
- **UNVERIFIED** means the gate could not decide. Do not describe the control as working.
- **NOT_APPLICABLE** means there was no applicable surface in the scanned scope.

Always report:

- the profile and files scanned
- the controls verified and their evidence
- contradictions between claims and the gate
- suppressed findings and their expiry
- residual risk and limitations
- anything that remains `UNVERIFIED`

## CI example

`integrations/github-actions/secureflow.yml` installs the skill into the user scope and runs the
gate with `--fail-on unverified`. It uploads the JSON and Markdown reports even when the gate
fails.

For a stricter pipeline, run `verify-report` as a separate step and store the report as an
artifact. The report hashes let reviewers confirm that the evidence was not changed after the
scan.
