# Testing SecureFlow

This document describes how the project is tested, what the tests actually verify, and what
remains unverified. The test suite uses only the Python standard library.

## Requirements

- Python 3.9 or newer. The local release validation used Python 3.12.10 on Windows.
- .NET SDK 10.0 or newer for the build and runtime checks of the examples.
- Git or a source archive. No network access is required for the unit tests.

## Run the full suite

From the repository root:

```bash
python -m unittest discover -s tests -v
```

Expected final lines:

```text
Ran 157 tests in <time>

OK
```

The run time depends on the machine. On the release validation machine it was approximately
15 seconds.

## Run the gate smoke test

```bash
python tests/ci_gate_smoke.py
```

Expected output:

```text
CI gate smoke test passed.
```

The smoke test:

1. scans the secure example and requires exit code `0`;
2. scans the vulnerable example and requires exit code `1`;
3. writes a report, verifies it, and requires the verification to succeed.

This is the command used by the GitHub Actions matrix.

## Test inventory

| File | Tests | What it covers |
| --- | --- | --- |
| `tests/test_skill_structure.py` | 7 | Frontmatter contract, name/directory match, description and compatibility limits, `SKILL.md` size, required references/assets/scripts, UTF-8 Markdown, relative links, JSON assets. |
| `tests/test_rulepacks.py` | 8 | Control IDs, unique rule IDs, required metadata, rule counts per control, `explain` output, secret token shapes, placeholder allowlist, status parsing. |
| `tests/test_csharp.py` | 11 | Comment/string masking, controller and action attributes, `[AllowAnonymous]`, comments cannot spoof authorization, fallback policy, minimal APIs with block lambdas, default parameter values, unregistered `AuthorizeFilter` rejection, auth configuration, custom schemes, insecure cookie flags. |
| `tests/test_engine.py` | 18 | `NOT_APPLICABLE` and `UNVERIFIED` fixtures, SQL and command injection positives and negatives, EF interpolated queries, shell `ArgumentList` risk, `ProcessStartInfo` variable analysis, secret redaction, placeholder allowlist, authentication scheme coverage, secure example all `PASS`, vulnerable example all `FAIL`, report source tampering, added file detection, report hash tampering, Markdown rendering, optional build-control alignment. |
| `tests/test_claims.py` | 7 | Valid claims confirmed, wrong snippet rejected, path escape rejected, overstated and understated contradictions, claims cannot upgrade a status, missing evidence rejected, schema required. |
| `tests/test_policy.py` | 4 | Active suppression moves findings to the audit list, expired suppression ignored, missing reason ignored, `UNVERIFIED` cannot be upgraded. |
| `tests/test_cli.py` | 13 | `version`, `explain`, secure scan exit `0`, vulnerable scan exit `1`, `UNVERIFIED` exit `2` with `--fail-on unverified` and exit `0` by default, missing command and invalid root exit `3`, report round-trip, tampered report exit `4`, `init-policy` overwrite behavior, launcher portability. |
| `tests/test_report.py` | 10 | Required report fields, deterministic hashes, hash changes after material changes, canonical JSON, written report verification, Markdown sections, schema enum, no Unicode replacement characters, path traversal rejection, inventory hash tampering. |
| `tests/test_python_compat.py` | 3 | Python 3.9 syntax via `ast.parse(feature_version=(3, 9))`, no third-party imports, launcher has no shell or network calls. |
| `tests/test_installer.py` | 7 | OpenCode project installation, all-agent destinations, user scope with `SECUREFLOW_HOME`, overwrite refusal and `--force`, dry-run, missing project directory, source tree unchanged. |
| `tests/test_firewall.py` | 51 | pfSense XML parsing, firewall control statuses, permissive rule detection with WAN/internal context classification, NAT exposure, segmentation including WiFi/guest isolation, logging/NTP across legacy and pfSense 24.0 layouts, admin exposure, IPv4/IPv6 rule distinction, VPN tunnel presence, evidence line accuracy against the real export, secret redaction in reports, report integrity, plan and apply modes, backup and rollback. |
| `tests/test_detections.py` | 13 | MITRE technique validation, mapping load, telemetry source filtering, Sigma rule generation, YAML/JSON serialization, coverage ledger. |
| `tests/test_incident.py` | 3 | `init-incident` copies templates, refuses overwrite, and honors `--force`. |
| `tests/test_wazuh_adapter.py` | 2 | Wazuh adapter converts YAML and JSON Sigma rules into Wazuh XML alert stubs. |
| **Total** | **157** | |

## What the tests prove

- The skill has valid, portable Agent Skills metadata and its referenced files exist.
- Rule packs are structurally valid and every rule has actionable remediation and standards
  mappings.
- The gate produces all four statuses in the expected situations.
- Positive and negative cases exist for SQL injection, OS command injection, hardcoded secrets,
  input validation suppression, authentication middleware, cookie flags, endpoint
  authorization, firewall rule permissiveness, NAT exposure, and security logging.
- Firewall evidence lines point at the exact XML element that triggered the finding (verified
  against the real pfSense 24.0 export), and report snippets never contain credentials, password
  hashes, or private keys.
- Claims cannot raise a control status, and invalid evidence is rejected.
- Policy suppressions are time-bounded, audited, and cannot upgrade `UNVERIFIED`.
- Reports are deterministic for unchanged content and detect file, inventory, and report-hash
  tampering.
- Detection Engineering: MITRE mappings are validated, Sigma rules are generated only when a
  telemetry source is available, and the coverage ledger lists uncovered controls.
- CLI exit codes match the documented contract.
- The installer writes only to documented destinations and does not modify the source skill.
- Both reference applications produce the expected gate outcome.

## Manual validation performed for the release candidate

Commands were run on Windows with Python 3.12.10 and .NET SDK 10.0.404.

### 1. Full suite

```text
Ran 157 tests in 12.946s

OK
```

### 2. Smoke test

```text
CI gate smoke test passed.
```

### 3. Secure example

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-secure/SecureOrders.Api \
  --report secure-report.json \
  --markdown secure-report.md
```

Actual result: overall `PASS`, six controls `PASS` (input-validation, authentication, authorization, injection-prevention, secrets-management, security-logging), exit `0`.

### 4. Vulnerable example

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-vulnerable/VulnerableOrders.Api
```

Actual result: overall `FAIL`, five baseline controls `FAIL` (input-validation, authentication,
authorization, injection-prevention, secrets-management), `security-logging` `UNVERIFIED`, exit
`1`. The report contained findings for `SF-VAL-001`, `SF-AUTH-001`, `SF-AUTH-003`, `SF-AUTH-004`,
`SF-AUTHZ-001`, `SF-INJ-001`, `SF-INJ-002`, `SF-SEC-001`, `SF-SEC-004`, `SF-LOG-001`, and
`SF-LOG-002`.

### 5. Builds

```bash
dotnet build examples/csharp-secure/SecureOrders.Api/SecureOrders.Api.csproj --nologo
dotnet build examples/csharp-vulnerable/VulnerableOrders.Api/VulnerableOrders.Api.csproj --nologo
```

Actual result: both builds succeeded with zero warnings and zero errors after updating
`Microsoft.Data.Sqlite` to `11.0.0`.

### 6. Dependency check

```bash
dotnet list examples/csharp-secure/SecureOrders.Api/SecureOrders.Api.csproj package \
  --vulnerable --include-transitive
```

Actual result: no known vulnerable packages.

### 7. Packaging

```bash
python -m venv <temporary-venv>
<temporary-venv>/Scripts/python -m pip install .
<temporary-venv>/Scripts/secureflow-gate version
```

Actual result: `secureflow-gate 0.2.1`; scanning the secure example through the installed console
script returned exit `0`.

### 8. Installation
The installer is covered by automated tests for all five agents, project and user scope,
overwrite protection, dry-run, and source immutability. A manual clean-directory installation was
also checked:

```bash
python integrations/install.py --agent opencode --scope project --project-dir <temporary-project>
```

Expected and observed: `.opencode/skills/secureflow/SKILL.md` exists, the marker file exists, and
the installed gate reports its version.

### 9. Build adapter

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-secure/SecureOrders.Api \
  --build \
  --report secure-build-report.json
```

Observed after the control-alignment fix: overall `PASS`, `build-integrity` `PASS` with reason
`dotnet build target: SecureOrders.Api.csproj; exit: 0`, and report verification succeeds. The
adapter runs `dotnet build --nologo` with no shell and is not a sandbox.

### 10. Report schema

The Draft 2020-12 schema and both final JSON reports were validated with `jsonschema` installed
only in an isolated temporary virtual environment. Secure and vulnerable reports both passed
schema validation. `jsonschema` is a validation-only tool, not a SecureFlow runtime dependency.

### 11. Firewall audit / plan / apply

```bash
python skill/secureflow/scripts/secureflow-gate.py audit-firewall \
  --config tests/fixtures/firewall/pfsense-vulnerable.xml \
  --report fw-report.json --markdown fw-report.md
```

Observed: overall `FAIL`, eight controls evaluated, multiple findings such as `FW-ADMIN-001`
(admin web GUI on HTTP), `FW-RULE-001` (any/any permit), and `FW-NAT-001` (port forward to
admin port).

```bash
python skill/secureflow/scripts/secureflow-gate.py plan-firewall \
  --config tests/fixtures/firewall/pfsense-vulnerable.xml \
  --changes fw-changes.json
```

Observed: a `secureflow.firewall.changes/v1` JSON plan with backup path, proposed XML changes,
and rollback instructions.

```bash
python skill/secureflow/scripts/secureflow-gate.py apply-firewall \
  --config tests/fixtures/firewall/pfsense-vulnerable.xml \
  --output fw-applied.xml --plan fw-changes.json --confirm
```

Observed: original file backed up, modified XML written, post-apply audit generated. This is the
only command that writes to the configuration file and it requires `--confirm`.

### 12. Detection Engineering (Sigma)

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-vulnerable/VulnerableOrders.Api \
  --sigma-out sigma-rules --sigma-format yml
```

Observed: Sigma rules generated only for findings with a MITRE technique and a telemetry source;
each rule includes `status: experimental`, tags, references to the source file/line, and
falsepositives. The JSON report includes a `detections` section with covered/uncovered controls.

```bash
python skill/secureflow/scripts/secureflow-gate.py generate-sigma \
  --report gate-report.json --out sigma-from-report --format yml
```

Observed: Sigma rules regenerated from a saved report.

### 13. Incident response templates

```bash
python skill/secureflow/scripts/secureflow-gate.py init-incident --output incident-2026-11-22
```

Observed: directory created with `incident-response-template.md`, `ioc-template.md`, and
`timeline-template.md`.

## Runtime smoke checks for the secure example

```bash
dotnet run --project examples/csharp-secure/SecureOrders.Api --urls http://localhost:5080
```

From another terminal:

```bash
curl -i http://localhost:5080/health
curl -i http://localhost:5080/api/orders/1
```

Expected: `/health` returns `200`; `/api/orders/1` returns `401` without an authenticated cookie.
These checks validate the example's runtime behavior, not the gate's static result. The gate
itself does not make HTTP requests.

## Cross-platform coverage

The CI configuration runs the unit suite and smoke test on:

- Ubuntu and Windows;
- Python 3.9 and 3.12.

A separate Ubuntu job builds both examples with the .NET 10 SDK. The workflow is committed but
was not executed on GitHub during local release preparation. The local validation was Windows
only. The Python compatibility tests enforce 3.9 syntax and standard-library-only imports, but
they do not replace running on every platform.

## What is not tested

- Live discovery and invocation inside OpenCode, Claude Code, Codex, Cursor, or GitHub Copilot.
  Only installation layout, metadata, and file placement are tested.
- Full C# language coverage. The parser is a masked structural parser, not Roslyn.
- Object-level authorization semantics.
- Dependency vulnerability scanning, secret history scanning, DAST, penetration testing, cloud
  configuration, or runtime behavior.
- Report signing. Hashes are tamper-evident, not an authenticity signature.
- Firewall assessment against live pfSense devices; tests use fixtures only.
- Live SIEM deployment of generated Sigma or Wazuh rules; adapter output is a stub for review.
- Runtime validation that Sigma rules actually trigger on real telemetry.
- Performance and memory at very large repository scale.
- Fuzzing of the parsers and regexes.

## Adding tests

- Put shared helpers in `tests/support.py`.
- Use `temporary_project` or `tempfile.TemporaryDirectory`; never write into the repository.
- Assert both the control status and the expected rule IDs.
- Add a negative case that should not produce a finding.
- For every new status or exit code, update this document and `docs/usage.md`.
- Keep tests deterministic and offline.

## Troubleshooting

- `dotnet` not found: the unit suite does not require .NET; only the example build and `--build`
  adapter do.
- Permission errors during installation: use a writable project directory or `--dry-run` first.
- Report verification fails after editing the report: this is expected. Generate a new report
  instead of editing the JSON.
- A scan of documentation reports secret-like strings: the gate is scanning text, not
  understanding intent. Use a path-scoped policy suppression with a reason and expiry, or exclude
  documentation from the scan root.
