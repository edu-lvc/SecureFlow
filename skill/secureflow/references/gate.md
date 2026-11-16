# SecureFlow Gate

The gate is an independent, deterministic verifier. It inspects source and configuration, produces
evidence, and never trusts agent claims. It is intentionally narrower than a vulnerability
scanner: it verifies the five baseline controls for C# and ASP.NET Core and reports exactly what
it could and could not establish.

## Design goals

- **Deterministic:** sorted inputs, sorted findings, stable hashes. No timestamps in the report
  hash.
- **Evidence-based:** every finding points to a path, line, column, snippet, and snippet hash.
- **Fail closed:** an unresolved check is `UNVERIFIED`, never `PASS`.
- **Tamper-evident:** the report binds the scanned files and its own content with SHA-256.
- **Safe by default:** no target code execution. The optional build adapter invokes the .NET SDK
  compiler only.
- **Auditable exceptions:** policy suppressions require a reason and expiry and remain visible.

## Requirements

- Python 3.9 or newer.
- No third-party Python packages.
- For the `csharp-aspnetcore` profile: source files are read as text; .NET is only needed for
  `--build`.

## Commands

```bash
# Scan
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root PATH \
  --profile csharp-aspnetcore \
  --report secureflow-report.json \
  --markdown secureflow-report.md \
  --claims secureflow-claims.json \
  --policy secureflow-policy.json \
  --fail-on fail

# Verify a report against the current tree
python skill/secureflow/scripts/secureflow-gate.py verify-report \
  --report secureflow-report.json \
  --root PATH

# Explain a rule
python skill/secureflow/scripts/secureflow-gate.py explain --rule SF-INJ-001

# Create a policy template
python skill/secureflow/scripts/secureflow-gate.py init-policy --output secureflow-policy.json

# Version
python skill/secureflow/scripts/secureflow-gate.py version
```

`--fail-on` values:

- `fail` (default): exit 1 only when a control fails.
- `unverified`: exit 2 when no control fails but at least one is unverified.
- `never`: exit 0 for completed scans regardless of status; report still contains the result.

Exit codes: 0 pass, 1 fail, 2 unverified (with `--fail-on unverified`), 3 usage/input/execution
error, 4 integrity failure.

## Status model

| Status | Meaning |
| --- | --- |
| `PASS` | Every required check produced positive evidence. |
| `FAIL` | At least one unsuppressed finding shows a missing or broken control. |
| `UNVERIFIED` | The control has applicable surface but the gate cannot establish pass or fail. |
| `NOT_APPLICABLE` | No applicable surface was found in the scanned root. |

Aggregation per control:

```text
findings > 0                  -> FAIL
no applicable surface         -> NOT_APPLICABLE
required checks not all PASS  -> UNVERIFIED
otherwise                     -> PASS
```

Overall status is the worst control status: `FAIL` > `UNVERIFIED` > `PASS` > `NOT_APPLICABLE`.
If every control is `NOT_APPLICABLE`, overall is `NOT_APPLICABLE` (exit 0).

## Profiles and rule packs

A profile merges one or more JSON packs:

- `base` — cross-language secret detection and control metadata.
- `csharp-aspnetcore` — C# rules, analyzers, and applicability for ASP.NET Core.

A rule pack has this shape:

```json
{
  "schema_version": "secureflow.rulepack/v1",
  "id": "base",
  "controls": [
    {
      "id": "secrets-management",
      "title": "Secrets management",
      "description": "Credentials are not stored in source.",
      "analyzers": ["secrets"]
    }
  ],
  "rules": [
    {
      "id": "SF-SEC-001",
      "control": "secrets-management",
      "title": "Hardcoded credential",
      "kind": "regex",
      "severity": "high",
      "confidence": "high",
      "include": ["**/*.cs", "**/*.json"],
      "pattern": "...",
      "allow_pattern": "...",
      "message": "...",
      "remediation": "...",
      "cwe": ["CWE-798"],
      "asvs": ["V13.3.1"],
      "owasp": ["A02:2025"]
    }
  ]
}
```

To extend to a new language, add a pack with include globs and regex rules, then add a profile in
`rules.py`. Framework-specific semantics require a Python analyzer. Rule-only packs are useful
for secrets and simple sink patterns; they are explicitly less precise.

### Supported rule modes

- `finding`: a match is evidence of a broken control. Produces `FAIL`.
- `review`: a match requires manual review. Produces `UNVERIFIED`.

## C# static analysis

### Comment and string masking

Structural analysis masks comments and string contents while preserving offsets and line
numbers. Secret detection uses the original text. This prevents attributes or keywords inside
comments and strings from creating false positives.

### Endpoint discovery

Controller endpoints:

- Class-level and method-level attributes.
- `[HttpPost]`, `[HttpPut]`, `[HttpPatch]`, `[HttpDelete]`.
- `[Route]` without a verb is treated as multi-verb and therefore mutating.
- `[AcceptVerbs]` containing a mutating verb.
- `[Authorize]` at class or method level.
- `[AllowAnonymous]` at class or method level.

Minimal APIs:

- `MapPost`, `MapPut`, `MapPatch`, `MapDelete`.
- `.RequireAuthorization()` in the same statement.
- `.AllowAnonymous()` in the same statement.
- Fallback policy and global `AuthorizeFilter` / `MapControllers().RequireAuthorization()`.

Global deny-by-default evidence:

- `FallbackPolicy = ...` (not `null`).
- `AuthorizeFilter`.
- `MapControllers().RequireAuthorization()`.
- `AddAuthorization` with a non-null fallback policy.

### Authentication

Detects registration and middleware:

- `AddAuthentication`, `AddCookie`, `AddJwtBearer`, `AddOpenIdConnect`, `AddIdentity`,
  `AddMicrosoftIdentityWebApp`.
- `UseAuthentication`.
- Cookie `HttpOnly` and `SecurePolicy`.
- JWT `RequireHttpsMetadata`.

### Input validation

Detects:

- `[ApiController]`, `ModelState.IsValid`, FluentValidation validators and registration,
  `Validator.TryValidateObject`, `ValidationProblem`.
- Validation attributes: `[Required]`, `[StringLength]`, `[MaxLength]`, `[MinLength]`, `[Range]`,
  `[RegularExpression]`, `[EmailAddress]`, `[Phone]`, `[Url]`, `[Compare]`,
  `[CustomValidation]`, `[BindRequired]`, `[JsonRequired]`.
- `SuppressModelStateInvalidFilter = true`.

### Injection

SQL surfaces:

- `FromSqlRaw`, `ExecuteSqlRaw`.
- `new SqlCommand`, `new SqliteCommand`.
- Dapper `Query`, `QueryAsync`, `Execute`, `ExecuteAsync`.
- Parameterization evidence: `SqlParameter`, `SqliteParameter`, `Parameters.Add`,
  `AddWithValue`, `FromSqlInterpolated`, `ExecuteSqlInterpolated`, Dapper parameter objects.

OS command surfaces:

- `Process.Start`.
- `new ProcessStartInfo`.
- Dynamic `Arguments` assignment.
- Safe evidence: constant `FileName` plus `ArgumentList.Add`.

The gate distinguishes a constant query/command from a dynamic one and from an unresolved
variable. Dynamic without mitigation is `FAIL`; unresolved is `UNVERIFIED`.

### Known false positives and false negatives

False positives are possible when:

- A safe custom wrapper hides parameterization.
- A dynamic string is validated elsewhere and then passed to a sink.
- `ProcessStartInfo` is configured in a helper method outside the inspected block.
- Authorization is enforced by a custom middleware or gateway not recognized by the parser.

False negatives are possible when:

- Queries or commands are built through reflection, dynamic dispatch, or custom abstractions.
- Authorization uses a custom attribute or endpoint filter.
- Object-level authorization is missing even though the route has `[Authorize]`.
- Secrets are encoded, split, generated, or stored outside scanned files.
- The language or framework is not covered by the active profile.

Every false positive or negative should become a test fixture and, where feasible, an analyzer
improvement. Do not silently suppress a class of findings.

## Claims audit

Claims are JSON. The gate validates structure and evidence, then compares claimed status with
the independently computed status. A claim cannot upgrade a gate result.

Verdicts:

- `confirmed`: claim and gate agree on `PASS`.
- `contradiction_overstated`: claim says `PASS` where gate is `FAIL` or `UNVERIFIED`.
- `contradiction_understated`: claim is more pessimistic than the gate; gate stays as computed.
- `unverified`: claim or gate is `UNVERIFIED`.
- `rejected`: malformed claim, invalid status, or invalid evidence.

Evidence validation:

- Path must be relative and resolve inside the root. Absolute paths, `..` escapes, and symlinks
  outside the root are rejected.
- File must exist and be within the scan limits.
- Line must exist (1-based).
- Snippet must match the trimmed line.
- Optional SHA-256 must match the trimmed snippet.

## Policy and suppressions

Policy file:

```json
{
  "schema_version": "secureflow.policy/v1",
  "suppressions": [
    {
      "rule_id": "SF-SEC-001",
      "path": "tests/Fixtures/FakeCredential.cs",
      "reason": "Fake credential used only in a negative test fixture.",
      "expires": "2026-12-31",
      "owner": "security-team"
    }
  ]
}
```

Rules:

- `reason` and `expires` are required. An expired suppression is not applied.
- A suppression without a valid reason/date is ignored and reported as a warning.
- Suppressed findings remain in `suppressed_findings` with the suppression metadata.
- A control with suppressed findings can become `PASS`, but the report states how many findings
  were suppressed. This is an explicit accepted-risk decision, not a hidden pass.
- Suppressions never modify the underlying evidence or file hashes.

## Report integrity

The report contains:

- `integrity.files`: relative path, SHA-256, size for every scanned file.
- `integrity.inventory_sha256`: hash of the sorted file inventory.
- `integrity.report_sha256`: SHA-256 of the canonical JSON report excluding this field.

Canonical JSON means UTF-8, sorted keys, separators `,` and `:` without spaces, and no ASCII
escaping. Timestamps are included in the report but not in the hash input.

`verify-report`:

1. Recomputes `report_sha256`; a mismatch exits 4.
2. Re-hashes every listed file and reports changed or missing files.
3. Rescans the tree with the stored profile and excludes; reports added files.
4. Checks `inventory_sha256`.
5. Exits 4 on any integrity failure; 0 otherwise.

A report is evidence of a scan at a point in time, not a signature. An attacker who can rewrite
both the report and the tree can recompute hashes. For release signing, sign the report hash with
an external key or transparency log.

## Safety

- No `shell=True`. External commands use argument lists.
- Symlinks are not followed during the scan.
- Files with NUL bytes and files larger than 2 MiB are skipped and reported.
- Default excluded directories: `.git`, `.vs`, `node_modules`, `bin`, `obj`, `dist`, `build`,
  `coverage`, `.venv`, `__pycache__`, `vendor`, `.secureflow`.
- The build adapter has a timeout and captures a bounded output tail.
- Secret snippets are masked before being written to reports.
- The gate does not send source code to any network service.

## Extending the gate safely

1. Add a failing fixture and a passing fixture.
2. Add or update a rule with complete metadata.
3. Implement the analyzer without executing target code.
4. Ensure every outcome is one of the four statuses.
5. Run the full test suite on Windows and a POSIX environment if available.
6. Update `docs/limitations.md` and the rule documentation.
