# Changelog

All notable changes to SecureFlow are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic
versioning.

## [0.1.0] - 2026-11-15

Release candidate. This is the first public, installable version. It is ready for a pilot, not
for a production security certification program.

### Added

#### SecureFlow Skill

- Portable `SKILL.md` with portable Agent Skills frontmatter and a six-phase security workflow.
- Guidance for scope, risk identification, testable requirements, threat modeling, secure
  implementation, review, verification, and evidence-based reporting.
- Progressive-disclosure references for workflow, threat modeling, controls, C#/ASP.NET Core
  secure coding, checklists, gate design, agent compatibility, and reporting.
- Templates for threat models, security requirements, claims, policy, and human reports.

#### SecureFlow Gate

- Standard-library Python 3.9+ gate with no third-party runtime dependencies.
- Commands: `scan`, `verify-report`, `explain`, `init-policy`, and `version`.
- Four statuses: `PASS`, `FAIL`, `UNVERIFIED`, and `NOT_APPLICABLE`.
- Deterministic file inventory with SHA-256, size, sorted paths, exclusions, binary and size
  limits, and no symlink following.
- Regex rule packs with allowlists, per-rule metadata, CWE, ASVS 5.0, and OWASP Top 10:2025
  mappings.
- C#/ASP.NET Core parser and analyzers for:
  - input validation mechanisms and global validation suppression;
  - authentication registration, middleware invocation, cookie flags, and JWT transport;
  - controller and minimal-API mutating endpoints, `[Authorize]`, `[AllowAnonymous]`, and
    fallback authorization policy;
  - hardcoded credentials, private keys, recognizable access tokens, and connection-string
    passwords;
  - dynamic SQL construction, raw SQL sinks, Dapper calls, `CommandText`, and SQL parameter
    evidence;
  - `Process.Start`, `ProcessStartInfo`, dynamic arguments, shell execution, and
    `ArgumentList` evidence.
- Claims audit with evidence validation, path containment, line and snippet matching, and
  contradiction verdicts. Claims cannot upgrade a gate status.
- Time-bounded policy suppressions that retain suppressed findings as audit evidence.
- Canonical JSON report with per-file hashes, inventory hash, and `report_sha256`.
- `verify-report` detects report tampering, modified or missing files, and newly added files.
- Markdown report rendering.
- Optional `--build` adapter runs `dotnet build` with `shell=False` and a timeout.

#### Examples

- `examples/csharp-secure/SecureOrders.Api`: buildable ASP.NET Core reference application that
  passes all five controls.
- `examples/csharp-vulnerable/VulnerableOrders.Api`: buildable intentionally insecure
  application that fails all five controls with reproducible findings.

#### Agent integrations

- Installer for OpenCode, Claude Code, OpenAI Codex, Cursor, and GitHub Copilot, with project and
  user scope, copy and symlink modes, dry-run, overwrite protection, and post-install
  validation.
- Optional templates: OpenCode permission snippet, Codex interface metadata, Cursor rule,
  Copilot instructions and prompt, Claude Code notes, and a GitHub Actions workflow.

#### Project

- `README.md`, `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.
- Architecture, installation, usage, testing, limitations, roadmap, and research documentation.
- CI workflow for Windows and Ubuntu with Python 3.9 and 3.12, plus .NET example builds.
- Standard-library test suite covering skill structure, rule packs, C# parsing, engine statuses,
  claims, policy, reports, CLI exit codes, installer behavior, Python 3.9 syntax compatibility,
  and both examples.

### Security

- Secret values are masked before snippets are hashed or written to reports.
- Claims and evidence paths cannot escape the scan root.
- Scanner and installer use `pathlib` and avoid shell execution.
- `Microsoft.Data.Sqlite` was updated from `10.0.0` to `11.0.0` after the earlier dependency
  graph reported a vulnerable transitive `SQLitePCLRaw.lib.e_sqlite3` version. The final example
  dependency check reports no known vulnerable packages.

### Known limitations

- The gate is static and covers five controls for C#/ASP.NET Core. It does not execute the target
  application by default.
- The C# parser is a masked structural parser, not Roslyn. It does not cover every C# construct,
  generated code, custom routing, or runtime policy provider.
- Object-level authorization, dependency vulnerabilities, secret history, DAST, infrastructure,
  and runtime configuration are not verified.
- Live discovery and invocation inside each supported agent were not automated in this release.
- Report hashes are tamper-evident, not cryptographically signed.
- See [docs/limitations.md](docs/limitations.md) for the complete list.

### Verification

- Full test suite: 88 tests, all passing on Windows with Python 3.12.10 in 12.085 seconds.
- Gate smoke test: secure example exits `0`; vulnerable example exits `1`; report round-trip
  verifies.
- Both reference applications build with .NET SDK 10.0.404 and no warnings.
- `pip install .` in a clean virtual environment provides the `secureflow-gate` console script.
- Cross-platform CI configuration is included; the Linux matrix had not been run in the local
  development environment at release time.
