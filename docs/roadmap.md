# Roadmap

The roadmap describes intended direction, not committed delivery dates. Priorities may change
based on pilot feedback, security reports, and ecosystem demand.

## Guiding principles

1. Keep the core skill portable and agent-independent.
2. Prefer deterministic evidence over model confidence.
3. Never convert missing evidence into a passing result.
4. Add depth to one ecosystem before adding shallow coverage to many.
5. Keep the gate dependency-free and safe by default.

## 0.1.x — Release candidate hardening

Status: current.

- [x] Portable `SKILL.md` and progressive-disclosure references.
- [x] Five-control C#/ASP.NET Core gate with four statuses.
- [x] Claims audit and contradiction detection.
- [x] Time-bounded policy suppressions with audit evidence.
- [x] Tamper-evident JSON report and verification command.
- [x] Installer for five agents and optional templates.
- [x] Buildable secure and vulnerable examples.
- [x] Standard-library test suite and CI configuration.
- [ ] Execute the CI matrix on hosted Windows and Ubuntu runners and publish the result.
- [ ] Collect pilot reports from real projects and classify false positives and false negatives.
- [ ] Add a small SARIF exporter for code-scanning integrations.

## 0.2 — Deeper C# and ASP.NET Core coverage

- [ ] Recognize `record` controllers and broaden endpoint discovery beyond conventional
  controllers and mutating minimal API methods.
- [ ] Add object-level authorization review cues: owner/tenant parameters, `FindAsync`/query by
  identifier, and missing policy checks.
- [ ] Improve EF Core coverage: `FromSqlRaw`, `ExecuteSqlRaw`, `FromSqlInterpolated`, and raw
  string handling in both directions.
- [ ] Add Dapper and ADO.NET data-flow hints for parameters passed through helper methods.
- [ ] Add Razor Pages and MVC view-model validation coverage.
- [ ] Add selected security-header and HTTPS-redirection checks as review-only evidence.
- [ ] Add regression fixtures for false positives found during pilots.

## 0.3 — Additional ecosystems

Each ecosystem starts as experimental and must include positive, negative, and not-applicable
fixtures before it is described as supported.

- [ ] JavaScript/TypeScript: Node.js, Express, and common ORM/query-builder sinks.
- [ ] Python: Django and Flask input validation, authentication, authorization, and query
  construction.
- [ ] Java: Spring Boot endpoint authorization and JDBC/JPA query construction.
- [ ] Go: `net/http` handlers, `database/sql` parameterization, and `os/exec` argument usage.
- [ ] Shared secret patterns and configuration-file checks across ecosystems.

## 0.4 — Evidence and integration maturity

- [ ] SARIF output with rule metadata and baseline comparison.
- [ ] GitHub code-scanning upload example and documented permissions.
- [ ] Optional detached signatures or Sigstore signing for reports.
- [ ] Baseline mode that reports only new findings while preserving the full inventory.
- [ ] Machine-readable limitation and skipped-file summaries in CI annotations.
- [ ] Rule-pack versioning and compatibility checks for third-party packs.
- [ ] A stable JSON schema release policy and migration notes.

## 0.5 — Agent compatibility verification

- [ ] Automated live discovery checks for each supported agent version where a headless mode is
  available.
- [ ] A published compatibility matrix with exact agent versions and invocation results.
- [ ] Tested permission and hook examples only for agents that document those features.
- [ ] Installation verification that checks both file layout and agent-visible skill listing.
- [ ] Clear deprecation policy for agent-specific templates.

## 1.0 — Stable release criteria

- [ ] At least two ecosystems with test depth comparable to the C# profile.
- [ ] No known false `PASS` in the supported rule set, or documented and bounded exceptions.
- [ ] Stable report schema with a compatibility policy.
- [ ] Reproducible CI runs on Windows, Linux, and macOS.
- [ ] Pilot evidence from multiple real projects, including known limitations.
- [ ] Independent security review of the gate, parser, installer, and report integrity logic.
- [ ] Documentation that distinguishes verified compatibility from intended compatibility.

## Out of scope

SecureFlow is not planned to become:

- a runtime DAST or penetration-testing platform;
- a dependency or container vulnerability scanner;
- a SIEM, SOC, or incident-response product;
- a certification or compliance attestation service;
- an autonomous exploit generator.

Those problems need dedicated tools and human accountability. SecureFlow should integrate with
them, not pretend to replace them.

## How to influence the roadmap

Open an issue with:

- the ecosystem and framework version;
- a minimal reproducible fixture;
- the expected status and the actual status;
- why the gap matters for a real security decision.

Security-relevant false `PASS` reports should follow [SECURITY.md](../SECURITY.md).
