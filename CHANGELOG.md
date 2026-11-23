# Changelog

All notable changes to SecureFlow are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic
versioning.

## [0.2.1] - 2026-11-22

Accuracy release for the Firewall Security module: fixes false positives and unsound heuristics
found during the first audit of a real pfSense 24.0 export, without changing the CLI or the
`secureflow.firewall.report/v1` schema.

### Fixed

- **FW-RULE-003 context awareness.** Sensitive-port rules are now classified by interface,
  source, and destination: WAN rules stay `critical`/`high` `FAIL`, internal rules restricted to
  specific source networks and destination hosts are reported as `low` `UNVERIFIED` instead of
  `high` `FAIL`. Automatic plan changes are only generated for `critical`/`high` findings.
- **FW-LOG-004 NTP detection.** The analyzer recognises `<system><timeservers>` (pfSense >= 24.0)
  in addition to the legacy `<ntp><timeservers>` layout, so a configured firewall is no longer
  reported as having no time synchronization. An empty timeservers element now yields FW-LOG-003.
- **VPN presence.** `<ipsec>` and `<openvpn>` elements without tunnel children (phase1 /
  openvpn-server / openvpn-client) are treated as *no VPN configured* (`NOT_APPLICABLE`), not as
  a passing VPN posture. The PASS check now carries evidence of the configured tunnels.
- **Evidence lines.** `_line_for_element` builds an exact element-path index with a single expat
  pass instead of a sequential cursor, so every finding points at its own XML element even for
  repeated tags such as `<rule>`. The `<filter>` lookup no longer matches
  `<filterdescriptions>`. Evidence `snippet_sha256` is computed over the stored (redacted)
  snippet.
- **IPv6 analysis.** Rules now parse `<ipprotocol>`; only active (non-disabled) IPv6 rules count
  as IPv6 coverage. The previous heuristic that treated any WAN-interface rule as an IPv6 rule
  was removed.
- **Segmentation.** WiFi/guest interfaces (by name or description) are evaluated for LAN
  isolation with rule-order awareness (new FW-SEG-003); DMZ detection uses the interface name or
  description instead of a fixed interface list; PASS checks carry the concrete rule or
  interface evidence.
- **Interface security.** DHCP/PPPoE WAN addresses cannot be verified statically, so the
  `wan-address` check is `UNVERIFIED` (with evidence) instead of contributing to a blanket PASS.
  An `interface-enabled` PASS check reports the verified enablement with evidence.
- **Port parsing.** An explicit `<port>` sibling of `<any/>` in a destination is honoured
  (pfSense writes `<destination><any/><port>445</port></destination>`).

### Security

- Evidence snippets are redacted at the source (`FirewallConfig.evidence`), covering check
  evidence as well as finding evidence; `<bcrypt-hash>` was added to the sensitive-tag list.
  Verified by tests that reports contain no credentials, hashes, or private keys.

### Tests

- 26 regression tests added for the defects above (131 -> 157 total), including evidence-line
  checks against the real pfSense 24.0 export.
- Secure/vulnerable fixtures retained; expectation updates: secure fixture is `UNVERIFIED`
  overall (DHCP WAN), vulnerable fixture `interface-security`/`ipv6-security` are `UNVERIFIED`.

### Known limitations

- FW-ADMIN-002 still defaults a missing WebGUI port to 443 even when the protocol is HTTP, so an
  HTTP console on the default port does not raise the non-standard-port finding.
- Guest/WiFi isolation PASS for "default deny" configurations is based on the absence of allow
  rules toward LAN/any; rules are evaluated in document order without alias or schedule support.
- The RFC 1918 check for DHCP WAN addresses requires reading the runtime address from the live
  device, which this release intentionally does not do.
- Report hashes remain tamper-evident but unsigned.

### Re-audit of the real pfSense 24.0 export (before -> after)

- Overall: `FAIL` -> `FAIL` (WebGUI HTTP remains a true positive).
- Controls: `vpn-security` PASS -> NOT_APPLICABLE, `segmentation` PASS -> UNVERIFIED,
  `interface-security` PASS -> UNVERIFIED, `rule-permissiveness` FAIL -> UNVERIFIED,
  `logging-ntp` keeps UNVERIFIED but loses the false-positive FW-LOG-004.
- Findings: 9 -> 9; FW-LOG-004 (false positive) removed, FW-SEG-003 (WiFi reachability) added;
  all evidence lines corrected (FW-IPV6-001 165 -> 167; FW-RULE-003 168/203/238/273/308 ->
  273/308/822/1374/1409); severity mix changed from 6 high/3 medium to 1 high/3 medium/5 low.

## [0.2.0] - 2026-11-22

Evolution release: adds firewall assessment, detection engineering, security logging, and
incident response templates while preserving the existing application-security gate.

### Added

#### Firewall Security

- `secureflow_gate.firewall` package with pfSense XML parser, analyzer, report builder, and
  plan/apply helpers.
- CLI commands: `audit-firewall`, `plan-firewall`, and `apply-firewall` (requires `--confirm`).
- Backup and re-audit behavior for `apply-firewall`.
- Fixtures: `tests/fixtures/firewall/pfsense-secure.xml` and `pfsense-vulnerable.xml`.

#### Security Logging

- New `security-logging` control in the `csharp-aspnetcore` profile.
- Analyzer distinguishes logging infrastructure (`ILogger`, Serilog, NLog, `LoggerMessage.Define`)
  from explicit security-relevant log events.
- Rules `SF-LOG-001` and `SF-LOG-002`.

#### Detection Engineering

- Optional `mitre_attack` and `telemetry_sources` metadata on rules.
- `data/mitre-mapping.json` and `data/telemetry-sources.json` with curated mappings.
- `detections/` package: MITRE validation, telemetry registry, Sigma rule generation, and coverage
  ledger.
- `scan --sigma-out` and `generate-sigma` commands for Sigma rule output.
- Additive `detections` section in gate reports.

#### Incident Response

- Incident response templates: `incident-response-template.md`, `ioc-template.md`, and
  `timeline-template.md`.
- CLI command `init-incident` to copy templates into an output directory.

#### SIEM Integration (optional)

- `integrations/siem/wazuh/` adapter stub that converts Sigma rules to Wazuh XML rule fragments.
- Documented as optional and not a runtime dependency.

#### Tests and quality

- 25 firewall tests and 13 detection tests added.
- Existing 88 application-security tests still pass.
- Full suite: 131 tests passing on Windows with Python 3.12.10 in 15.343 seconds.

### Changed

- The `csharp-aspnetcore` profile now includes six controls instead of five.
- `pyproject.toml` packages include `secureflow_gate.data`, `secureflow_gate.detections`, and
  `secureflow_gate.firewall`.

### Known limitations

- Only pfSense firewall XML exports are supported; other vendors are not implemented.
- Sigma rules are experimental stubs and must be reviewed before deployment.
- The Wazuh adapter emits rule fragments; it does not install them into a manager.
- See [docs/limitations.md](docs/limitations.md) for the complete list.

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
