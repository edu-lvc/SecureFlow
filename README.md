# SecureFlow

SecureFlow is an open-source, agent-agnostic security skill for AI coding agents. It makes
secure development the default behavior across the software lifecycle: identify risk before
implementation, define requirements and a threat model, apply secure coding practices, review
the change, run deterministic verification, and produce an evidence-based report.

It is **prevention-first**, not another vulnerability scanner. The optional verification gate
checks whether the security controls an agent claims are present can actually be found in the
repository. It does not execute target code by default and does not turn missing evidence into
a passing result.

**Release candidate:** `0.1.0` · **License:** MIT · **First validated ecosystem:** C# and
ASP.NET Core.

## Why SecureFlow is different

- **Lifecycle workflow, not a scan-only prompt.** Threat modeling, testable requirements,
  secure implementation guidance, review checklists, verification, and reporting are part of
  one skill.
- **Independent evidence gate.** `secureflow-gate` reads the repository itself. Agent claims are
  audited as untrusted annotations and can never upgrade a control status.
- **Four explicit statuses.** `PASS`, `FAIL`, `UNVERIFIED`, and `NOT_APPLICABLE` prevent an
  unknown control from being reported as secure.
- **Tamper-bound reports.** Reports contain file hashes, an inventory hash, and a canonical
  report hash. `verify-report` detects modified, added, or missing files.
- **Time-bounded suppressions.** Exceptions require a rule, path, reason, and expiry; an
  owner is recorded when supplied. Suppressed findings remain in the report as audit evidence.
- **Zero-dependency gate.** Python 3.9+ standard library only; no package installation is
  required to run the scanner.
- **Extensible rule packs.** The C#/ASP.NET Core profile is the deeply validated baseline;
  other ecosystems can add rule packs without changing the gate engine.

## Components

| Component | Purpose |
| --- | --- |
| **SecureFlow Skill** | Universal `SKILL.md`, six-phase workflow, threat modeling, secure coding guidance, checklists, references, and templates. |
| **SecureFlow Gate** | Deterministic static verification of five baseline controls, machine-readable JSON, Markdown report, claims audit, and report integrity verification. |
| **Agent integrations** | Installer plus optional agent-specific templates. The core skill remains independent of any agent. |

## Baseline controls

| Control | What the gate checks |
| --- | --- |
| Input validation | Active server-side validation mechanism; global validation suppression is a failure. |
| Authentication | Authentication registered and invoked; insecure cookie and JWT transport flags. |
| Authorization | Mutating ASP.NET Core endpoints require authorization or a fallback policy. |
| Secrets management | Hardcoded credentials and tokens; managed configuration or secret-provider evidence. |
| Injection prevention | Dynamic SQL and OS command construction versus parameterization and argument isolation. |

The gate maps findings to CWE, OWASP ASVS 5.0, and OWASP Top 10:2025 identifiers. The workflow
also maps practices to NIST SSDF.

## Quick start

Requirements for the gate: Python 3.9 or newer. The C# examples require the .NET 10 SDK.

```bash
# From a checkout of this repository
python -m unittest discover -s tests -v

# Scan the secure reference application (expected: PASS, exit 0)
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-secure/SecureOrders.Api \
  --report secure-report.json \
  --markdown secure-report.md

# Scan the intentionally vulnerable application (expected: FAIL, exit 1)
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-vulnerable/VulnerableOrders.Api
```

Install the skill into a project (OpenCode example):

```bash
python integrations/install.py --agent opencode --scope project --project-dir /path/to/project
```

Then invoke `secureflow` through your agent. See [Installation](docs/installation.md) and
[Usage](docs/usage.md).

## Gate statuses and exit codes

| Status | Meaning |
| --- | --- |
| `PASS` | Required checks ran and produced positive evidence. |
| `FAIL` | A check produced evidence of a missing or broken control. |
| `UNVERIFIED` | The gate could not establish pass or fail from available evidence. |
| `NOT_APPLICABLE` | No applicable surface exists in scope. |

| Exit | Meaning |
| --- | --- |
| `0` | Overall `PASS`, or only `UNVERIFIED` without `--fail-on unverified`. |
| `1` | At least one `FAIL`. |
| `2` | No `FAIL`, at least one `UNVERIFIED`, and `--fail-on unverified`. |
| `3` | Usage, input, policy, claims, or execution error. |
| `4` | Report integrity verification failed. |

## Supported agents

| Agent | Installation layout | Live invocation tested in this release? |
| --- | --- | --- |
| OpenCode | `.opencode/skills/secureflow` / `~/.config/opencode/skills/secureflow` | No; installer and layout tested |
| Claude Code | `.claude/skills/secureflow` / `~/.claude/skills/secureflow` | No; installer and layout tested |
| OpenAI Codex | `.agents/skills/secureflow` / `~/.agents/skills/secureflow` | No; installer and layout tested |
| Cursor | `.cursor/skills/secureflow` / `~/.cursor/skills/secureflow` | No; installer and layout tested |
| GitHub Copilot | `.github/skills/secureflow` / `~/.copilot/skills/secureflow` | No; installer and layout tested |

The installation destinations follow each vendor's published Agent Skills documentation. The
core skill uses only portable frontmatter. Agent-specific optional templates are provided under
`integrations/`; they are not required and are not presented as verified runtime behavior.

## Repository layout

```text
skill/secureflow/          Portable skill: SKILL.md, references, assets, gate scripts
  scripts/secureflow_gate/ Standard-library Python gate package
examples/csharp-secure/    Buildable secure ASP.NET Core reference application
examples/csharp-vulnerable/Buildable intentionally vulnerable application
integrations/              Installer and optional agent templates
tests/                     Standard-library unittest suite and fixtures
docs/                      Architecture, installation, usage, testing, research, limitations
```

## Documentation

- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [Usage](docs/usage.md)
- [Testing](docs/testing.md)
- [Known limitations](docs/limitations.md)
- [Roadmap](docs/roadmap.md)
- [Research and standards](docs/research.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Scope and honesty

A `PASS` means the detected surface satisfied the configured static checks. It is **not** proof
that an application is secure, free of vulnerabilities, or safe to deploy. SecureFlow does not
replace dependency scanning, DAST, penetration testing, infrastructure review, or human
security review. Read [Known limitations](docs/limitations.md) before relying on a result.

## License

MIT. See [LICENSE](LICENSE).
