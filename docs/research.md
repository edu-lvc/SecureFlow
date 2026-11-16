# Research and standards basis

This document records the primary sources used to design SecureFlow and the decisions they
informed. It is a design record, not a claim of certification or complete standards coverage.

Research was performed against official specifications and vendor documentation. Where a detail
could not be verified, the implementation reports `UNVERIFIED` or documents the gap instead of
asserting support.

## 1. Agent Skills specification

Primary source: <https://agentskills.io/specification>

Key requirements and recommendations used by SecureFlow:

- A skill is a directory with a required `SKILL.md` and optional supporting files.
- YAML frontmatter requires `name` and `description`.
- `name` must be 1–64 characters, use lowercase letters, digits, and hyphens, must not start or
  end with a hyphen, must not contain `--`, and must match the parent directory name.
- `description` must be 1–1024 characters and should say what the skill does and when to use it.
- Optional fields include `license`, `compatibility`, `metadata`, and the experimental
  `allowed-tools`.
- The body is free-form, but a compact `SKILL.md` with detailed material in one-level-deep
  references is recommended for progressive disclosure.
- The reference validator is `skills-ref validate ./my-skill` from the `agentskills/agentskills`
  project.

SecureFlow decisions:

- `skill/secureflow/SKILL.md` uses only portable frontmatter: `name`, `description`, `license`,
  `compatibility`, and string-to-string `metadata`.
- The directory name matches `name: secureflow`.
- The body stays under 500 lines and links to references and assets.
- The gate is an optional script, not a mandatory dependency of the skill instructions.
- Agent-specific frontmatter and hooks are kept out of the core file.

## 2. Agent compatibility research

### OpenCode

Primary source: <https://opencode.ai/docs/skills/>

Findings used:

- Project skills are discovered under `.opencode/skills/`.
- Global skills are discovered under `~/.config/opencode/skills/`.
- OpenCode also reads Claude-compatible and `.agents` skill locations.
- The skill ID is derived from the path and is case-sensitive; the frontmatter `name` is a
  display label.
- The description is required for the skill to be advertised to the model.
- Loading happens through the `skill` tool by exact ID. Supporting files are not auto-loaded.
- Permissions can allow, ask, or deny a skill by resource ID.
- `skills` entries in `opencode.json`/`opencode.jsonc` can add local or HTTP catalogs.

SecureFlow integration: installer destination `.opencode/skills/secureflow` or
`~/.config/opencode/skills/secureflow`; optional permission snippet documenting
`permission.skill.secureflow`.

### OpenAI Codex

Primary source: <https://developers.openai.com/codex/skills>

Findings used:

- Codex uses the open Agent Skills format.
- Repository skills are discovered under `.agents/skills/` from the current directory up to the
  repository root.
- User skills live under `$HOME/.agents/skills/`.
- An optional `agents/openai.yaml` can define interface metadata and implicit-invocation policy.
- Skills can be invoked explicitly or implicitly through the description.
- The initial skill list has a context budget, so concise descriptions matter.

SecureFlow integration: installer destination `.agents/skills/secureflow` or
`~/.agents/skills/secureflow`; optional `integrations/codex/agents/openai.yaml` copied into the
installed skill only when the user wants interface metadata.

### Claude Code

Primary source: <https://docs.claude.com/en/docs/claude-code/skills>

Findings used:

- Claude Code follows the Agent Skills standard.
- Locations include enterprise-managed, personal `~/.claude/skills`, project `.claude/skills`,
  nested skill directories, and additional directories.
- Claude supports extra frontmatter fields such as `when_to_use`, `disable-model-invocation`,
  `user-invocable`, `allowed-tools`, `disallowed-tools`, `model`, `context`, `hooks`, and
  `paths`.
- Claude can dynamically inject command output into a skill. That feature is not portable and is
  not used in the core skill.
- Descriptions may be truncated in the listing, so the first sentences carry the discovery
  signal.

SecureFlow integration: installer destination `.claude/skills/secureflow` or
`~/.claude/skills/secureflow`. No Claude-only hook is required or claimed.

### Cursor

Primary source: <https://cursor.com/docs/context/skills>

Findings used:

- Cursor supports project `.cursor/skills/` and `.agents/skills/`, and user `~/.cursor/skills/`
  and `~/.agents/skills/`.
- Cursor also loads compatible skills from Claude and Codex locations.
- Frontmatter supports required `name` and `description`, plus optional `paths`,
  `disable-model-invocation`, `icon`, `color`, and `metadata`.
- Cursor has separate rules under `.cursor/rules/*.mdc` and supports `AGENTS.md`.
- Cursor ships a built-in security review prompt; SecureFlow is complementary and focuses on
  lifecycle prevention plus deterministic control evidence.

SecureFlow integration: installer destination `.cursor/skills/secureflow` or
`~/.cursor/skills/secureflow`; optional `.mdc` rule in `integrations/cursor/`.

### GitHub Copilot

Primary source:
<https://docs.github.com/en/copilot/concepts/agents/about-agent-skills>

Findings used:

- Copilot supports the open Agent Skills standard.
- Project locations include `.github/skills/`, `.claude/skills/`, and `.agents/skills/`.
- Personal locations include `~/.copilot/skills/` and `~/.agents/skills/`.
- Support varies by Copilot surface and version: app, CLI, cloud agent, code review, and IDE
  agent modes.
- Copilot also supports repository custom instructions, path-specific instructions, and prompt
  files, which are separate mechanisms from skills.

SecureFlow integration: installer destination `.github/skills/secureflow` or
`~/.copilot/skills/secureflow`; optional instructions and prompt files under
`integrations/copilot/`.

### Compatibility conclusion

The installation paths and file layouts are implemented and covered by automated tests. **Live
discovery and invocation inside each agent application were not automated for this release.**
The documentation therefore distinguishes "installed layout tested" from "runtime invocation
verified". This is deliberate: vendor behavior and versions differ, and claiming untested
compatibility would violate the project's evidence standard.

## 3. OWASP Application Security Verification Standard

Primary source: <https://owasp.org/www-project-application-security-verification-standard/>

Design baseline: ASVS 5.0.0, published May 2025. The standard contains 345 requirements across
17 chapters, including encoding and sanitization, validation and business logic, web frontend
security, API and web service security, file handling, authentication, session management,
authorization, self-contained tokens, OAuth/OIDC, cryptography, secure communication,
configuration, data protection, secure coding and architecture, logging and error handling, and
WebRTC.

ASVS requirements referenced by the implemented rules include:

| Requirement | Used for |
| --- | --- |
| V1.2.4 | Parameterized queries and protection against SQL/database injection. |
| V1.2.5 | Protection against OS command injection; argument isolation. |
| V1.2.1–V1.2.3 | Output encoding context, URL handling, JavaScript/JSON encoding. |
| V1.2.6–V1.2.10 | LDAP, XPath, regex escaping, and CSV/formula injection guidance. |
| V2.2.1 | Input validation against allowlists, patterns, ranges, or expected structure. |
| V2.2.2 | Validation at a trusted service layer, never only at the client. |
| V2.2.3 | Reasonable combinations of related data. |
| V6.3.1 | Protection against credential stuffing and brute force. |
| V6.3.2 | No default accounts. |
| V6.3.3 | MFA or a combination of authentication factors. |
| V6.3.4 | No undocumented authentication pathways. |
| V6.3.5 | Notification of suspicious authentication. |
| V6.3.6 | Email is not a single or MFA factor. |
| V6.3.8 | No user enumeration through errors or timing. |
| V7 | Session management and cookie protections, cited at chapter level where an exact requirement ID was not verified. |
| V8 | Authorization, cited at chapter level where exact requirement IDs were not extracted. |
| V9 | Self-contained token handling. |
| V13.3.1 | Secret management and protection of credentials. |

SecureFlow does not claim ASVS compliance. It maps individual findings to relevant requirements
so a reviewer can connect a technical result to a standard.

## 4. OWASP Top 10:2025

Primary source: <https://owasp.org/Top10/2025/>

The 2025 list used for mappings:

| ID | Category |
| --- | --- |
| A01 | Broken Access Control |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |

The implemented rules primarily map to A01, A02, A04, A05, A06, and A07. The skill's workflow
also considers A03, A08, A09, and A10, but the gate does not yet verify them.

## 5. OWASP Cheat Sheet Series

Primary source: <https://cheatsheetseries.owasp.org/>

Cheat sheets used as implementation guidance:

- Injection Prevention
- Query Parameterization
- SQL Injection Prevention
- OS Command Injection Defense
- Input Validation
- Authentication
- Authorization
- Authorization Testing Automation
- Secrets Management
- DotNet Security
- Secure Code Review
- Secure Coding with AI
- Threat Modeling
- Password Storage
- Session Management
- Cross-Site Request Forgery Prevention

The cheat sheets inform the secure-coding reference and remediation text. They are not bundled
or copied; links and short paraphrases are used.

## 6. NIST Secure Software Development Framework

Primary source: <https://csrc.nist.gov/pubs/sp/800/218/final>

Design baseline: NIST SP 800-218, SSDF version 1.1, February 2022.

Practice groups used in the workflow:

| Group | Focus | SecureFlow mapping |
| --- | --- | --- |
| PO | Prepare the organization | Security requirements, roles, and tooling setup. |
| PS | Protect the software | Protect code, provenance, and release integrity. |
| PW.1 | Design software to meet security requirements | Threat modeling and security requirements phase. |
| PW.2 | Review the software design | Design review and abuse-case review. |
| PW.4 | Reuse secure components | Dependency and component review guidance. |
| PW.5 | Create source code securely | Secure coding reference and checklists. |
| PW.6 | Configure build and compile securely | Optional build adapter and CI guidance. |
| PW.7 | Review and analyze code | Static gate and manual review checklist. |
| PW.8 | Test executable code | Security test guidance; runtime testing not automated by the gate. |
| PW.9 | Configure software securely by default | Secure defaults and configuration checks. |
| RV.1–RV.3 | Identify, assess, and remediate vulnerabilities | Findings, evidence, policy expiry, and reporting. |

The gate report does not claim SSDF compliance. It provides evidence that can support an SSDF
program.

## 7. CWE Top 25 and secure coding

Primary source: <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>

Relevant 2025 entries used in mappings:

| CWE | Name |
| --- | --- |
| CWE-79 | Cross-site scripting |
| CWE-89 | SQL injection |
| CWE-352 | Cross-site request forgery |
| CWE-862 | Missing authorization |
| CWE-787 | Out-of-bounds write |
| CWE-22 | Path traversal |
| CWE-416 | Use after free |
| CWE-125 | Out-of-bounds read |
| CWE-78 | OS command injection |
| CWE-94 | Code injection |
| CWE-434 | Unrestricted upload of dangerous file type |
| CWE-502 | Deserialization of untrusted data |
| CWE-863 | Incorrect authorization |
| CWE-20 | Improper input validation |
| CWE-200 | Exposure of sensitive information |
| CWE-306 | Missing authentication for critical function |
| CWE-918 | Server-side request forgery |
| CWE-77 | Command injection |
| CWE-639 | Authorization bypass through user-controlled key |
| CWE-770 | Allocation of resources without limits or throttling |

The baseline gate covers CWE-20, CWE-78, CWE-89, CWE-259, CWE-287, CWE-295, CWE-306, CWE-321,
CWE-614, CWE-798, CWE-862, CWE-1004, and related authorization and secret-handling weaknesses.
Coverage is partial by design; the report lists the mapped CWE for each finding.

## 8. Existing open-source security skills and tools

### Cloudflare security-audit-skill

Repository: <https://github.com/cloudflare/security-audit-skill>

It is a multi-phase vulnerability audit harness. It emphasizes reconnaissance, a coverage ledger,
isolated hunter agents, fresh verifier agents, and a findings file with confirmed,
needs-validation, and rejected states. It requires an OS sandbox for executing target code.

What SecureFlow learned:

- Independent verification is more credible than a single model's claim.
- Coverage and evidence ledgers prevent "looks good" conclusions.
- Verification must be separated from discovery.

Where SecureFlow differs:

- SecureFlow starts before implementation with requirements and threat modeling.
- SecureFlow is a deterministic, static control gate with a machine-readable schema, not a
  penetration-test orchestration harness.
- SecureFlow binds results to a file inventory and report hash, and audits agent claims against
  the gate.
- SecureFlow does not require target execution or an OS sandbox for its default path.

### Anthropic-Cybersecurity-Skills and similar collections

These projects provide broad catalogs of offensive and defensive security skills. They are useful
for knowledge breadth, but a catalog does not enforce a development lifecycle or produce
reproducible per-control evidence. SecureFlow focuses on a small number of controls with explicit
statuses and tests.

### NVIDIA SkillSpector and Snyk agent-scan

These tools scan AI skills themselves for malicious or unsafe content. That is a different trust
problem: protecting the agent from a hostile skill. SecureFlow protects the software produced by
an agent and does not claim to vet third-party skills.

### Cursor's built-in security review

Cursor documents a security review workflow. It is prompt-driven and editor-integrated.
SecureFlow is agent-agnostic, adds a separate verifier, and records tamper-evident evidence.
They can be used together.

### General-purpose SAST and dependency scanners

Tools such as CodeQL, Semgrep, Snyk, and Dependabot are deeper in their domains. SecureFlow is not
a replacement. It is a lifecycle skill plus a small, auditable gate that makes missing controls
visible and gives agents a concrete definition of done. Integration with these tools is a
roadmap item, not a current claim.

## 9. Design conclusions

The research led to these choices:

1. **Prevention-first workflow.** The most valuable agent intervention is before insecure code is
   written. The skill therefore starts with scope, assets, threats, and testable requirements.
2. **A separate gate.** A model cannot reliably verify its own claims. The gate reads the
   repository and treats claims as untrusted input.
3. **Four statuses.** Binary pass/fail hides uncertainty. `UNVERIFIED` prevents missing evidence
   from becoming a false `PASS`, and `NOT_APPLICABLE` avoids penalizing projects without the
   relevant surface.
4. **C# first.** ASP.NET Core has clear, testable conventions for attributes, middleware, cookie
   options, SQL access, and process execution. It is a practical first ecosystem for a deep
   parser and analyzers.
5. **Rule packs, not a monolith.** Other languages can start with regex rules and add analyzers
   only where semantics require them.
6. **Evidence binding.** A finding without a path, line, snippet hash, and rule is not actionable.
   A report without integrity checks is easy to alter.
7. **Honest compatibility.** Installation layout is tested; live agent invocation is not. The
   documentation says so.

## 10. Open research questions

- How often does a static route-level authorization `PASS` hide an object-level authorization
  failure in real projects?
- Which C# constructs cause the most parser false negatives in practice?
- Can a rule-only pack provide useful signal without generating unacceptable false positives?
- What is the right evidence format for agent claims that is both machine-checkable and resistant
  to gaming?
- How should report signing and CI artifact storage work for small teams?
- Which agent versions expose a headless way to verify skill discovery automatically?

These questions are tracked in the roadmap and should be answered with pilot data, not
assumptions.
