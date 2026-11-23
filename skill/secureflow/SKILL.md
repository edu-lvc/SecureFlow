---
name: secureflow
description: Security workflow for AI coding agents. Use when designing, implementing, reviewing, testing, or shipping software that handles input, identities, permissions, secrets, database queries, or OS commands. Guides threat modeling, secure coding, security review, deterministic gate verification, and evidence-based reporting.
license: MIT
compatibility: Agent-agnostic Agent Skill. The workflow needs only file access and command execution. The optional gate requires Python 3.9+ and runs without third-party packages.
metadata:
  version: "0.2.1"
  standard: "Agent Skills specification"
---

# SecureFlow

SecureFlow makes secure development the default behavior of an AI coding agent. It is a
prevention-first workflow, not a vulnerability scanner. Use it before code is written, while
code is written, and before security work is declared complete.

## Core rules

1. **Security requirements come before implementation.** For any change that touches input,
   identity, permissions, secrets, persistence, files, network calls, or OS commands, identify
   assets, trust boundaries, threats, and required controls first.
2. **Never claim a control works without evidence.** Evidence is a file path, a line number,
   and the exact code or configuration that implements the control. "It should be safe" is not
   evidence.
3. **Treat missing evidence as `UNVERIFIED`.** Never convert absence of evidence into `PASS`.
4. **The gate is independent.** `secureflow-gate` inspects the repository and does not trust
   comments, commit messages, or agent claims. Claims are audited as annotations and never
   change a control status.
5. **Fail closed.** If a required check cannot run, report `UNVERIFIED` and explain why.
6. **Do not weaken controls to make a check pass.** Fix the code, document a real exception, or
   report the failure.
7. **Never deploy or execute untrusted target code as part of a scan.** The gate is static by
   default. The optional `--build` adapter only compiles a .NET project.
8. **Redact secrets.** Never copy credential values into reports, tickets, or chat. Report the
   location and a masked snippet.

## When to use this skill

Use SecureFlow when the task involves any of the following:

- A new feature, endpoint, API, background job, CLI command, data flow, or firewall rule.
- Authentication, sessions, tokens, passwords, MFA, or identity providers.
- Authorization, roles, policies, tenants, ownership checks, or admin functions.
- SQL, ORM queries, stored procedures, shell commands, process execution, or file paths.
- Configuration, connection strings, API keys, certificates, or environment variables.
- Firewall configuration exports, NAT rules, VPN settings, or network segmentation.
- Security logging, detection rules, incident response, or SIEM rule stubs.
- A security review, threat model, security test plan, release gate, or security report.
- A request to "make this secure", "check for vulnerabilities", or "review security".

Do not use it as a substitute for a penetration test, runtime DAST, dependency scanning, or a
human security review of high-risk systems.

## Workflow

Follow the phases in order. Scale the depth to the risk; do not skip evidence.

### Phase 0 — Establish scope

- Identify the repository root, languages, frameworks, entry points, data stores, external
  services, and deployment model.
- List what is in scope and explicitly out of scope.
- Locate existing security policy, threat model, and test commands.
- If the repository is unfamiliar, read `references/workflow.md` before changing code.

### Phase 1 — Identify security risks

- Map assets: data, credentials, sessions, money, permissions, availability.
- Map trust boundaries: browser to API, API to database, service to service, CI to production.
- Identify attacker-controlled input and privileged operations.
- Record assumptions and unknowns. Unknowns become `UNVERIFIED`, not `PASS`.

### Phase 2 — Define requirements and threat model

- Select applicable controls from `references/controls.md`.
- Write requirements as testable statements with an ID, for example:
  `REQ-AUTHZ-001: Only the order owner or an administrator may read an order.`
- Build or update a lightweight threat model using
  `assets/threat-model-template.md` and `references/threat-modeling.md`.
- Map requirements to OWASP ASVS 5.0, OWASP Top 10, CWE, and NIST SSDF where useful.
- Define the evidence that will prove each requirement.

### Phase 3 — Implement secure defaults

- Apply the language guidance. For C# and ASP.NET Core, read
  `references/secure-coding-csharp.md`.
- Prefer framework primitives over custom cryptography or custom authorization.
- Validate on the server at a trusted boundary. Parameterize queries. Avoid dynamic OS
  commands. Load secrets from a secret store or configuration provider.
- Add tests for the control, including negative cases.

### Phase 4 — Review the change

- Review the diff and the surrounding code, not only the added lines.
- Use `references/checklists.md` for the five baseline controls.
- Look for missing authorization on object access, not only on routes.
- Look for secrets in source, configuration, tests, fixtures, and CI files.
- Look for missing security-relevant logging on authentication, authorization, and admin events.
- Record findings with location, impact, and remediation.

### Phase 5 — Verify with evidence

Run the deterministic gate when the ecosystem is supported:

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root . \
  --profile csharp-aspnetcore \
  --report secureflow-report.json \
  --markdown secureflow-report.md
```

For firewall configuration exports:

```bash
python skill/secureflow/scripts/secureflow-gate.py audit-firewall \
  --config firewall-config.xml \
  --vendor pfsense \
  --report firewall-report.json \
  --markdown firewall-report.md
```

If the skill is installed elsewhere, use the installed path to `scripts/secureflow-gate.py`.
Add `--claims secureflow-claims.json` to audit agent claims. Add `--build` only when compiling
the target is acceptable.

The gate returns:

| Exit | Meaning |
| --- | --- |
| 0 | Overall `PASS` (all controls `PASS` or `NOT_APPLICABLE`) |
| 1 | At least one `FAIL` |
| 2 | No `FAIL`, but at least one `UNVERIFIED` and `--fail-on unverified` |
| 3 | Usage, input, policy, or execution error |
| 4 | Report integrity verification failed |

Status semantics:

- `PASS`: the required checks ran and produced positive evidence.
- `FAIL`: a check produced evidence of a missing or broken control.
- `UNVERIFIED`: the check could not establish pass or fail from available evidence.
- `NOT_APPLICABLE`: the control has no applicable surface in scope.

A control is `FAIL` if it has any unsuppressed finding. Otherwise it is `NOT_APPLICABLE` if no
surface exists, `UNVERIFIED` if any required check is unverified, and `PASS` only when every
required check passed.

### Phase 6 — Report and hand off

- Produce the machine-readable report from the gate and a human summary.
- Generate Sigma rules with `scan --sigma-out <dir>` when the findings have MITRE mappings and
  telemetry sources.
- For firewall work, produce an audit report or a remediation plan (`plan-firewall`) and apply
  changes only with explicit approval (`apply-firewall --confirm`).
- For incidents, use `init-incident` to create response templates.
- For every claim, include the control, status, evidence path, line, and snippet hash.
- State limitations and residual risk explicitly.
- Do not say "the application is secure". Say which controls were verified, with evidence,
  and which were not.
- Use `assets/report-template.md` and `references/reporting.md`.

## Claims and the gate

Agent claims are inputs to an audit, never authority. A claim file looks like this:

```json
{
  "schema_version": "secureflow.claims/v1",
  "claims": [
    {
      "control": "authorization",
      "status": "PASS",
      "evidence": [
        {
          "path": "src/OrdersController.cs",
          "line": 42,
          "snippet": "[Authorize]",
          "sha256": "<sha256 of the trimmed snippet>"
        }
      ]
    }
  ]
}
```

Rules enforced by the gate:

- Evidence must resolve inside the scanned root, at an existing line.
- The snippet must match that line after trimming.
- If `sha256` is present, it must match the trimmed snippet.
- A claim cannot raise a gate status. `PASS` versus gate `FAIL` is a contradiction and is
  recorded as overstated. `FAIL` versus gate `PASS` is recorded as understated; the gate remains
  `PASS` and the discrepancy is visible.
- Invalid claims are rejected and reported, not silently ignored.

## Baseline controls

| Control | Minimum evidence |
| --- | --- |
| Input validation | Server-side validation mechanism, allowlists or typed constraints, rejection path tested |
| Authentication | Auth middleware registered and used, secure cookie/token settings, no default credentials |
| Authorization | Every mutating endpoint protected, object-level ownership or policy checks, deny-by-default |
| Secrets management | No hardcoded credentials, secret provider configured, values absent from source and artifacts |
| Injection prevention | Parameterized SQL/ORM, no dynamic shell construction, argument-vector process execution |
| Security logging | Logging infrastructure present, authentication/authorization/admin events explicitly logged |

Read `references/controls.md` for requirements, evidence, and anti-patterns.

## Progressive disclosure

Load only what the task needs:

- `references/workflow.md` — detailed six-phase workflow and decision points.
- `references/threat-modeling.md` — lightweight threat modeling method and examples.
- `references/controls.md` — control requirements, evidence, and failure modes.
- `references/secure-coding-csharp.md` — C# and ASP.NET Core implementation guidance.
- `references/checklists.md` — review checklists for the six baseline controls.
- `references/gate.md` — gate architecture, rules, policy, claims, and report schema.
- `references/firewall.md` — firewall assessment with pfSense.
- `references/detection-engineering.md` — MITRE mapping, Sigma generation, and coverage ledger.
- `references/incident-response.md` — incident response templates and workflow.
- `references/agent-compatibility.md` — supported agents and installation differences.
- `references/reporting.md` — evidence-based report structure and wording.

Templates are in `assets/`. The executable gate is in `scripts/`.

## Stop conditions

Stop and report `UNVERIFIED` or `FAIL` when:

- A required control has no implementation evidence.
- The gate cannot run because the ecosystem or runtime is unavailable.
- The only evidence is an agent statement, a comment, or a test that was not executed.
- A secret is found. Do not reproduce the value; rotate it and remove it from history.
- Authorization cannot be proven for an object-level operation.
- The requested change would require disabling a security control without an approved,
  time-bound exception.

## Definition of done for a secure change

- Threats and requirements are recorded.
- Controls are implemented at a trusted layer.
- Negative tests exist and pass.
- Gate report is generated and reviewed.
- Every `FAIL` is fixed or explicitly accepted with owner, reason, and expiry.
- Every `UNVERIFIED` is resolved or disclosed as residual risk.
- Documentation matches the implemented behavior.
