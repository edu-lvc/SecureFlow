# SecureFlow architecture

## Design goals

1. **Prevent before verifying.** The skill must influence design and implementation, not only
   inspect finished code.
2. **Agent independence.** The core is an Agent Skill with portable frontmatter and plain file
   access. Agent-specific features are optional adapters.
3. **Evidence over claims.** The gate reads repository contents and records path, line, snippet
   hash, rule, and control for every result.
4. **Fail closed.** Missing, ambiguous, or unsupported evidence is `UNVERIFIED`, never `PASS`.
5. **Reproducibility.** Rule evaluation is deterministic; output ordering is stable; reports are
   integrity-bound.
6. **Safety.** The default scan is static and never executes target code.

## Components

```text
┌─────────────────────────────────────────────────────────────────────┐
│ SecureFlow Skill                                                    │
│ SKILL.md → workflow → references/assets → agent behavior            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ produces code, claims, review evidence
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ SecureFlow Gate                                                     │
│ scan_tree → regex rules + C# analyzers → policy → claims → report   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ JSON + Markdown
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Consumers                                                           │
│ agent summary · CI gate · human review · report verification        │
└─────────────────────────────────────────────────────────────────────┘
```

### 1. SecureFlow Skill

- `skill/secureflow/SKILL.md` is the portable entry point. It contains the six phases, core
  rules, status semantics, gate commands, claims rules, and progressive-disclosure map.
- `references/` contains on-demand detail: workflow, threat modeling, control requirements,
  C# guidance, checklists, gate design, agent compatibility, and reporting.
- `assets/` contains threat-model, requirements, claims, policy, and report templates.
- `scripts/` contains the executable gate.

The skill works without the gate. When the gate is available, the skill requires its evidence
for the supported profile.

### 2. SecureFlow Gate

The gate is a standard-library Python package under
`skill/secureflow/scripts/secureflow_gate/`.

| Module | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, commands, exit codes, summaries. |
| `engine.py` | Orchestration: scan, rules, analyzers, policy, claims, build adapter, report. |
| `scanner.py` | Safe deterministic file inventory with exclusions and hashes. |
| `rules.py` | Rule-pack loading, validation, profiles, explain output. |
| `rulepacks/base.json` | Cross-language secret and policy-independent rules. |
| `rulepacks/csharp-aspnetcore.json` | C#/ASP.NET Core rules, analyzers, control definitions. |
| `csharp.py` | Comment/string masking and a small ASP.NET Core endpoint/auth parser. |
| `analyzers.py` | Control checks for validation, authentication, authorization, secrets, injection. |
| `policy.py` | Time-bounded suppressions with audit metadata. |
| `claims.py` | Evidence validation and claim-versus-gate verdicts. |
| `report.py` | Canonical JSON, report hash, Markdown, integrity verification. |
| `redact.py` | Credential-value masking in report snippets. |
| `globs.py` | Bounded glob matching used by rules and policies. |
| `model.py` | Status, evidence, check, finding, control, and scan-file types. |
| `schema/report.schema.json` | Machine-readable report contract. |

The launcher `scripts/secureflow-gate.py` adds its own directory to `sys.path`, so the gate runs
from a copied skill without installation. The package is also installable through
`pyproject.toml`.

## Scan flow

```text
validate root and profile
        │
        ▼
inventory files (sorted, excludes applied, SHA-256 per file)
        │
        ├── regex rule pass (line-oriented, allowlists, dedupe)
        │
        ├── parse C# once (masked structural view)
        │
        └── analyzer pass (control-specific semantics)
        │
        ▼
apply policy suppressions (findings move to audit list)
        │
        ▼
audit claims against final control statuses
        │
        ▼
optional dotnet build adapter
        │
        ▼
aggregate control statuses → overall status
        │
        ▼
build report → canonical hash → JSON / Markdown
```

### Status aggregation

- A control is `FAIL` if it has an unsuppressed `FAIL` finding.
- Otherwise it is `NOT_APPLICABLE` if no applicable surface exists.
- Otherwise it is `UNVERIFIED` if any required check is unverified.
- Otherwise it is `PASS`.

The overall status is the worst control status using the order
`NOT_APPLICABLE < PASS < UNVERIFIED < FAIL`.

A claim cannot modify this computation.

## C# parsing strategy

The gate does not use Roslyn or a full C# syntax tree. It uses a masked structural view:

- Comments, string contents, and character literals are blanked while preserving length and
  newlines. This prevents strings and comments from spoofing attributes or sinks.
- Class and method attributes are read only at the correct brace depth.
- Controllers are recognized by name or API attributes. Methods are recognized by HTTP verb
  attributes. Minimal APIs are recognized by `MapPost`, `MapPut`, `MapPatch`, and `MapDelete`.
- Global fallback policy and `[Authorize]`/`[AllowAnonymous]` are combined to decide whether a
  mutating endpoint is protected.
- SQL and process-execution sinks are classified as dynamic, constant, or unresolved.

This is deliberately partial. It is predictable and auditable, but it does not understand every
C# construct, generated code, custom routing framework, or runtime policy provider. Those gaps
are reported as limitations and usually become `UNVERIFIED`.

## Rule-pack model

A profile merges one or more packs:

```json
{
  "profiles": {
    "csharp-aspnetcore": ["base", "csharp-aspnetcore"]
  }
}
```

Each rule declares:

- `id` (`SF-<AREA>-<NNN>`), `control`, `title`, `kind` (`regex` or `analyzer`), `mode`
  (`finding` or `review`), severity, confidence
- file include/exclude globs
- regex pattern and optional allow pattern for regex rules
- message, remediation, CWE, ASVS, OWASP mappings
- `min_matches` for minimum regex match count

Controls declare applicability and the analyzers that implement them. New languages can ship a
rule-only pack; new frameworks can add a Python analyzer module and register it in a control
definition. The engine does not execute target code.

## Evidence model

Every finding carries:

- relative path using forward slashes
- 1-based line and column
- redacted snippet
- SHA-256 of the trimmed snippet
- rule, control, severity, confidence, result
- remediation and standard mappings
- stable fingerprint derived from rule, location, and snippet hash

Secret values are masked before the snippet is hashed or written. The report never needs the
original secret value.

## Policy suppressions

Suppressions require `rule_id`, `path`, `reason`, and ISO `expires`; `owner` is optional.
Expired or malformed entries are ignored with a warning. A matched finding is removed from the
active set, annotated with its suppression, and retained in `suppressed_findings`. Only `FAIL`
checks whose rule IDs are all suppressed can become `PASS`; `UNVERIFIED` checks are never
upgraded.

## Claims audit

Claims are untrusted assertions. For each claim the gate verifies:

- known control and valid status
- evidence present for `PASS` and `FAIL`
- relative path resolves inside the scan root
- file exists and line is in range
- trimmed snippet matches the actual line
- optional SHA-256 matches the trimmed snippet

Verdicts are `confirmed`, `contradiction_overstated`, `contradiction_understated`,
`unverified`, or `rejected`. Contradictions are reported in the summary and never change a
control status.

## Report integrity

The report has three integrity layers:

1. Per-file SHA-256 and size for every scanned file.
2. Inventory SHA-256 over the canonical list of `path`, `hash`, and `size`.
3. `report_sha256` over canonical JSON excluding the hash field itself.

`verify-report` recomputes the report hash, re-hashes listed files, rescans the root with the
recorded excludes, and detects modified, added, missing, or newly excluded files. Timestamps are
excluded from the report hash, so two scans of unchanged content have the same hash.

## Safety boundaries

- No symlink following during inventory.
- Files larger than 2 MiB and binary files are skipped.
- Common build, dependency, and VCS directories are excluded.
- No target code execution during a normal scan.
- Optional `--build` runs `dotnet build` with `shell=False` and a timeout. It is an adapter, not
  a sandbox; enable it only when compilation is acceptable.
- Reports and Markdown output are excluded from the scan when placed inside the root.

## Extensibility

To add a language:

1. Create a rule pack with controls, include globs, and regex rules for secrets, injection
   sinks, and configuration hazards.
2. Add a profile entry.
3. Add tests with positive, negative, and not-applicable fixtures.
4. Only add a Python analyzer when regex cannot express framework semantics; register it on the
   control and test it independently.

To add an agent:

1. Confirm the vendor's documented skill location.
2. Add an installer destination and test it.
3. Keep the core frontmatter portable.
4. Add optional templates only for features the vendor documents.
5. Do not claim live runtime verification without executing that agent.
