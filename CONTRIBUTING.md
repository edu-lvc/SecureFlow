# Contributing to SecureFlow

SecureFlow is an Agent Skill plus a deterministic verification gate. Contributions are welcome
when they improve secure-development behavior, verification accuracy, portability, or evidence
quality.

## Before you start

- Read [Architecture](docs/architecture.md), [Known limitations](docs/limitations.md), and the
  [Agent Skills specification](https://agentskills.io/specification).
- Check existing issues and tests before adding a new rule.
- Keep changes focused. Do not mix refactors, new controls, and documentation rewrites in one
  pull request.
- All source code, Markdown, comments, fixtures, and commit messages must be in English.

## Development environment

Requirements:

- Python 3.9 or newer (the gate uses only the standard library).
- .NET SDK 10.0 or newer to build the example applications.
- Optional: an Agent Skills-compatible agent for manual invocation testing.

Run the full suite from the repository root:

```bash
python -m unittest discover -s tests -v
python tests/ci_gate_smoke.py
```

Build the reference applications:

```bash
dotnet build examples/csharp-secure/SecureOrders.Api/SecureOrders.Api.csproj --nologo
dotnet build examples/csharp-vulnerable/VulnerableOrders.Api/VulnerableOrders.Api.csproj --nologo
```

Test package installation in an isolated environment:

```bash
python -m venv .venv-package
.venv-package/Scripts/python -m pip install .
.venv-package/Scripts/secureflow-gate version
```

On Linux or macOS, use `.venv-package/bin/python` and `.venv-package/bin/secureflow-gate`.

## Repository layout

| Path | Purpose |
| --- | --- |
| `skill/secureflow/SKILL.md` | Portable skill entry point. Keep it under 500 lines. |
| `skill/secureflow/references/` | On-demand guidance loaded by the agent. |
| `skill/secureflow/assets/` | Copies of threat-model, claims, policy, and report templates. |
| `skill/secureflow/scripts/secureflow_gate/` | Python gate package. |
| `examples/` | Buildable secure and intentionally vulnerable ASP.NET Core applications. |
| `integrations/` | Installer and optional agent-specific templates. |
| `tests/` | Standard-library `unittest` suite and fixtures. |
| `docs/` | Architecture, installation, usage, testing, research, limitations, and roadmap. |

## Adding or changing a rule

1. Choose the owning control: `input-validation`, `authentication`, `authorization`,
   `secrets-management`, or `injection-prevention`.
2. Add the rule to the appropriate pack in
   `skill/secureflow/scripts/secureflow_gate/rulepacks/`.
3. Include a unique `SF-<AREA>-<NNN>` ID, severity, confidence, message, remediation, and at
   least one CWE, ASVS, and OWASP Top 10 mapping.
4. Add a positive fixture and a negative fixture. A rule without both is not complete.
5. Add a test that asserts the expected status and rule ID.
6. Update `references/controls.md` if the control contract changes.
7. Run the gate against both examples. A new rule must not cause the secure example to fail
   unless the secure example is genuinely wrong.

Regex rules are line-oriented and must remain bounded. Avoid catastrophic backtracking. Prefer
an analyzer for framework semantics that a regex cannot express safely.

## Adding an analyzer

Analyzers are Python functions registered on a control definition. They must:

- read from the scanned file model, never execute target code;
- mask comments and string contents before making structural decisions;
- return a `ControlOutcome` with explicit checks and findings;
- use `UNVERIFIED` when evidence is ambiguous rather than assuming safety;
- set `rule_ids` on checks so policy suppression and aggregation work correctly;
- include a docstring and comments explaining the security decision.

Add parser tests separately from analyzer tests. Parser bugs are a common source of false
negatives.

## Extending to another ecosystem

A new language can start as a rule-only pack:

1. Copy the pack structure from `csharp-aspnetcore.json`.
2. Define controls and include globs.
3. Add regex rules for secrets, dangerous sinks, and insecure configuration.
4. Register the profile in `rules.py`.
5. Add positive, negative, and not-applicable fixtures.
6. Document the new profile as experimental until it has the same test depth as C#.

Do not claim full support for an ecosystem based on a rule-only pack.

## Testing standards

- Use `unittest`, not third-party test frameworks.
- Use temporary directories for filesystem tests. Never write into the repository during a test.
- Test all four statuses: `PASS`, `FAIL`, `UNVERIFIED`, `NOT_APPLICABLE`.
- Test false-positive allowlists and false-negative review paths.
- Test report tampering, missing files, added files, and invalid hashes.
- Test exit codes `0`, `1`, `2`, `3`, and `4`.
- Keep tests deterministic: no network access, no wall-clock dependencies, no fixed absolute
  paths outside temporary directories.
- On Windows, use `pathlib` and forward-slash report paths; do not depend on a POSIX shell.

## Documentation standards

- Write in English and use present tense.
- Distinguish verified behavior from intended behavior.
- State compatibility per agent. Do not imply that a vendor integration was executed if it was
  only installed and inspected.
- Do not call an application "secure". Name the controls that passed, the evidence, and the
  controls that remain unverified.
- Update `CHANGELOG.md` for user-visible changes.

## Security reports

Do not open a public issue for a vulnerability in SecureFlow itself. Follow
[SECURITY.md](SECURITY.md).

If a test fixture needs a credential-like value, use an obvious synthetic value and document it.
Never commit a real secret, token, private key, or connection string. If a real secret is
committed by mistake, rotate it first; removing the file is not sufficient.

## Pull request checklist

- [ ] The change has a focused purpose and an English description.
- [ ] `python -m unittest discover -s tests -v` passes.
- [ ] `python tests/ci_gate_smoke.py` passes.
- [ ] Both example applications build, if the change affects C# parsing or examples.
- [ ] New rules have positive and negative tests.
- [ ] New statuses or exit codes are documented.
- [ ] Documentation matches actual behavior.
- [ ] No real secrets, personal data, or generated build artifacts are included.
- [ ] Compatibility claims are accurate and scoped.

## License

By contributing, you agree that your contribution is licensed under the MIT License. See
[LICENSE](LICENSE).
