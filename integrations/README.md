# Agent integrations

SecureFlow core is agent-independent. The same `skill/secureflow` directory is installed
for every supported agent. Integration files in this directory are optional and are never
written into agent configuration by the installer.

| Agent | Installer ID | Project destination | User destination |
| --- | --- | --- | --- |
| OpenCode | `opencode` | `.opencode/skills/secureflow` | `~/.config/opencode/skills/secureflow` |
| Claude Code | `claude-code` | `.claude/skills/secureflow` | `~/.claude/skills/secureflow` |
| OpenAI Codex | `codex` | `.agents/skills/secureflow` | `~/.agents/skills/secureflow` |
| Cursor | `cursor` | `.cursor/skills/secureflow` | `~/.cursor/skills/secureflow` |
| GitHub Copilot | `copilot` | `.github/skills/secureflow` | `~/.copilot/skills/secureflow` |

Installation paths are based on the vendors' published documentation and are covered by the
installer tests. Live discovery and invocation inside each agent were not automated in this
release candidate; verify the skill appears in your installed agent version before relying on
implicit invocation.

## Install

From the repository root:

```bash
python integrations/install.py --agent opencode --scope project --project-dir .
python integrations/install.py --agent claude-code --scope project --project-dir .
python integrations/install.py --agent codex --scope project --project-dir .
python integrations/install.py --agent cursor --scope project --project-dir .
python integrations/install.py --agent copilot --scope project --project-dir .
```

Or install for every supported agent:

```bash
python integrations/install.py --agent all --scope project --project-dir .
```

Use `--scope user` for a per-user installation, `--force` to replace an existing copy, and
`--dry-run` to inspect destinations. `--symlink` is supported where the operating system
allows directory links; otherwise use the default copy mode.

The installer copies the entire skill, validates the installed `SKILL.md`, and writes
`.secureflow-install.json` inside copied installations. It never edits `opencode.json`,
`.claude/settings.json`, Cursor settings, or Copilot organization settings.

## Optional files

- `opencode/permission-snippet.json` — example permission entry. Merge it into your OpenCode
  configuration only if your version supports skill permissions.
- `codex/agents/openai.yaml` — optional Codex interface metadata. Copy it to
  `<installed-skill>/agents/openai.yaml` if you want a display name and default prompt.
- `cursor/secureflow.mdc` — optional Cursor rule that points the agent at the installed skill.
  Copy it to `.cursor/rules/secureflow.mdc`.
- `copilot/secureflow.instructions.md` — optional path-specific instructions. Copy it to
  `.github/instructions/secureflow.instructions.md`.
- `copilot/secureflow.prompt.md` — optional reusable prompt file. Copy it to
  `.github/prompts/secureflow.prompt.md`.
- `claude-code/README.md` — Claude Code-specific invocation notes. No hook is required.
- `github-actions/secureflow.yml` — CI workflow that runs the deterministic gate.

These optional files are templates, not automatically tested behavior. They do not expand the
gate's compatibility claims.

## Invocation

Use the agent's normal skill invocation mechanism. Examples include `$secureflow` in Codex,
`/secureflow` in Claude Code and Cursor, and the skill picker in OpenCode. When implicit
invocation is unavailable, mention the skill by name and point the agent at the installed
directory.

The gate itself is invoked directly and does not depend on the agent:

```bash
python .opencode/skills/secureflow/scripts/secureflow-gate.py scan --root . --report secureflow-report.json
```
