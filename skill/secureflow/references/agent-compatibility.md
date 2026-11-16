# Agent Compatibility

SecureFlow follows the open Agent Skills specification. `SKILL.md` uses only portable
frontmatter fields: `name`, `description`, `license`, `compatibility`, and `metadata`. No agent
specific hooks, dynamic command injection, or tool permissions are required by the core skill.

The installer copies the same skill tree to the location each agent documents. Agent-specific
templates are optional and live in `integrations/`.

## Compatibility summary

| Agent | Project location | User location | Invocation | Status |
| --- | --- | --- | --- | --- |
| OpenCode | `.opencode/skills/secureflow` | `~/.config/opencode/skills/secureflow` | Skill tool; description-based or explicit skill selection | Layout and installer tested; live invocation documented, not covered by automated tests |
| Claude Code | `.claude/skills/secureflow` | `~/.claude/skills/secureflow` | `/secureflow` or model invocation from description | Layout and installer tested; live invocation documented, not covered by automated tests |
| OpenAI Codex | `.agents/skills/secureflow` | `~/.agents/skills/secureflow` | `$secureflow`, `/skills`, or implicit invocation | Layout and installer tested; live invocation documented, not covered by automated tests |
| Cursor | `.agents/skills/secureflow` or `.cursor/skills/secureflow` | `~/.agents/skills/secureflow` or `~/.cursor/skills/secureflow` | `/secureflow` or description-based | Layout and installer tested for `.agents`; `.cursor` location documented |
| GitHub Copilot | `.github/skills/secureflow` | `~/.copilot/skills/secureflow` | Agent mode skill invocation; version dependent | Layout and installer tested; live invocation documented, not covered by automated tests |

"Installer tested" means the automated test suite copies the skill to the documented destination
and validates the installed `SKILL.md`. It does not mean the agent's runtime was launched and the
model was observed invoking the skill. Compatibility claims are limited accordingly.

## Portable metadata

`SKILL.md` frontmatter:

```yaml
name: secureflow
description: ...
license: MIT
compatibility: ...
metadata:
  version: "0.1.0"
```

- `name` matches the parent directory `secureflow`.
- `description` is under 1024 characters and states what the skill does and when to use it.
- `compatibility` is under 500 characters.
- No `allowed-tools`, `hooks`, `context`, `model`, or agent-specific keys.

This keeps the skill loadable by any implementation of the specification.

## OpenCode

Official locations:

- Project: `.opencode/skills/<name>/SKILL.md`
- Global: `~/.config/opencode/skills/<name>/SKILL.md`
- OpenCode also discovers `.claude/skills` and `.agents/skills`.

Install:

```bash
python integrations/install.py --agent opencode --scope project --project-dir .
```

Optional permission snippet for `opencode.json` (verify against your OpenCode version):

```json
{
  "permission": {
    "skill": {
      "secureflow": "allow"
    }
  }
}
```

OpenCode's skill discovery is path-based. Avoid duplicate IDs in multiple loaded locations. The
skill does not depend on OpenCode-specific `metadata.opencode` keys.

## Claude Code

Official locations:

- Project: `.claude/skills/<name>/SKILL.md`
- Personal: `~/.claude/skills/<name>/SKILL.md`
- Enterprise: managed `.claude/skills`

Install:

```bash
python integrations/install.py --agent claude-code --scope project --project-dir .
```

Claude Code supports additional frontmatter and hooks, but SecureFlow does not use them. This
avoids breaking other agents and avoids relying on a feature that may change. Invoke with
`/secureflow` or let the model select it from the description.

## OpenAI Codex

Official locations:

- Repository: `.agents/skills/<name>/SKILL.md` discovered from the current directory up to the
  repository root.
- User: `~/.agents/skills/<name>/SKILL.md`.
- Admin/system locations are managed by the organization.

Install:

```bash
python integrations/install.py --agent codex --scope project --project-dir .
```

The optional `agents/openai.yaml` in this repository is a template for Codex interface metadata.
It is not required for the skill to load. Use `/skills` or `$secureflow` for explicit invocation.
Codex's initial skill list has a context budget; keep the description focused, as this skill does.

## Cursor

Official locations:

- Project: `.agents/skills/<name>/SKILL.md` or `.cursor/skills/<name>/SKILL.md`.
- User: `~/.agents/skills/<name>/SKILL.md` or `~/.cursor/skills/<name>/SKILL.md`.
- Cursor also loads some Claude and Codex skill locations for compatibility.

Install (defaults to `.agents`, which is shared with Codex):

```bash
python integrations/install.py --agent cursor --scope project --project-dir .
```

To use `.cursor/skills`, copy the `skill/secureflow` directory there manually or adapt the
installer. The optional rule in `integrations/cursor/secureflow.mdc` can reinforce the workflow
in Cursor, but it is not required and is not a substitute for the skill.

## GitHub Copilot

Official locations:

- Project: `.github/skills/<name>/SKILL.md`, with compatibility loading from `.claude/skills` and
  `.agents/skills`.
- Personal: `~/.copilot/skills/<name>/SKILL.md` and `~/.agents/skills/<name>/SKILL.md`.
- Cloud agent: `.copilot/skills` in the dotfiles repository.

Install:

```bash
python integrations/install.py --agent copilot --scope project --project-dir .
```

Copilot support for agent skills varies by product and version. The installer verifies the file
layout only. The optional `integrations/copilot/secureflow.instructions.md` can be copied to
`.github/instructions/` for repositories that use path-specific instructions.

## Feature support is not assumed

| Capability | OpenCode | Claude Code | Codex | Cursor | Copilot |
| --- | --- | --- | --- | --- | --- |
| Agent Skills directory | Yes | Yes | Yes | Yes | Yes, version dependent |
| Model auto-invocation from description | Yes | Yes | Yes | Yes | Yes, version dependent |
| Explicit invocation | Skill tool | `/skill` | `$skill` / `/skills` | `/skill` | Agent UI, version dependent |
| Skill permissions | Yes | Yes | Policy/config | Rules/permissions | Product settings |
| Hooks used by SecureFlow | No | No | No | No | No |
| Core gate requires agent features | No | No | No | No | No |

The gate is a Python CLI. Any agent that can execute a command can use it, even if it does not
support skills.

## Installation validation

The installer writes `.secureflow-install.json` with the source version, agent, scope, and
destination. It refuses to overwrite a non-empty destination unless `--force` is provided. After
copying, it parses and validates the installed `SKILL.md` name, description, and structure.

The test suite covers:

- Project and user destinations for all five agents.
- Idempotent reinstall.
- Overwrite refusal and forced overwrite.
- Skill validation after copy.
- Markers.

It does not cover live agent discovery, model behavior, or product-specific permission syntax.
Those must be verified in the target environment before claiming production compatibility.
