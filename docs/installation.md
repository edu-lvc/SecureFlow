# Installation

## Requirements

- **Gate:** Python 3.9 or newer. No third-party Python packages are required.
- **C# reference examples and `--build` adapter:** .NET SDK 10.0 or newer.
- **Skill:** file read/write access and command execution in the target agent.

## 1. Get the repository

Clone or copy this repository to a local directory. The examples below assume the repository
root is the current directory.

## 2. Install the skill into a project

The installer copies the complete skill tree and validates the installed `SKILL.md`.

```bash
# OpenCode
python integrations/install.py --agent opencode --scope project --project-dir /path/to/project

# Claude Code
python integrations/install.py --agent claude-code --scope project --project-dir /path/to/project

# OpenAI Codex
python integrations/install.py --agent codex --scope project --project-dir /path/to/project

# Cursor
python integrations/install.py --agent cursor --scope project --project-dir /path/to/project

# GitHub Copilot
python integrations/install.py --agent copilot --scope project --project-dir /path/to/project
```

Install for every supported agent at once:

```bash
python integrations/install.py --agent all --scope project --project-dir /path/to/project
```

Windows PowerShell:

```powershell
python integrations\install.py --agent opencode --scope project --project-dir C:\path\to\project
```

### Destinations

| Agent | Project scope | User scope |
| --- | --- | --- |
| OpenCode | `.opencode/skills/secureflow` | `~/.config/opencode/skills/secureflow` |
| Claude Code | `.claude/skills/secureflow` | `~/.claude/skills/secureflow` |
| Codex | `.agents/skills/secureflow` | `~/.agents/skills/secureflow` |
| Cursor | `.cursor/skills/secureflow` | `~/.cursor/skills/secureflow` |
| Copilot | `.github/skills/secureflow` | `~/.copilot/skills/secureflow` |

Install for the current user instead of a project:

```bash
python integrations/install.py --agent claude-code --scope user
```

Useful installer options:

```text
--copy       Copy the skill (default)
--symlink    Create a directory symlink where the OS permits it
--force      Replace an existing installation
--dry-run    Print intended destinations without writing
```

The installer never edits agent configuration files. It writes
`.secureflow-install.json` inside copied installations with version, agent, scope, mode, source,
and installation time. Symlink installations do not add a marker to the source tree.

## 3. Optional agent templates

These files are optional. Review the vendor documentation for your installed version before
using them.

```bash
# OpenCode: merge the snippet into your config, then reload.
cat integrations/opencode/permission-snippet.json

# Codex: optional interface metadata
cp integrations/codex/agents/openai.yaml /path/to/project/.agents/skills/secureflow/agents/openai.yaml

# Cursor: optional rule
mkdir -p /path/to/project/.cursor/rules
cp integrations/cursor/secureflow.mdc /path/to/project/.cursor/rules/secureflow.mdc

# Copilot: optional instructions and prompt
mkdir -p /path/to/project/.github/instructions /path/to/project/.github/prompts
cp integrations/copilot/secureflow.instructions.md /path/to/project/.github/instructions/
cp integrations/copilot/secureflow.prompt.md /path/to/project/.github/prompts/
```

Claude Code needs no additional file; read `integrations/claude-code/README.md` only if your
organization restricts command execution.

## 4. Run the gate

From the repository that contains the copy:

```bash
python .opencode/skills/secureflow/scripts/secureflow-gate.py scan \
  --root . \
  --profile csharp-aspnetcore \
  --report secureflow-report.json \
  --markdown secureflow-report.md
```

Replace `.opencode` with the destination for your agent. You can also run the gate directly
from this repository without installing the skill:

```bash
python skill/secureflow/scripts/secureflow-gate.py scan \
  --root examples/csharp-secure/SecureOrders.Api
```

### Optional Python package

The gate can also be installed as a console script:

```bash
python -m pip install .
secureflow-gate version
```

The installer is not required for the package. If you use only the copied skill, skip this step.

## 5. Verify the installation

Check that the skill file exists and starts with portable frontmatter:

```bash
python -c "from pathlib import Path; p=Path('/path/to/project/.opencode/skills/secureflow/SKILL.md'); t=p.read_text(encoding='utf-8'); print(t.splitlines()[0], t.splitlines()[1])"
```

Expected output begins with `---` and `name: secureflow`.

Run the gate's built-in version command from the installed copy:

```bash
python /path/to/project/.opencode/skills/secureflow/scripts/secureflow-gate.py version
```

## Compatibility status

The installation paths above follow the vendors' published Agent Skills documentation, and the
installer destinations are covered by automated tests. Live discovery and invocation inside
each agent application were not automated for this release candidate. Verify that the skill is
listed by your installed agent version before relying on implicit invocation.

## Uninstallation

Remove the installed skill directory for the relevant agent:

```bash
rm -rf /path/to/project/.opencode/skills/secureflow
```

On Windows PowerShell:

```powershell
Remove-Item -Recurse -Force C:\path\to\project\.opencode\skills\secureflow
```

The installer does not modify agent configuration, so there is no other state to remove.
