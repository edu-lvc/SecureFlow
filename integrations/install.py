#!/usr/bin/env python3
"""Install the SecureFlow Agent Skill for supported coding agents.

The installer copies (or links) the complete skill directory. It never edits
agent configuration files: permissions, hooks, and instruction files are
opt-in templates under this directory.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "skill" / "secureflow"
MARKER = ".secureflow-install.json"
VERSION = "0.1.0"

AGENTS = ("opencode", "claude-code", "codex", "cursor", "copilot")

PROJECT_PATHS = {
    "opencode": ".opencode/skills/secureflow",
    "claude-code": ".claude/skills/secureflow",
    "codex": ".agents/skills/secureflow",
    "cursor": ".cursor/skills/secureflow",
    "copilot": ".github/skills/secureflow",
}

USER_PATHS = {
    "opencode": ".config/opencode/skills/secureflow",
    "claude-code": ".claude/skills/secureflow",
    "codex": ".agents/skills/secureflow",
    "cursor": ".cursor/skills/secureflow",
    "copilot": ".copilot/skills/secureflow",
}

EXCLUDED_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", "bin", "obj", ".git", "build", "dist", ".venv"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".egg-info")


class InstallError(RuntimeError):
    pass


def validate_source() -> None:
    skill_file = SOURCE / "SKILL.md"
    if not skill_file.is_file():
        raise InstallError("Source skill not found: %s" % skill_file)
    text = skill_file.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise InstallError("SKILL.md has no YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise InstallError("SKILL.md frontmatter is not closed")
    frontmatter = text[4:end]
    if "name: secureflow" not in frontmatter:
        raise InstallError("SKILL.md name must be secureflow")
    if "description:" not in frontmatter:
        raise InstallError("SKILL.md description is required")


def validate_installed(destination: Path) -> None:
    skill_file = destination / "SKILL.md"
    if not skill_file.is_file():
        raise InstallError("Installed skill is missing SKILL.md: %s" % skill_file)
    text = skill_file.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "name: secureflow" not in text[:2000]:
        raise InstallError("Installed SKILL.md failed validation: %s" % skill_file)


def destination_for(agent: str, scope: str, project_dir: Path, home: Path) -> Path:
    relative = PROJECT_PATHS[agent] if scope == "project" else USER_PATHS[agent]
    base = project_dir if scope == "project" else home
    return (base / relative).resolve()


def _ignore(_directory: str, names: List[str]) -> List[str]:
    return [
        name
        for name in names
        if name in EXCLUDED_NAMES or name.endswith(EXCLUDED_SUFFIXES)
    ]


def copy_skill(destination: Path) -> None:
    shutil.copytree(str(SOURCE), str(destination), ignore=_ignore)


def install_one(
    agent: str,
    scope: str,
    project_dir: Path,
    home: Path,
    mode: str,
    force: bool,
    dry_run: bool = False,
) -> Path:
    destination = destination_for(agent, scope, project_dir, home)
    if destination.exists() or destination.is_symlink():
        if not force:
            raise InstallError(
                "Destination already exists: %s (use --force to replace it)" % destination
            )
    if dry_run:
        return destination

    if force and (destination.exists() or destination.is_symlink()):
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        else:
            shutil.rmtree(str(destination))

    destination.parent.mkdir(parents=True, exist_ok=True)
    if mode == "symlink":
        try:
            os.symlink(str(SOURCE), str(destination), target_is_directory=True)
        except OSError as exc:
            raise InstallError(
                "Could not create a directory symlink at %s: %s. "
                "Use --copy on platforms that require elevated privileges." % (destination, exc)
            ) from exc
    else:
        copy_skill(destination)

    validate_installed(destination)
    if mode == "copy":
        marker = {
            "schema_version": "secureflow.install/v1",
            "tool": "secureflow",
            "version": VERSION,
            "agent": agent,
            "scope": scope,
            "mode": mode,
            "installed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "source": str(SOURCE),
        }
        (destination / MARKER).write_text(
            json.dumps(marker, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install the SecureFlow skill for AI coding agents.",
    )
    parser.add_argument("--agent", choices=list(AGENTS) + ["all"], required=True)
    parser.add_argument("--scope", choices=("project", "user"), default="project")
    parser.add_argument("--project-dir", default=".", help="Project root for project scope")
    parser.add_argument("--copy", action="store_true", help="Copy the skill (default)")
    parser.add_argument("--symlink", action="store_true", help="Create a directory symlink")
    parser.add_argument("--force", action="store_true", help="Replace an existing installation")
    parser.add_argument("--dry-run", action="store_true", help="Print destinations without writing")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.copy and args.symlink:
        parser.error("choose either --copy or --symlink")
    mode = "symlink" if args.symlink else "copy"
    project_dir = Path(args.project_dir).resolve()
    home = Path(os.environ.get("SECUREFLOW_HOME", str(Path.home()))).resolve()

    if args.scope == "project" and not project_dir.is_dir():
        print("install.py: project directory not found: %s" % project_dir, file=sys.stderr)
        return 3

    agents: List[str]
    if args.agent == "all":
        agents = list(AGENTS)
    else:
        agents = [args.agent]

    try:
        validate_source()
        destinations: List[Tuple[str, Path]] = []
        for agent in agents:
            destination = destination_for(agent, args.scope, project_dir, home)
            if (destination.exists() or destination.is_symlink()) and not args.force:
                raise InstallError(
                    "Destination already exists: %s (use --force to replace it)" % destination
                )
            destinations.append((agent, destination))

        for agent, destination in destinations:
            install_one(
                agent=agent,
                scope=args.scope,
                project_dir=project_dir,
                home=home,
                mode=mode,
                force=args.force,
                dry_run=args.dry_run,
            )
            action = "Would install" if args.dry_run else "Installed"
            print("%s %s for %s: %s" % (action, "symlink" if mode == "symlink" else "skill", agent, destination))
    except (InstallError, OSError) as exc:
        print("install.py: %s" % exc, file=sys.stderr)
        return 3

    if not args.dry_run:
        print("")
        print("Next steps:")
        print("1. Open the project in the agent and invoke the secureflow skill.")
        print("2. Review the optional templates in integrations/ for permissions and instructions.")
        print("3. Run the gate: python skill/secureflow/scripts/secureflow-gate.py scan --root <project>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
