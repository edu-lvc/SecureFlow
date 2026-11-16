# Claude Code notes

Claude Code discovers the installed skill at `.claude/skills/secureflow` (project) or
`~/.claude/skills/secureflow` (user). No Claude-specific hook is required for the core
workflow.

- Invoke the skill with `/secureflow` or by asking for a security review that matches its
  description.
- Claude Code supports additional frontmatter fields that other agents do not. SecureFlow
  deliberately ships only portable fields (`name`, `description`, `license`, `compatibility`,
  `metadata`) so the same directory remains usable everywhere.
- If your organization restricts command execution, allow the gate script explicitly in your
  Claude Code permission policy. SecureFlow does not install or modify that policy.
- The optional `--build` gate adapter runs `dotnet build`. Enable it only in an environment
  where compiling the target repository is acceptable.

The installer and file layout are tested. Live Claude Code discovery and prompt invocation were
not automated in this release candidate.
