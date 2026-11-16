---
applyTo: "**"
---

# SecureFlow instructions for GitHub Copilot

When a change touches input validation, authentication, authorization, secrets, SQL, shell
commands, or release configuration, use the installed `secureflow` skill.

Required behavior:

- Identify assets, trust boundaries, and abuse cases before implementation.
- Write testable security requirements and map them to evidence.
- Prefer framework security primitives and deny-by-default authorization.
- Never place credentials in source, fixtures, examples, or CI configuration.
- Run the deterministic gate when the project uses the supported C#/ASP.NET Core profile.
- Do not claim a control passes without a path, line, and code snippet. Missing evidence is
  `UNVERIFIED`.
