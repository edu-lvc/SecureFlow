---
mode: agent
description: Run the SecureFlow security workflow for this change.
---

Use the installed `secureflow` skill for this task.

1. State the scope, assets, trust boundaries, and attacker-controlled inputs.
2. List the applicable security requirements and the evidence needed to prove each one.
3. Implement or review the change with the baseline controls: input validation,
   authentication, authorization, secrets management, and injection prevention.
4. Run the gate and inspect every finding and unverified control.
5. Report confirmed controls with file paths and lines, contradictions, residual risk, and
   remaining work. Never state that the application is secure.
