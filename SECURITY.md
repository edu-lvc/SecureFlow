# Security policy

SecureFlow is a security tool, but it is not a guarantee that an application is secure. This
policy covers vulnerabilities in SecureFlow itself and explains how to report them.

## Supported versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes, release candidate |
| Older versions | No |

## Reporting a vulnerability

Do **not** open a public issue for a vulnerability in SecureFlow. Use the repository's private
GitHub Security Advisory feature:

1. Open the repository on GitHub.
2. Select **Security** and then **Advisories**.
3. Create a new draft advisory and include the details below.

If private advisories are unavailable, contact the repository maintainers through the private
contact listed in the repository profile. Do not include exploit details in a public discussion.

Include:

- affected version or commit;
- operating system and Python version;
- the command or skill path involved;
- a minimal reproduction, if safe to share;
- impact: what an attacker could read, change, execute, or bypass;
- whether the issue is in the skill guidance, the gate engine, a rule pack, the installer, or an
  example application;
- any suggested fix or mitigation.

Do not include real credentials, personal data, or third-party system details. Redact secrets
from logs and screenshots.

## Scope

In scope:

- gate bypasses or false `PASS` results caused by parser, rule, policy, claim, or report logic;
- report integrity flaws, including hash or path handling weaknesses;
- path traversal, symlink escape, or unsafe file handling in the scanner or installer;
- unintended execution of target code;
- secret leakage through reports, logs, fixtures, or generated artifacts;
- installer behavior that writes outside its documented destination;
- vulnerabilities in the reference applications that are not intentional (the vulnerable
  application is intentionally insecure and is out of scope).

Out of scope:

- the intentionally vulnerable example application;
- findings that require modifying the scanned repository to defeat a static check, unless they
  bypass the gate's documented trust boundary;
- missing coverage for controls or ecosystems listed in [Known limitations](docs/limitations.md);
- reports that a `PASS` does not prove an application is secure (this is documented);
- third-party dependencies of the example applications, except when SecureFlow pins a known
  vulnerable version;
- social engineering or physical attacks.

## Response process

Maintainers aim to:

1. acknowledge a private report within five business days;
2. reproduce and classify the issue;
3. prepare a fix and regression test;
4. publish an advisory and release notes after a fix is available.

These are best-effort targets for a community project, not a contractual service level.

## Secure use of the gate

- Run the gate on code you are authorized to inspect.
- Do not enable `--build` on untrusted code. The adapter is not a sandbox.
- Treat reports as evidence, not as a security certification.
- Review findings before sharing a report; remove any context that is sensitive to your
  organization.
- Rotate any secret discovered in source or history. Deleting the current file does not remove
  the secret from version control history.

## Disclosure

Please allow maintainers to fix and release before public disclosure. Credit is given in the
advisory unless the reporter requests anonymity.
