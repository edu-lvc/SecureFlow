# Known limitations

SecureFlow is a release candidate. It is designed to make security work visible and repeatable,
not to certify an application as secure. This page lists the boundaries that matter when you
interpret a result.

## Scope of verification

- **Five controls only.** The baseline profile verifies input validation, authentication,
  authorization, secrets management, and injection prevention. It does not verify cryptography,
  session management beyond selected cookie/JWT flags, CSRF, SSRF, deserialization, file upload,
  logging, rate limiting, transport security, business logic, or cloud configuration.
- **C# and ASP.NET Core only.** `csharp-aspnetcore` is the only deeply validated profile. `base`
  is a cross-language secrets and generic-pattern profile, not a framework analyzer. Other
  ecosystems need new rule packs and tests, and should be labeled experimental.
- **Static analysis only by default.** The gate reads files. It does not run the application,
  exercise endpoints, inspect a database, or test runtime policy behavior. A static `PASS` can
  miss a vulnerability that only appears at runtime.
- **Not a vulnerability scanner.** Dependency CVEs, container images, secrets in Git history,
  infrastructure as code, and penetration testing are out of scope.
- **Not a replacement for human review.** High-risk systems still need threat modeling, design
  review, penetration testing, and an accountable security owner.

## Parser and analyzer limits

The C# parser is a masked structural parser, not Roslyn or a full syntax tree. It deliberately
favors predictable behavior over complete language coverage.

Known gaps include:

- Controllers declared as `record` types are not recognized.
- Custom routing frameworks, endpoint filters, dynamic policy providers, generated controllers,
  source generators, and runtime middleware ordering are not modeled.
- `[AllowAnonymous]` mutating endpoints are excluded from the authorization finding and reported
  as a review item. The gate does not decide whether anonymity is appropriate for that endpoint.
- GET-only APIs are reported `UNVERIFIED` for authorization because object-level and
  resource-level authorization cannot be established from route attributes alone.
- Protected endpoints are reported `PASS` for route-level authorization, with an explicit note
  that object-level authorization was not assessed. An endpoint can be protected at the route
  and still leak another user's object through an insecure direct object reference.
- The input-validation analyzer recognizes common mechanisms and attributes, but it can be
  satisfied by a mechanism that is present yet not applied to every endpoint. Manual validation
  combined with global suppression is `UNVERIFIED`, not `PASS`.
- Authentication analysis checks registration, `UseAuthentication`, cookie flags, and selected
  JWT flags. It does not prove that a scheme is correctly configured, that tokens are validated
  against the right issuer and audience, or that account recovery and MFA are safe.
- Secrets detection is pattern-based. It can miss custom credential formats and can flag
  documentation, fixtures, or generated samples. Placeholder allowlists reduce noise but do not
  eliminate false positives.
- Injection analysis recognizes common SQL and process-execution sinks. It does not perform
  data-flow analysis across methods, does not understand every ORM, and may classify an
  unresolved expression as `UNVERIFIED` rather than proving it safe or unsafe.
- Suppressing a finding removes it from the active set and marks the related check `PASS` only
  when every rule ID for that check is suppressed. This is an audited policy decision, not
  evidence that the underlying code is safe.

## Evidence and reporting limits

- A `PASS` means the configured static checks found positive evidence for the detected surface.
  It is not proof of security, correctness, or compliance.
- `UNVERIFIED` is the correct result when evidence is missing or ambiguous. Do not rewrite it as
  `PASS` in a summary.
- The report hash is tamper-evident, not a digital signature. Someone who can rewrite the report
  can recompute the hash. Use artifact signing or protected CI storage when authenticity matters.
- `verify-report` detects changed, missing, and added files under the recorded scan root. It does
  not detect a replaced file with an identical hash (a collision is computationally impractical
  but the guarantee is integrity, not authenticity), and it does not protect the report after
  verification.
- The Markdown report is a rendering of the JSON. The JSON report is the source of truth.
- File inventory skips symlinks, non-regular files, binary files, files larger than 2 MiB,
  common build/dependency/VCS directories, and installed agent-skill directories (such as
  `.opencode`, `.claude`, `.agents`, `.cursor`, and `.github/skills`) to avoid self-scanning.
  Findings in skipped files are not evaluated and the report records skip reasons, but readers
  must check the skipped list.

## Policy and claims limits

- Claims are untrusted annotations. A claim cannot raise a control status, and a `PASS` claim
  against a `FAIL` gate is recorded as an overstated contradiction.
- A claim can still be misleading if its evidence line exists but does not actually implement the
  control. The gate checks location and snippet integrity, not semantic sufficiency.
- Policy suppressions require a reason and an expiry, and suppressed findings remain in the
  report. An expired or malformed suppression is ignored with a warning.
- A policy can hide a real finding from the active set for its lifetime. Use short expiries and
  review the suppressed-findings section.

## Execution and safety limits

- The default scan never executes target code.
- `--build` runs `dotnet build` and is not a sandbox. It can execute MSBuild targets, analyzers,
  and package build scripts from the target repository. Do not enable it on untrusted code.
- The gate does not make network requests, but a build invoked with `--build` may restore
  packages from the network depending on the project and local NuGet cache.
- The optional examples use `Microsoft.Data.Sqlite` and are reference code, not production
  templates. They lack production identity, migrations, rate limiting, observability, and
  deployment hardening.

## Agent compatibility limits

- The installation paths follow each vendor's published Agent Skills documentation. The installer
  and resulting file layout are covered by automated tests.
- **Live discovery and invocation inside OpenCode, Claude Code, OpenAI Codex, Cursor, and GitHub
  Copilot were not automated for this release.** Agent versions change; verify that the skill is
  listed by your installed version before relying on implicit invocation or permissions.
- Agent-specific templates are optional and may need adjustment for your installed version.
- The core skill assumes file read/write and command execution. An agent that cannot execute the
  gate cannot produce gate evidence; the resulting control status is `UNVERIFIED`, not `PASS`.

## Platform limits

- Local validation was performed on Windows with Python 3.12.10. The CI workflow covers Windows
  and Ubuntu with Python 3.9 and 3.12, but the hosted workflow was not executed during local
  release preparation.
- Symlink installation depends on operating-system privileges and developer mode. Use `--copy`
  when symlinks are unavailable.
- Paths are normalized to forward slashes in reports. Case sensitivity follows the host
  filesystem.
- The parser targets modern ASP.NET Core patterns. Older `Startup.cs`-only applications may be
  partially analyzed and should be reviewed manually.

## What would change a result

A control can move from `PASS` to `FAIL` or `UNVERIFIED` when:

- a new file introduces a dangerous sink or a hardcoded credential;
- an endpoint attribute or fallback policy changes;
- a rule pack or analyzer is updated;
- a policy suppression expires;
- the report is verified against a different root;
- the project uses a construct the parser does not understand.

Treat the report as a snapshot bound to the inventory hash, not as a permanent property of the
repository.

## Reporting a limitation

If a limitation causes a false `PASS`, treat it as a security issue in SecureFlow and follow
[SECURITY.md](../SECURITY.md). If it causes noise or a false `FAIL`, open a regular issue with a
minimal fixture and the expected result.
