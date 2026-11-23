"""Control analyzers for the C# / ASP.NET Core profile.

Analyzers combine the small framework parser with conservative text checks. They
never execute target code and they never upgrade an unproven control to PASS.
Every check carries rule identifiers so policy suppressions can be applied after
analysis without losing the original evidence.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .csharp import (
    CSharpModel,
    Endpoint,
    argument_ranges,
    call_open,
    evidence_at,
    expression_constant_string,
    expression_dynamic,
    expression_identifier,
    first_argument,
    mask_csharp,
    matching_paren,
    statement_end,
)
from .model import Check, ControlOutcome, Evidence, Finding, ScanFile, Status, snippet_hash
from .rules import Rule


def _first(values: Iterable[Evidence]) -> Optional[Evidence]:
    for value in values:
        return value
    return None


def _check(
    check_id: str,
    title: str,
    status: Status,
    detail: str,
    evidence: Sequence[Evidence] = (),
    rule_ids: Sequence[str] = (),
) -> Check:
    return Check(
        id=check_id,
        title=title,
        status=status,
        detail=detail,
        evidence=list(evidence),
        rule_ids=list(rule_ids),
    )


def _finding(
    rule: Rule,
    evidence: Evidence,
    message: str,
    result: Optional[Status] = None,
) -> Finding:
    return Finding(
        rule_id=rule.id,
        control=rule.control,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        result=result or (Status.FAIL if rule.mode == "finding" else Status.UNVERIFIED),
        message=message,
        remediation=rule.remediation,
        cwe=list(rule.cwe),
        asvs=list(rule.asvs),
        owasp=list(rule.owasp),
        mitre_attack=list(rule.mitre_attack),
        telemetry_sources=list(rule.telemetry_sources),
        evidence=evidence,
    )


def _status(findings: Sequence[Finding], checks: Sequence[Check], surface: bool) -> Status:
    if any(finding.result == Status.FAIL for finding in findings):
        return Status.FAIL
    if any(finding.result == Status.UNVERIFIED for finding in findings):
        return Status.UNVERIFIED
    if not surface:
        return Status.NOT_APPLICABLE
    if all(check.status in (Status.PASS, Status.NOT_APPLICABLE) for check in checks):
        return Status.PASS
    if any(check.status == Status.FAIL for check in checks):
        return Status.FAIL
    return Status.UNVERIFIED


def analyze_input_validation(model: CSharpModel, rules: Dict[str, Rule]) -> ControlOutcome:
    rule = rules.get("SF-VAL-001")
    findings: List[Finding] = []
    checks: List[Check] = []

    mechanism_evidence = _first(
        evidence
        for name in sorted(model.validation_mechanisms)
        for evidence in model.validation_mechanisms[name]
    )
    attribute_evidence = _first(model.validation_attributes)
    suppress_evidence = _first(model.suppress_validation)
    manual_evidence = _first(model.manual_validation)
    surface = bool(model.endpoints or model.mvc_surface or model.validation_mechanisms)

    if not surface:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No HTTP endpoints or MVC validation surface was found.",
            checks=[
                _check(
                    "input-validation-surface",
                    "Validation surface",
                    Status.NOT_APPLICABLE,
                    "No request models or endpoints were detected.",
                )
            ],
        )

    if suppress_evidence and not manual_evidence and rule is not None:
        findings.append(
            _finding(
                rule,
                suppress_evidence,
                "Global model validation was disabled. Request models can reach actions without validation.",
            )
        )

    if suppress_evidence and not manual_evidence:
        checks.append(
            _check(
                "validation-active",
                "Automatic request validation",
                Status.FAIL,
                "Automatic model validation is suppressed and no manual validation call was found.",
                [suppress_evidence] if suppress_evidence else [],
                [rule.id] if rule is not None else [],
            )
        )
    elif suppress_evidence and manual_evidence:
        checks.append(
            _check(
                "validation-active",
                "Automatic request validation",
                Status.UNVERIFIED,
                "Automatic validation is disabled. Manual validation exists but full endpoint coverage is not proven.",
                [suppress_evidence, manual_evidence],
                [rule.id] if rule is not None else [],
            )
        )
    elif mechanism_evidence:
        checks.append(
            _check(
                "validation-active",
                "Request validation mechanism",
                Status.PASS,
                "A request validation mechanism is configured.",
                [mechanism_evidence],
                [rule.id] if rule is not None else [],
            )
        )
    elif attribute_evidence:
        checks.append(
            _check(
                "validation-active",
                "Request validation mechanism",
                Status.UNVERIFIED,
                "Validation attributes are present, but no enforcement mechanism was proven.",
                [attribute_evidence],
                [rule.id] if rule is not None else [],
            )
        )
    else:
        checks.append(
            _check(
                "validation-active",
                "Request validation mechanism",
                Status.UNVERIFIED,
                "Endpoints are present but no input validation mechanism was detected.",
                [],
                [rule.id] if rule is not None else [],
            )
        )

    status = _status(findings, checks, surface)
    reason = {
        Status.FAIL: "Request input validation is bypassed.",
        Status.UNVERIFIED: "Request validation is not proven for every endpoint.",
        Status.PASS: "A request validation mechanism is configured and active.",
        Status.NOT_APPLICABLE: "No request validation surface was found.",
    }[status]
    return ControlOutcome(status=status, reason=reason, checks=checks, findings=findings)


def analyze_authentication(model: CSharpModel, rules: Dict[str, Rule]) -> ControlOutcome:
    findings: List[Finding] = []
    checks: List[Check] = []
    surface = bool(model.endpoints or model.mvc_surface)

    if not surface:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No authentication configuration or protected surface was found.",
            checks=[
                _check(
                    "authentication-surface",
                    "Authentication surface",
                    Status.NOT_APPLICABLE,
                    "No authentication configuration was detected.",
                )
            ],
        )

    auth_rule = rules.get("SF-AUTH-001")
    if model.has_auth_config:
        first_config = _first(model.auth_config)
        first_use = _first(model.use_authentication)
        if model.use_authentication:
            checks.append(
                _check(
                    "authentication-middleware",
                    "Authentication middleware",
                    Status.PASS,
                    "Authentication is registered and the authentication middleware is invoked.",
                    [first_config, first_use],
                    [auth_rule.id] if auth_rule is not None else [],
                )
            )
        else:
            if auth_rule is not None and first_config is not None:
                findings.append(
                    _finding(
                        auth_rule,
                        first_config,
                        "Authentication is registered but UseAuthentication is missing, so the request pipeline never authenticates users.",
                    )
                )
            checks.append(
                _check(
                    "authentication-middleware",
                    "Authentication middleware",
                    Status.FAIL,
                    "Authentication is registered but UseAuthentication is missing.",
                    [first_config] if first_config else [],
                    [auth_rule.id] if auth_rule is not None else [],
                )
            )
    else:
        checks.append(
            _check(
                "authentication-middleware",
                "Authentication middleware",
                Status.UNVERIFIED,
                "Endpoints exist but no authentication scheme was detected.",
                [],
                [auth_rule.id] if auth_rule is not None else [],
            )
        )

    if model.has_auth_config:
        if model.has_auth_scheme:
            checks.append(
                _check(
                    "authentication-scheme",
                    "Authentication scheme",
                    Status.PASS,
                    "A recognized authentication scheme is registered.",
                    [model.auth_scheme[0]],
                    [],
                )
            )
        else:
            checks.append(
                _check(
                    "authentication-scheme",
                    "Authentication scheme",
                    Status.UNVERIFIED,
                    "Authentication is registered, but no recognized default or handler scheme was detected.",
                    [model.auth_config[0]],
                    [],
                )
            )

    cookie_rule_http_only = rules.get("SF-AUTH-003")
    cookie_rule_secure = rules.get("SF-AUTH-004")
    if model.cookie_auth:
        cookie_findings = 0
        for evidence in model.httponly_false:
            cookie_findings += 1
            if cookie_rule_http_only is not None:
                findings.append(
                    _finding(
                        cookie_rule_http_only,
                        evidence,
                        "Authentication cookie is configured with HttpOnly disabled, exposing it to script access.",
                    )
                )
        for evidence in model.secure_none:
            cookie_findings += 1
            if cookie_rule_secure is not None:
                findings.append(
                    _finding(
                        cookie_rule_secure,
                        evidence,
                        "Authentication cookie can be sent over plain HTTP because SecurePolicy is None.",
                    )
                )
        if cookie_findings:
            checks.append(
                _check(
                    "cookie-hardening",
                    "Authentication cookie hardening",
                    Status.FAIL,
                    "One or more cookie protections are disabled.",
                    list(model.httponly_false) + list(model.secure_none),
                    [rule.id for rule in (cookie_rule_http_only, cookie_rule_secure) if rule is not None],
                )
            )
        else:
            checks.append(
                _check(
                    "cookie-hardening",
                    "Authentication cookie hardening",
                    Status.PASS,
                    "Cookie authentication is configured without the detected insecure flags.",
                    [model.cookie_auth[0]],
                    [rule.id for rule in (cookie_rule_http_only, cookie_rule_secure) if rule is not None],
                )
            )
    else:
        checks.append(
            _check(
                "cookie-hardening",
                "Authentication cookie hardening",
                Status.NOT_APPLICABLE,
                "Cookie authentication is not used.",
                [],
                [rule.id for rule in (cookie_rule_http_only, cookie_rule_secure) if rule is not None],
            )
        )

    jwt_rule = rules.get("SF-AUTH-005")
    if model.jwt_config or model.jwt_https_false:
        jwt_bad = 0
        for evidence in model.jwt_https_false:
            jwt_bad += 1
            if jwt_rule is not None:
                findings.append(
                    _finding(
                        jwt_rule,
                        evidence,
                        "JWT bearer metadata is allowed over plain HTTP because RequireHttpsMetadata is false.",
                    )
                )
        if jwt_bad:
            checks.append(
                _check(
                    "jwt-transport",
                    "JWT metadata transport",
                    Status.FAIL,
                    "JWT metadata transport protection is disabled.",
                    list(model.jwt_https_false),
                    [jwt_rule.id] if jwt_rule is not None else [],
                )
            )
        else:
            checks.append(
                _check(
                    "jwt-transport",
                    "JWT metadata transport",
                    Status.PASS,
                    "JWT bearer authentication is configured without disabling HTTPS metadata.",
                    [model.jwt_config[0]] if model.jwt_config else [],
                    [jwt_rule.id] if jwt_rule is not None else [],
                )
            )
    else:
        checks.append(
            _check(
                "jwt-transport",
                "JWT metadata transport",
                Status.NOT_APPLICABLE,
                "JWT bearer authentication is not used.",
                [],
                [jwt_rule.id] if jwt_rule is not None else [],
            )
        )

    status = _status(findings, checks, surface)
    reason = {
        Status.FAIL: "Authentication controls are incomplete or insecure.",
        Status.UNVERIFIED: "Authentication is not proven for the detected endpoints.",
        Status.PASS: "Authentication is registered, invoked, and configured without the detected insecure flags.",
        Status.NOT_APPLICABLE: "No authentication surface was found.",
    }[status]
    return ControlOutcome(status=status, reason=reason, checks=checks, findings=findings)


def analyze_authorization(model: CSharpModel, rules: Dict[str, Rule]) -> ControlOutcome:
    rule = rules.get("SF-AUTHZ-001")
    findings: List[Finding] = []
    checks: List[Check] = []
    endpoints = list(model.endpoints)
    mutating = [endpoint for endpoint in endpoints if endpoint.mutating]
    anonymous_mutating = [endpoint for endpoint in mutating if endpoint.anonymous]
    protected_mutating = [endpoint for endpoint in mutating if endpoint.protected]
    unprotected = [endpoint for endpoint in mutating if not endpoint.protected and not endpoint.anonymous]

    if not endpoints:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No HTTP endpoints were found.",
            checks=[
                _check(
                    "authorization-surface",
                    "Authorization surface",
                    Status.NOT_APPLICABLE,
                    "No HTTP endpoints were detected.",
                    [],
                    [rule.id] if rule is not None else [],
                )
            ],
        )

    for endpoint in unprotected:
        snippet = "%s [%s]" % (endpoint.label, endpoint.verb)
        evidence = Evidence(
            path=endpoint.path,
            line=endpoint.line,
            column=endpoint.column,
            snippet=snippet,
            snippet_sha256=snippet_hash(snippet),
            language="csharp",
        )
        if rule is not None:
            findings.append(
                _finding(
                    rule,
                    evidence,
                    "Mutating endpoint %s has no authorization requirement." % endpoint.label,
                )
            )

    if unprotected:
        checks.append(
            _check(
                "mutating-endpoint-authorization",
                "Mutating endpoint authorization",
                Status.FAIL,
                "%d mutating endpoint(s) lack an authorization requirement." % len(unprotected),
                [finding.evidence for finding in findings],
                [rule.id] if rule is not None else [],
            )
        )
    elif not mutating:
        checks.append(
            _check(
                "mutating-endpoint-authorization",
                "Mutating endpoint authorization",
                Status.UNVERIFIED,
                "No mutating endpoints were found. Read-only endpoints and object-level authorization were not assessed.",
                [],
                [rule.id] if rule is not None else [],
            )
        )
    elif anonymous_mutating:
        checks.append(
            _check(
                "mutating-endpoint-authorization",
                "Mutating endpoint authorization",
                Status.UNVERIFIED,
                "Mutating endpoints are explicitly anonymous. Intentional exposure was not proven.",
                [],
                [rule.id] if rule is not None else [],
            )
        )
    else:
        detail = "All detected mutating endpoints require authorization."
        if model.fallback is not None:
            detail += " A global fallback policy also applies."
        else:
            detail += " Object-level authorization was not assessed."
        checks.append(
            _check(
                "mutating-endpoint-authorization",
                "Mutating endpoint authorization",
                Status.PASS,
                detail,
                [model.fallback] if model.fallback is not None else [],
                [rule.id] if rule is not None else [],
            )
        )

    if mutating and not model.has_auth_config and not unprotected:
        checks.append(
            _check(
                "authorization-auth-backend",
                "Authorization backend",
                Status.UNVERIFIED,
                "Authorization attributes are present, but no authentication scheme was detected to supply identities.",
                [],
                [rule.id] if rule is not None else [],
            )
        )

    status = _status(findings, checks, bool(endpoints))
    reason = {
        Status.FAIL: "At least one mutating endpoint lacks an authorization requirement.",
        Status.UNVERIFIED: "Authorization is not proven for every detected endpoint.",
        Status.PASS: "Every detected mutating endpoint requires authorization.",
        Status.NOT_APPLICABLE: "No HTTP endpoints were found.",
    }[status]
    return ControlOutcome(status=status, reason=reason, checks=checks, findings=findings)


_SECRET_SURFACE = re.compile(
    r"(?i)\b(password|passwd|pwd|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|"
    r"connectionstrings?|jwt[_-]?key|signing[_-]?key|access[_-]?token)\b"
)
_SECRET_PROVIDER = re.compile(
    r"\b(IConfiguration|Configuration\s*\[|GetConfiguration|GetConnectionString|GetEnvironmentVariable|AddUserSecrets|"
    r"SecretClient|GetSecret|AddAzureKeyVault|KeyVault|SecretsManager|IOptions\s*<|Vault)"
)
_CONFIG_SUFFIXES = (
    ".json",
    ".config",
    ".xml",
    ".yml",
    ".yaml",
    ".env",
    ".props",
    ".targets",
    ".csproj",
    ".ps1",
    ".sh",
)


def analyze_secrets(
    files: Sequence[ScanFile],
    secret_findings: Sequence[Finding],
    rules: Dict[str, Rule],
) -> ControlOutcome:
    findings = list(secret_findings)
    checks: List[Check] = []
    secret_rules = sorted(rule.id for rule in rules.values() if rule.control == "secrets-management")

    surface_evidence: Optional[Evidence] = None
    provider_evidence: Optional[Evidence] = None
    for file in files:
        if file.relpath.lower().endswith(".cs"):
            text = file.text
        elif file.relpath.lower().endswith(_CONFIG_SUFFIXES):
            text = file.text
        else:
            continue
        if surface_evidence is None:
            match = _SECRET_SURFACE.search(text)
            if match:
                surface_evidence = evidence_at(file, match.start())
        if provider_evidence is None:
            match = _SECRET_PROVIDER.search(text)
            if match:
                provider_evidence = evidence_at(file, match.start())

    if findings:
        checks.append(
            _check(
                "no-hardcoded-secret",
                "Hardcoded secret detection",
                Status.FAIL,
                "%d hardcoded credential finding(s) were detected." % len(findings),
                [finding.evidence for finding in findings],
                secret_rules,
            )
        )
        checks.append(
            _check(
                "managed-secret-source",
                "Managed secret source",
                Status.PASS if provider_evidence is not None else Status.UNVERIFIED,
                "A managed secret source is used, but it does not offset hardcoded credentials."
                if provider_evidence is not None
                else "A managed secret source does not offset hardcoded credentials.",
                [provider_evidence] if provider_evidence else [],
                secret_rules,
            )
        )
        return ControlOutcome(
            status=Status.FAIL,
            reason="Hardcoded credentials or private key material were detected.",
            checks=checks,
            findings=findings,
        )

    if surface_evidence is None:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No secret-bearing configuration surface was found.",
            checks=[
                _check(
                    "no-hardcoded-secret",
                    "Hardcoded secret detection",
                    Status.PASS,
                    "No secret patterns were detected, and no secret-bearing surface was found.",
                    [],
                    secret_rules,
                )
            ],
        )

    checks.append(
        _check(
            "no-hardcoded-secret",
            "Hardcoded secret detection",
            Status.PASS,
            "No hardcoded credential pattern was detected.",
            [surface_evidence],
            secret_rules,
        )
    )
    if provider_evidence is not None:
        checks.append(
            _check(
                "managed-secret-source",
                "Managed secret source",
                Status.PASS,
                "Configuration or a managed secret provider is used for secret-bearing settings.",
                [provider_evidence],
                secret_rules,
            )
        )
        return ControlOutcome(
            status=Status.PASS,
            reason="Secret-bearing settings are supplied through configuration or a managed secret provider.",
            checks=checks,
        )

    checks.append(
        _check(
            "managed-secret-source",
            "Managed secret source",
            Status.UNVERIFIED,
            "Secret-bearing settings exist but no configuration or managed secret provider was detected.",
            [surface_evidence],
            secret_rules,
        )
    )
    return ControlOutcome(
        status=Status.UNVERIFIED,
        reason="Secret usage is present but the source of secret values is not proven.",
        checks=checks,
    )


_SQL_SURFACE_PATTERNS = (
    re.compile(r"\b(?:FromSqlRaw|ExecuteSqlRaw)\s*\("),
    re.compile(r"\bnew\s+(?:Sqlite|Sql)Command\s*\("),
    re.compile(r"\.CommandText\s*="),
    re.compile(
        r"\b(?:connection|conn|db|database|sqlConnection|sqliteConnection)\s*\.\s*"
        r"(?:Query|QueryAsync|Execute|ExecuteAsync)\b"
    ),
)
_SQL_SAFE = re.compile(
    r"\b(FromSqlInterpolated|ExecuteSqlInterpolated|SqlParameter|SqliteParameter|"
    r"Parameters\s*\.\s*Add|AddWithValue)\b"
)
_SQL_SAFE_SURFACE = re.compile(r"\b(?:FromSqlInterpolated|ExecuteSqlInterpolated)\b")
_COMMAND_SAFE = re.compile(r"\bArgumentList\s*\.\s*Add\b")
_SHELL = re.compile(r'["\'](?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|sh|bash)["\']', re.IGNORECASE)


def _classify(expression: str) -> str:
    expression = expression.strip().rstrip(";").strip()
    if expression_dynamic(expression):
        return "dynamic"
    if expression_constant_string(expression):
        return "constant"
    if expression_identifier(expression):
        return "identifier"
    return "review"


def _dynamic_process_info_properties(statement: str) -> bool:
    """True when FileName or Arguments is not a constant in this statement."""

    for match in re.finditer(r"\b(?:FileName|Arguments)\s*=\s*([^;,\r\n]+)", statement):
        if _classify(match.group(1)) != "constant":
            return True
    return False


def _dedupe(findings: Sequence[Finding]) -> List[Finding]:
    seen = set()
    result: List[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.evidence.path, finding.evidence.line)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def _argument_list_shell_risk(masked: str, original: str) -> bool:
    """True when a shell command gets non-constant data through ArgumentList."""

    if not _SHELL.search(original):
        return False
    for match in re.finditer(r"ArgumentList\s*\.\s*Add\s*\(", masked):
        opening = call_open(masked, match.start())
        if opening == -1:
            continue
        for start, end in argument_ranges(masked, opening):
            if _classify(masked[start:end]) != "constant":
                return True
    return False


def _process_info_variables(files: Sequence[ScanFile]) -> Tuple[set, set, set]:
    """Return (declared, safe, unsafe) ProcessStartInfo variable names.

    Unsafe means a dynamic file name or argument property, or a shell whose
    ArgumentList receives non-constant data.
    """

    declared = set()
    safe = set()
    unsafe_vars = set()
    for file in files:
        if not file.relpath.lower().endswith(".cs"):
            continue
        masked = mask_csharp(file.text)
        for match in re.finditer(
            r"\b(?:var|ProcessStartInfo)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+ProcessStartInfo\b",
            masked,
        ):
            name = match.group(1)
            declared.add(name)
            end = statement_end(masked, match.start())
            statement = masked[match.start() : end]
            original = file.text[match.start() : end]
            shell = bool(_SHELL.search(original))
            dynamic_property = _dynamic_process_info_properties(statement)
            uses_argument_list = False
            unsafe = False
            for use in re.finditer(
                r"\b%s\s*\.\s*ArgumentList\s*\.\s*Add\s*\(" % re.escape(name),
                masked,
            ):
                uses_argument_list = True
                opening = call_open(masked, use.start())
                if opening == -1:
                    continue
                for start, finish in argument_ranges(masked, opening):
                    if _classify(masked[start:finish]) != "constant":
                        unsafe = True
            if dynamic_property or (shell and unsafe):
                unsafe_vars.add(name)
            elif uses_argument_list or _COMMAND_SAFE.search(statement):
                safe.add(name)
    return declared, safe - unsafe_vars, unsafe_vars


def analyze_injection(files: Sequence[ScanFile], rules: Dict[str, Rule]) -> ControlOutcome:
    sql_rule = rules.get("SF-INJ-001")
    sql_review_rule = rules.get("SF-INJ-004")
    command_rule = rules.get("SF-INJ-002")
    command_review_rule = rules.get("SF-INJ-003")

    sql_findings: List[Finding] = []
    command_findings: List[Finding] = []
    sql_surface_evidence: Optional[Evidence] = None
    command_surface_evidence: Optional[Evidence] = None
    sql_safe_evidence: Optional[Evidence] = None
    command_safe_evidence: Optional[Evidence] = None
    process_vars, safe_process_vars, unsafe_process_vars = _process_info_variables(files)

    for file in files:
        if not file.relpath.lower().endswith(".cs"):
            continue
        masked = mask_csharp(file.text)

        for pattern in _SQL_SURFACE_PATTERNS:
            for match in pattern.finditer(masked):
                if sql_surface_evidence is None:
                    sql_surface_evidence = evidence_at(file, match.start())
                if pattern.pattern.startswith(r"\bnew"):
                    start, end = first_argument(masked, match.start())
                elif pattern.pattern.startswith(r"\.CommandText"):
                    start = match.end()
                    end = statement_end(masked, start)
                else:
                    start, end = first_argument(masked, match.start())
                expression = masked[start:end]
                kind = _classify(expression)
                evidence = evidence_at(file, match.start())
                if kind == "dynamic" and sql_rule is not None:
                    sql_findings.append(
                        _finding(
                            sql_rule,
                            evidence,
                            "SQL text is built with interpolation or concatenation instead of parameters.",
                        )
                    )
                elif kind == "identifier" and sql_review_rule is not None:
                    sql_findings.append(
                        _finding(
                            sql_review_rule,
                            evidence,
                            "SQL text comes from a variable. Parameterization could not be proven.",
                        )
                    )
                elif kind == "review" and sql_review_rule is not None:
                    sql_findings.append(
                        _finding(
                            sql_review_rule,
                            evidence,
                            "SQL construction could not be resolved safely without running the code.",
                        )
                    )

        safe_match = _SQL_SAFE.search(masked)
        if safe_match and sql_safe_evidence is None:
            sql_safe_evidence = evidence_at(file, safe_match.start())

        safe_surface_match = _SQL_SAFE_SURFACE.search(masked)
        if safe_surface_match is not None:
            if sql_surface_evidence is None:
                sql_surface_evidence = evidence_at(file, safe_surface_match.start())
            if sql_safe_evidence is None:
                sql_safe_evidence = evidence_at(file, safe_surface_match.start())

        start_info = re.compile(r"\bProcess\s*\.\s*Start\s*\(")
        for match in start_info.finditer(masked):
            if command_surface_evidence is None:
                command_surface_evidence = evidence_at(file, match.start())
            opening = call_open(masked, match.start())
            if opening == -1:
                continue
            ranges = argument_ranges(masked, opening)
            if not ranges:
                continue
            args_masked = [masked[start:end] for start, end in ranges]
            args_original = [file.text[start:end] for start, end in ranges]
            statement_end_position = statement_end(masked, match.start())
            statement = masked[match.start() : statement_end_position]
            statement_original = file.text[match.start() : statement_end_position]
            evidence = evidence_at(file, match.start())

            first_original = args_original[0].strip() if args_original else ""
            if "new ProcessStartInfo" in statement or "ProcessStartInfo" in statement:
                dynamic = _dynamic_process_info_properties(statement)
                if dynamic and command_rule is not None:
                    command_findings.append(
                        _finding(
                            command_rule,
                            evidence,
                            "ProcessStartInfo builds a file name or argument string dynamically.",
                        )
                    )
                elif _argument_list_shell_risk(statement, statement_original):
                    if command_rule is not None:
                        command_findings.append(
                            _finding(
                                command_rule,
                                evidence,
                                "A shell receives non-constant values through ArgumentList, which does not prevent shell evaluation.",
                            )
                        )
                elif _COMMAND_SAFE.search(statement):
                    if command_safe_evidence is None:
                        command_safe_evidence = evidence_at(file, match.start())
                elif any(_classify(argument) == "dynamic" for argument in args_masked):
                    if command_rule is not None:
                        command_findings.append(
                            _finding(
                                command_rule,
                                evidence,
                                "Process.Start invokes a command with dynamically built arguments.",
                            )
                        )
                elif _SHELL.search(" ".join(args_original)) and len(ranges) > 1 and _classify(args_masked[1]) != "constant":
                    if command_rule is not None:
                        command_findings.append(
                            _finding(
                                command_rule,
                                evidence,
                                "A shell is invoked with argument data that is not a constant.",
                            )
                        )
                elif len(ranges) == 1 and _classify(args_masked[0]) != "constant":
                    if command_review_rule is not None:
                        command_findings.append(
                            _finding(
                                command_review_rule,
                                evidence,
                                "A ProcessStartInfo value could not be resolved. ArgumentList usage was not proven.",
                            )
                        )
                continue

            if first_original.startswith("new ProcessStartInfo"):
                continue
            first_kind = _classify(args_masked[0])
            if first_kind == "dynamic":
                if command_rule is not None:
                    command_findings.append(
                        _finding(
                            command_rule,
                            evidence,
                            "Process.Start receives a dynamically built executable name.",
                        )
                    )
            elif first_kind == "constant":
                if len(ranges) == 1:
                    if command_safe_evidence is None:
                        command_safe_evidence = evidence_at(file, match.start())
                else:
                    second_kind = _classify(args_masked[1])
                    if second_kind in ("dynamic", "identifier"):
                        if command_rule is not None:
                            command_findings.append(
                                _finding(
                                    command_rule,
                                    evidence,
                                    "Process.Start receives argument data that is not a constant and is not isolated with ArgumentList.",
                                )
                            )
                    else:
                        if command_safe_evidence is None:
                            command_safe_evidence = evidence_at(file, match.start())
            else:
                identifier = args_masked[0].strip()
                if identifier in unsafe_process_vars:
                    if command_rule is not None:
                        command_findings.append(
                            _finding(
                                command_rule,
                                evidence,
                                "A ProcessStartInfo variable receives dynamic data or a shell with non-constant ArgumentList values.",
                            )
                        )
                elif identifier in safe_process_vars:
                    if command_safe_evidence is None:
                        command_safe_evidence = evidence_at(file, match.start())
                elif identifier in process_vars:
                    if command_review_rule is not None:
                        command_findings.append(
                            _finding(
                                command_review_rule,
                                evidence,
                                "Process.Start uses a ProcessStartInfo variable without proven ArgumentList isolation.",
                            )
                        )
                elif command_review_rule is not None:
                    command_findings.append(
                        _finding(
                            command_review_rule,
                            evidence,
                            "Process.Start target could not be resolved. ArgumentList usage was not proven.",
                        )
                    )

        info_pattern = re.compile(r"\bnew\s+ProcessStartInfo\b")
        for match in info_pattern.finditer(masked):
            if command_surface_evidence is None:
                command_surface_evidence = evidence_at(file, match.start())
            statement = masked[match.start() : statement_end(masked, match.start())]
            statement_original = file.text[match.start() : statement_end(masked, match.start())]
            evidence = evidence_at(file, match.start())
            dynamic = _dynamic_process_info_properties(statement)
            if dynamic and command_rule is not None:
                command_findings.append(
                    _finding(
                        command_rule,
                        evidence,
                        "ProcessStartInfo builds a file name or argument string dynamically.",
                    )
                )
            elif _argument_list_shell_risk(statement, statement_original):
                if command_rule is not None:
                    command_findings.append(
                        _finding(
                            command_rule,
                            evidence,
                            "A shell receives non-constant values through ArgumentList, which does not prevent shell evaluation.",
                        )
                    )
            elif _COMMAND_SAFE.search(statement):
                if command_safe_evidence is None:
                    command_safe_evidence = evidence_at(file, match.start())
            else:
                opening = call_open(masked, match.start())
                if opening != -1 and opening < statement_end(masked, match.start()):
                    ranges = argument_ranges(masked, opening)
                    if any(_classify(masked[start:end]) == "dynamic" for start, end in ranges):
                        if command_rule is not None:
                            command_findings.append(
                                _finding(
                                    command_rule,
                                    evidence,
                                    "ProcessStartInfo receives dynamically built constructor arguments.",
                                )
                            )

    sql_findings = _dedupe(sql_findings)
    command_findings = _dedupe(command_findings)

    checks: List[Check] = []
    if sql_surface_evidence is None:
        checks.append(
            _check(
                "sql-parameterization",
                "SQL parameterization",
                Status.NOT_APPLICABLE,
                "No SQL construction surface was found.",
            )
        )
    else:
        sql_fail = [finding for finding in sql_findings if finding.result == Status.FAIL]
        sql_review = [finding for finding in sql_findings if finding.result == Status.UNVERIFIED]
        if sql_fail:
            sql_status = Status.FAIL
            detail = "%d SQL sink(s) build query text dynamically." % len(sql_fail)
        elif sql_review:
            sql_status = Status.UNVERIFIED
            detail = "%d SQL sink(s) could not be proven parameterized." % len(sql_review)
        else:
            sql_status = Status.PASS
            detail = "Detected SQL sinks use constants or identifiers with parameter evidence."
        checks.append(
            _check(
                "sql-parameterization",
                "SQL parameterization",
                sql_status,
                detail,
                [finding.evidence for finding in sql_fail + sql_review]
                or [sql_safe_evidence or sql_surface_evidence],
                [rule.id for rule in (sql_rule, sql_review_rule) if rule is not None],
            )
        )

    if command_surface_evidence is None:
        checks.append(
            _check(
                "os-command-safety",
                "OS command safety",
                Status.NOT_APPLICABLE,
                "No OS command surface was found.",
            )
        )
    else:
        command_fail = [finding for finding in command_findings if finding.result == Status.FAIL]
        command_review = [finding for finding in command_findings if finding.result == Status.UNVERIFIED]
        if command_fail:
            command_status = Status.FAIL
            detail = "%d OS command sink(s) use dynamic or unisolated input." % len(command_fail)
        elif command_review:
            command_status = Status.UNVERIFIED
            detail = "%d OS command sink(s) could not be proven safe." % len(command_review)
        else:
            command_status = Status.PASS
            detail = "Detected OS command sinks use constants or ArgumentList isolation."
        checks.append(
            _check(
                "os-command-safety",
                "OS command safety",
                command_status,
                detail,
                [finding.evidence for finding in command_fail + command_review]
                or [command_safe_evidence or command_surface_evidence],
                [rule.id for rule in (command_rule, command_review_rule) if rule is not None],
            )
        )

    findings = sql_findings + command_findings
    surface = sql_surface_evidence is not None or command_surface_evidence is not None
    status = _status(findings, checks, surface)
    reason = {
        Status.FAIL: "Dynamic SQL or OS command construction was detected.",
        Status.UNVERIFIED: "Injection safety could not be proven for every detected sink.",
        Status.PASS: "Detected SQL and OS command sinks use parameterization or argument isolation.",
        Status.NOT_APPLICABLE: "No SQL or OS command construction surface was found.",
    }[status]
    return ControlOutcome(status=status, reason=reason, checks=checks, findings=findings)


_LOGGING_INFRA = re.compile(
    r"\b(ILogger|ILoggerFactory|ILoggerProvider|AddLogging|AddSerilog|AddNLog|"
    r"Log\.Logger|LoggerMessage\.Define|Microsoft\.Extensions\.Logging)"
)
_SECURITY_EVENT = re.compile(
    r"\b_logger\.(Log(?:Information|Warning|Error|Critical)|LogDebug)"
    r"|LoggerMessage\.Define"
)
_SECURITY_EVENT_KEYWORDS = re.compile(
    r"(?i)\b(auth|login|log[- ]?in|logout|log[- ]?out|sign[- ]?in|sign[- ]?out|"
    r"access denied|unauthorized|forbidden|admin|create|delete|update|change password|"
    r"role|permission|audit|security)\b"
)


def analyze_security_logging(
    model: CSharpModel,
    files: Sequence[ScanFile],
    rules: Dict[str, Rule],
) -> ControlOutcome:
    rule_infra = rules.get("SF-LOG-001")
    rule_events = rules.get("SF-LOG-002")
    findings: List[Finding] = []
    checks: List[Check] = []
    surface = bool(model.endpoints or model.mvc_surface)

    if not surface:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No HTTP endpoints or MVC surface was found.",
            checks=[
                _check(
                    "logging-surface",
                    "Logging surface",
                    Status.NOT_APPLICABLE,
                    "No web application surface was detected.",
                )
            ],
        )

    infra_evidence: Optional[Evidence] = None
    event_evidence: Optional[Evidence] = None
    for file in files:
        if not file.relpath.lower().endswith(".cs"):
            continue
        if infra_evidence is None:
            match = _LOGGING_INFRA.search(file.text)
            if match:
                infra_evidence = evidence_at(file, match.start())
        if event_evidence is None:
            for match in _SECURITY_EVENT.finditer(file.text):
                end = match.end()
                # inspect a window after the call for a security keyword
                window = file.text[end:end + 200]
                if _SECURITY_EVENT_KEYWORDS.search(window):
                    event_evidence = evidence_at(file, match.start())
                    break

    if infra_evidence is None:
        # Conservative: missing logging infrastructure in a web project is
        # UNVERIFIED, not FAIL, because the code might log through a framework
        # or platform mechanism we cannot see statically.
        fallback_file = next(
            (file for file in files if file.relpath.lower().endswith(".cs")),
            None,
        )
        infra_placeholder = (
            Evidence(
                path=fallback_file.relpath,
                line=1,
                column=1,
                snippet="No logging infrastructure found",
                snippet_sha256=snippet_hash("No logging infrastructure found"),
                language="csharp",
            )
            if fallback_file is not None
            else Evidence(
                path="",
                line=1,
                column=1,
                snippet="No logging infrastructure found",
                snippet_sha256=snippet_hash("No logging infrastructure found"),
                language="csharp",
            )
        )
        if rule_infra is not None:
            findings.append(
                _finding(
                    rule_infra,
                    infra_placeholder,
                    "The application has HTTP endpoints but no recognized logging infrastructure was detected.",
                )
            )
        checks.append(
            _check(
                "logging-infrastructure",
                "Logging infrastructure",
                Status.UNVERIFIED,
                "No ILogger, Serilog, NLog or LoggerMessage usage was detected.",
                [infra_placeholder],
                [rule_infra.id] if rule_infra is not None else [],
            )
        )
    else:
        checks.append(
            _check(
                "logging-infrastructure",
                "Logging infrastructure",
                Status.PASS,
                "A recognized logging infrastructure is present.",
                [infra_evidence],
                [rule_infra.id] if rule_infra is not None else [],
            )
        )

    auth_surface = bool(model.has_auth_config or model.endpoints)
    if not auth_surface:
        checks.append(
            _check(
                "security-event-logging",
                "Security event logging",
                Status.NOT_APPLICABLE,
                "No authentication surface was detected; security event logging is not assessed.",
                [],
                [rule_events.id] if rule_events is not None else [],
            )
        )
    elif event_evidence is not None:
        checks.append(
            _check(
                "security-event-logging",
                "Security event logging",
                Status.PASS,
                "Explicit security-relevant log events were detected.",
                [event_evidence],
                [rule_events.id] if rule_events is not None else [],
            )
        )
    else:
        if rule_events is not None:
            findings.append(
                _finding(
                    rule_events,
                    infra_evidence
                    if infra_evidence is not None
                    else Evidence(
                        path="",
                        line=1,
                        column=1,
                        snippet="No security events logged",
                        snippet_sha256=snippet_hash("No security events logged"),
                        language="csharp",
                    ),
                    "Authentication or authorization events are not explicitly logged.",
                )
            )
        checks.append(
            _check(
                "security-event-logging",
                "Security event logging",
                Status.UNVERIFIED,
                "Logging infrastructure exists, but no explicit security-relevant events were detected.",
                [infra_evidence] if infra_evidence else [],
                [rule_events.id] if rule_events is not None else [],
            )
        )

    status = _status(findings, checks, surface)
    reason = {
        Status.FAIL: "The application does not have a recognized logging infrastructure.",
        Status.UNVERIFIED: "Security-relevant events are not explicitly logged.",
        Status.PASS: "Logging infrastructure and explicit security events are present.",
        Status.NOT_APPLICABLE: "No web application surface was found.",
    }[status]
    return ControlOutcome(status=status, reason=reason, checks=checks, findings=findings)
