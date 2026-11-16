"""C# / ASP.NET Core parsing helpers.

The parser is deliberately small and framework-aware. It does not execute code and
does not attempt to build a full syntax tree. It recognizes the constructs that
matter for the five baseline controls and preserves offsets for evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import Evidence, ScanFile, snippet_hash

MUTATING_VERBS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_VERBS = {"GET", "HEAD", "OPTIONS", "TRACE"}
METHOD_NAMES = {
    "if",
    "for",
    "foreach",
    "while",
    "switch",
    "catch",
    "using",
    "lock",
    "when",
    "return",
    "new",
    "typeof",
    "sizeof",
    "nameof",
    "checked",
    "unchecked",
}

ATTR_BLOCK = re.compile(r"(?:\[[^\[\]]*\]\s*)+", re.DOTALL)
SINGLE_ATTR = re.compile(r"\[[^\[\]]*\]")


@dataclass
class Endpoint:
    label: str
    path: str
    line: int
    column: int
    verb: str
    mutating: bool
    protected: bool
    anonymous: bool
    kind: str
    route: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "verb": self.verb,
            "mutating": self.mutating,
            "protected": self.protected,
            "anonymous": self.anonymous,
            "kind": self.kind,
            "route": self.route,
        }


@dataclass
class CSharpModel:
    endpoints: List[Endpoint] = field(default_factory=list)
    fallback: Optional[Evidence] = None
    fallback_detail: str = ""
    auth_config: List[Evidence] = field(default_factory=list)
    use_authentication: List[Evidence] = field(default_factory=list)
    cookie_auth: List[Evidence] = field(default_factory=list)
    jwt_config: List[Evidence] = field(default_factory=list)
    auth_scheme: List[Evidence] = field(default_factory=list)
    httponly_false: List[Evidence] = field(default_factory=list)
    secure_none: List[Evidence] = field(default_factory=list)
    jwt_https_false: List[Evidence] = field(default_factory=list)
    validation_mechanisms: Dict[str, List[Evidence]] = field(default_factory=dict)
    validation_attributes: List[Evidence] = field(default_factory=list)
    suppress_validation: List[Evidence] = field(default_factory=list)
    manual_validation: List[Evidence] = field(default_factory=list)
    mvc_surface: List[Evidence] = field(default_factory=list)
    anonymous_endpoints: List[Endpoint] = field(default_factory=list)

    @property
    def has_auth_config(self) -> bool:
        return bool(self.auth_config)

    @property
    def has_cookie_auth(self) -> bool:
        return bool(self.cookie_auth)

    @property
    def has_auth_scheme(self) -> bool:
        return bool(self.auth_scheme)

    @property
    def mutating_endpoints(self) -> List[Endpoint]:
        return [endpoint for endpoint in self.endpoints if endpoint.mutating]

    def mechanisms(self) -> List[str]:
        return sorted(self.validation_mechanisms)


def blank_character(out: List[str], index: int, text: str) -> None:
    if text[index] not in "\r\n":
        out[index] = " "


def mask_csharp(text: str) -> str:
    """Mask comments, string contents, and char contents without changing length."""

    out = list(text)
    length = len(text)
    index = 0

    def blank_until_line_end(position: int) -> int:
        while position < length and text[position] not in "\r\n":
            blank_character(out, position, text)
            position += 1
        return position

    while index < length:
        char = text[index]

        if char == "/" and index + 1 < length and text[index + 1] == "/":
            blank_character(out, index, text)
            blank_character(out, index + 1, text)
            index = blank_until_line_end(index + 2)
            continue

        if char == "/" and index + 1 < length and text[index + 1] == "*":
            blank_character(out, index, text)
            blank_character(out, index + 1, text)
            index += 2
            while index < length:
                if text[index] == "*" and index + 1 < length and text[index + 1] == "/":
                    blank_character(out, index, text)
                    blank_character(out, index + 1, text)
                    index += 2
                    break
                blank_character(out, index, text)
                index += 1
            continue

        # Raw string literal: """...""" (optionally interpolated with $).
        raw_start = index
        if char == "$" and text.startswith('$"""', index):
            raw_start = index + 1
        if text.startswith('"""', raw_start):
            # Preserve the opening quotes; mask content and closing quotes.
            quote_count = 3
            cursor = raw_start + 3
            end = text.find('"' * quote_count, cursor)
            if end == -1:
                end = length
            while cursor < end:
                blank_character(out, cursor, text)
                cursor += 1
            index = min(end + quote_count, length)
            for offset in range(raw_start, min(raw_start + 3, length)):
                out[offset] = text[offset]
            continue

        # Verbatim string: @"..." or @$"...
        if char == "@" and index + 1 < length and text[index + 1] == '"':
            cursor = index + 2
            while cursor < length:
                if text[cursor] == '"':
                    if cursor + 1 < length and text[cursor + 1] == '"':
                        blank_character(out, cursor, text)
                        blank_character(out, cursor + 1, text)
                        cursor += 2
                        continue
                    cursor += 1
                    break
                blank_character(out, cursor, text)
                cursor += 1
            index = cursor
            continue
        if char == "@" and text.startswith('@$"', index):
            cursor = index + 3
            while cursor < length:
                if text[cursor] == '"':
                    if cursor + 1 < length and text[cursor + 1] == '"':
                        blank_character(out, cursor, text)
                        blank_character(out, cursor + 1, text)
                        cursor += 2
                        continue
                    cursor += 1
                    break
                blank_character(out, cursor, text)
                cursor += 1
            index = cursor
            continue

        # Interpolated string: $"..." or $@"..."
        if char == "$" and index + 1 < length and text[index + 1] == '"':
            verbatim = False
            cursor = index + 2
            if index + 2 < length and text[index + 2] == "@":
                verbatim = True
                cursor = index + 3
            while cursor < length:
                if text[cursor] == '"':
                    if verbatim and cursor + 1 < length and text[cursor + 1] == '"':
                        blank_character(out, cursor, text)
                        blank_character(out, cursor + 1, text)
                        cursor += 2
                        continue
                    cursor += 1
                    break
                if not verbatim and text[cursor] == "\\" and cursor + 1 < length:
                    blank_character(out, cursor, text)
                    blank_character(out, cursor + 1, text)
                    cursor += 2
                    continue
                blank_character(out, cursor, text)
                cursor += 1
            index = cursor
            continue

        if char == '"':
            cursor = index + 1
            while cursor < length:
                if text[cursor] == "\\" and cursor + 1 < length:
                    blank_character(out, cursor, text)
                    blank_character(out, cursor + 1, text)
                    cursor += 2
                    continue
                if text[cursor] == '"':
                    cursor += 1
                    break
                blank_character(out, cursor, text)
                cursor += 1
            index = cursor
            continue

        if char == "'":
            cursor = index + 1
            while cursor < length:
                if text[cursor] == "\\" and cursor + 1 < length:
                    blank_character(out, cursor, text)
                    blank_character(out, cursor + 1, text)
                    cursor += 2
                    continue
                if text[cursor] == "'":
                    cursor += 1
                    break
                blank_character(out, cursor, text)
                cursor += 1
            index = cursor
            continue

        index += 1

    return "".join(out)


def line_column(text: str, position: int) -> Tuple[int, int]:
    line = text.count("\n", 0, max(0, position)) + 1
    last_newline = text.rfind("\n", 0, max(0, position))
    column = max(1, position - last_newline)
    return line, column


def evidence_at(file: ScanFile, position: int, snippet: Optional[str] = None) -> Evidence:
    line, column = line_column(file.text, position)
    lines = file.text.splitlines()
    raw = lines[line - 1] if 1 <= line <= len(lines) else ""
    chosen = snippet if snippet is not None else raw.strip()
    return Evidence(
        path=file.relpath,
        line=line,
        column=column,
        snippet=chosen,
        snippet_sha256=snippet_hash(raw),
        language="csharp",
    )


def matching_brace(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def brace_depth_at(text: str, position: int) -> int:
    return text.count("{", 0, position) - text.count("}", 0, position)


def trailing_attributes(text: str) -> Optional[Tuple[int, str]]:
    match = re.search(r"((?:\s*\[[^\[\]]*\]\s*)+)$", text, re.DOTALL)
    if not match:
        return None
    return match.start(1), match.group(0)


def _attribute_names(text: str) -> List[str]:
    return [match.group(0).strip() for match in SINGLE_ATTR.finditer(text)]


def _has_attribute(text: str, name: str) -> bool:
    return re.search(r"\[\s*" + re.escape(name) + r"\b", text) is not None


def _verb_facts(
    method_attributes: str,
) -> Tuple[bool, bool, str]:
    """Return (is_endpoint, mutating, verb)."""

    match = re.search(r"\bHttp(Post|Put|Patch|Delete)\b", method_attributes)
    if match:
        return True, True, match.group(1).upper()
    match = re.search(r"\bHttp(Get|Head|Options|Trace)\b", method_attributes)
    if match:
        return True, False, match.group(1).upper()
    if re.search(r"\bAcceptVerbs\b", method_attributes):
        verbs = [item.upper() for item in re.findall(r'"([A-Za-z]+)"', method_attributes)]
        mutating = any(item in MUTATING_VERBS for item in verbs)
        verb = "/".join(verbs) if verbs else "UNKNOWN"
        return True, mutating, verb
    if re.search(r"\bRoute\b", method_attributes):
        return True, True, "ANY"
    return False, False, ""


def _method_signature(masked: str, start: int) -> Optional[Tuple[str, int, str]]:
    window = masked[start : start + 1200]
    trimmed = window.lstrip()
    offset = len(window) - len(trimmed)
    stop = len(trimmed)
    for token in ("{", ";", "=>"):
        found = trimmed.find(token)
        if found != -1 and found < stop:
            stop = found
    signature = trimmed[:stop]
    if "(" not in signature or ")" not in signature:
        return None
    if any(word in signature for word in (" delegate ", " event ", " class ", " namespace ")):
        return None
    names = list(re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^<>]*>)?\s*\(", signature))
    if not names:
        return None
    name_match = names[-1]
    name = name_match.group(1)
    if name in METHOD_NAMES:
        return None
    # Reject field initializers and constructors that are not methods.
    if "=" in signature[: name_match.start()]:
        return None
    return name, start + offset + name_match.start(1), signature


def parse_controllers(file: ScanFile, masked: str) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    for class_match in re.finditer(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", masked):
        class_name = class_match.group(1)
        opening = masked.find("{", class_match.end())
        if opening == -1:
            continue
        semicolon = masked.find(";", class_match.end(), opening)
        if semicolon != -1:
            continue
        closing = matching_brace(masked, opening)
        if closing == -1:
            continue

        prefix_start = max(0, class_match.start() - 4000)
        prefix = masked[prefix_start : class_match.start()]
        boundary = max(prefix.rfind(";"), prefix.rfind("{"), prefix.rfind("}"))
        class_attrs = prefix[boundary + 1 if boundary != -1 else 0 :]
        is_controller = (
            class_name.endswith("Controller")
            or _has_attribute(class_attrs, "ApiController")
            or _has_attribute(class_attrs, "Route")
        )
        if not is_controller:
            continue
        class_authorize = _has_attribute(class_attrs, "Authorize")
        class_anonymous = _has_attribute(class_attrs, "AllowAnonymous")
        body_start = opening + 1
        body = masked[body_start:closing]

        for attr_match in ATTR_BLOCK.finditer(body):
            if brace_depth_at(body, attr_match.start()) != 0:
                continue
            method_attrs_start = body_start + attr_match.start()
            method_attrs = file.text[method_attrs_start : body_start + attr_match.end()]
            method_attrs_masked = body[attr_match.start() : attr_match.end()]
            after = body[attr_match.end() :]
            stripped = after.lstrip()
            offset = len(after) - len(stripped)
            signature = _method_signature(body, attr_match.end())
            if signature is None:
                continue
            method_name, name_position, signature_text = signature
            is_endpoint, mutating, verb = _verb_facts(method_attrs)
            if not is_endpoint:
                continue
            method_authorize = _has_attribute(method_attrs_masked, "Authorize")
            method_anonymous = _has_attribute(method_attrs_masked, "AllowAnonymous")
            anonymous = class_anonymous or method_anonymous
            protected = (class_authorize or method_authorize) and not anonymous
            position = body_start + name_position
            line, column = line_column(file.text, position)
            endpoints.append(
                Endpoint(
                    label="%s.%s" % (class_name, method_name),
                    path=file.relpath,
                    line=line,
                    column=column,
                    verb=verb,
                    mutating=mutating,
                    protected=protected,
                    anonymous=anonymous,
                    kind="controller",
                )
            )
    return endpoints


def parse_minimal_apis(file: ScanFile, masked: str) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    pattern = re.compile(r"\.Map(Post|Put|Patch|Delete)\s*\(")
    for match in pattern.finditer(masked):
        opening = call_open(masked, match.start())
        closing = matching_paren(masked, opening) if opening != -1 else -1
        if closing == -1:
            end = masked.find(";", match.end())
        else:
            end = masked.find(";", closing)
        if end == -1:
            end = min(len(masked), match.end() + 2000)
        statement = masked[match.start() : end]
        original = file.text[match.start() : end]
        protected = "RequireAuthorization" in statement
        anonymous = "AllowAnonymous" in statement
        route_match = re.search(r'Map(?:Post|Put|Patch|Delete)\s*\(\s*"([^"]*)"', original)
        route = route_match.group(1) if route_match else ""
        line, column = line_column(file.text, match.start())
        endpoints.append(
            Endpoint(
                label="Map%s%s" % (match.group(1), route),
                path=file.relpath,
                line=line,
                column=column,
                verb=match.group(1).upper(),
                mutating=True,
                protected=protected,
                anonymous=anonymous,
                kind="minimal",
                route=route,
            )
        )
    return endpoints


def _collect(
    files: Sequence[ScanFile],
    pattern: str,
    masked: bool = True,
    flags: int = 0,
) -> List[Evidence]:
    compiled = re.compile(pattern, flags)
    results: List[Evidence] = []
    seen = set()
    for file in files:
        if not file.relpath.lower().endswith(".cs"):
            continue
        haystack = mask_csharp(file.text) if masked else file.text
        for match in compiled.finditer(haystack):
            key = (file.relpath, match.start())
            if key in seen:
                continue
            seen.add(key)
            results.append(evidence_at(file, match.start()))
    return results


def _collect_validation_attributes(files: Sequence[ScanFile]) -> List[Evidence]:
    pattern = re.compile(
        r"\[\s*(Required|StringLength|MaxLength|MinLength|Range|RegularExpression|"
        r"EmailAddress|Phone|Url|Compare|CustomValidation|BindRequired|JsonRequired)\b"
    )
    results: List[Evidence] = []
    for file in files:
        if not file.relpath.lower().endswith(".cs"):
            continue
        masked = mask_csharp(file.text)
        for match in pattern.finditer(masked):
            results.append(evidence_at(file, match.start()))
    return results


def detect_fallback(files: Sequence[ScanFile]) -> Tuple[Optional[Evidence], str]:
    for file in files:
        if not file.relpath.lower().endswith(".cs"):
            continue
        masked = mask_csharp(file.text)
        for match in re.finditer(r"\bFallbackPolicy\s*=\s*", masked):
            tail = masked[match.end() : match.end() + 40]
            if re.match(r"\s*null\b", tail):
                continue
            return evidence_at(file, match.start()), "FallbackPolicy is configured"
        for match in re.finditer(r"\bnew\s+AuthorizeFilter\s*\(", masked):
            prefix = masked[max(0, match.start() - 160) : match.start()]
            if re.search(r"Filters\s*\.\s*Add\s*\(\s*$", prefix):
                return evidence_at(file, match.start()), "global AuthorizeFilter is registered"
        match = re.search(r"MapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization", masked)
        if match:
            return evidence_at(file, match.start()), "controllers are globally authorized"
    return None, ""


def parse_csharp(files: Sequence[ScanFile]) -> CSharpModel:
    model = CSharpModel()
    cs_files = [file for file in files if file.relpath.lower().endswith(".cs")]
    for file in cs_files:
        masked = mask_csharp(file.text)
        model.endpoints.extend(parse_controllers(file, masked))
        model.endpoints.extend(parse_minimal_apis(file, masked))

        for match in re.finditer(
            r"\b(AddAuthentication|AddIdentity|AddIdentityCore|AddMicrosoftIdentityWebApp|"
            r"AddOpenIdConnect|AddJwtBearer|AddCookie)\s*\(",
            masked,
        ):
            evidence = evidence_at(file, match.start())
            if match.group(1) in ("AddAuthentication", "AddIdentity", "AddIdentityCore", "AddMicrosoftIdentityWebApp", "AddOpenIdConnect"):
                model.auth_config.append(evidence)
            if match.group(1) == "AddJwtBearer":
                model.jwt_config.append(evidence)
                if not any(item.path == evidence.path and item.line == evidence.line for item in model.auth_config):
                    model.auth_config.append(evidence)
            if match.group(1) == "AddCookie":
                model.cookie_auth.append(evidence)
                if not any(item.path == evidence.path and item.line == evidence.line for item in model.auth_config):
                    model.auth_config.append(evidence)

        for match in re.finditer(
            r"\b(AddCookie|AddJwtBearer|AddIdentity|AddIdentityCore|AddMicrosoftIdentityWebApp|"
            r"AddOpenIdConnect|AddWsFederation|AddCertificate|AddOAuth|AddScheme)\b|"
            r"\b(DefaultScheme|DefaultAuthenticateScheme|DefaultChallengeScheme|DefaultForbidScheme)\b",
            masked,
        ):
            model.auth_scheme.append(evidence_at(file, match.start()))

        for match in re.finditer(r"\bUseAuthentication\s*\(", masked):
            model.use_authentication.append(evidence_at(file, match.start()))

        for match in re.finditer(r"\bHttpOnly\s*=\s*false\b", masked):
            model.httponly_false.append(evidence_at(file, match.start()))
        for match in re.finditer(r"\bSecurePolicy\s*=\s*CookieSecurePolicy\s*\.\s*None\b", masked):
            model.secure_none.append(evidence_at(file, match.start()))
        for match in re.finditer(r"\bRequireHttpsMetadata\s*=\s*false\b", masked):
            model.jwt_https_false.append(evidence_at(file, match.start()))

        mechanisms = {
            "ApiController": r"\[\s*ApiController\b",
            "ModelState": r"\bModelState\s*\.\s*IsValid\b",
            "FluentValidation": r"\b(AbstractValidator\s*<|AddValidatorsFromAssembly|IValidator\s*<)",
            "TryValidateObject": r"\bValidator\s*\.\s*TryValidateObject\b",
        }
        for name, pattern in mechanisms.items():
            for match in re.finditer(pattern, masked):
                model.validation_mechanisms.setdefault(name, []).append(evidence_at(file, match.start()))

        for match in re.finditer(r"\bSuppressModelStateInvalidFilter\s*=\s*true\b", masked):
            model.suppress_validation.append(evidence_at(file, match.start()))
        for match in re.finditer(
            r"(\bModelState\s*\.\s*IsValid\b|\bValidator\s*\.\s*TryValidateObject\b|"
            r"\bIValidator\s*<|\bValidate\s*\()",
            masked,
        ):
            model.manual_validation.append(evidence_at(file, match.start()))
        for match in re.finditer(
            r"\b(AddControllers|MapControllers|ControllerBase)\b|\bApiController\b", masked
        ):
            model.mvc_surface.append(evidence_at(file, match.start()))

    model.validation_attributes = _collect_validation_attributes(cs_files)
    model.fallback, model.fallback_detail = detect_fallback(cs_files)
    for endpoint in model.endpoints:
        if endpoint.anonymous:
            model.anonymous_endpoints.append(endpoint)
        elif model.fallback is not None:
            endpoint.protected = True
    model.endpoints.sort(key=lambda item: (item.line, item.label))
    model.anonymous_endpoints.sort(key=lambda item: (item.line, item.label))
    return model


def statement_end(text: str, start: int, limit: int = 2500) -> int:
    end = text.find(";", start)
    if end == -1:
        return min(len(text), start + limit)
    return min(end + 1, start + limit)


def call_open(text: str, start: int) -> int:
    return text.find("(", start)


def matching_paren(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def argument_ranges(text: str, opening: int) -> List[Tuple[int, int]]:
    """Return top-level argument ranges for a masked call."""

    closing = matching_paren(text, opening)
    if closing == -1:
        return []
    ranges: List[Tuple[int, int]] = []
    start = opening + 1
    depth = 0
    for index in range(opening + 1, closing):
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            ranges.append((start, index))
            start = index + 1
    ranges.append((start, closing))
    return ranges


def first_argument(text: str, start: int) -> Tuple[int, int]:
    opening = call_open(text, start)
    if opening == -1:
        return start, start
    ranges = argument_ranges(text, opening)
    return ranges[0] if ranges else (opening + 1, opening + 1)


def expression_dynamic(expression: str) -> bool:
    """True when a masked argument clearly contains interpolation or concatenation."""

    stripped = expression.strip()
    if not stripped:
        return False
    if '$"' in stripped or '$@"' in stripped:
        return True
    if re.search(r"\+\s*(?:[\"$A-Za-z_])", stripped):
        return True
    return False


def expression_constant_string(expression: str) -> bool:
    stripped = expression.strip()
    return bool(re.match(r'^@?"(?:[^"\\]|\\.)*"$', stripped, re.DOTALL)) or bool(
        re.match(r'^@"(?:[^"]|"")*"$', stripped, re.DOTALL)
    )


def expression_identifier(expression: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_\.]*$", expression.strip()))
