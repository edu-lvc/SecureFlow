"""pfSense configuration parser and analyzer.

Supports XML configuration exports.  API integration is left to future
adapters; this module never connects to a live device.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..model import Check, ControlOutcome, Evidence, Finding, Status
from .model import ConfigParseError, FirewallConfig, FirewallError, redact_config_snippet


class PfSenseParseError(ConfigParseError):
    pass


_SENSITIVE_PORTS = {"22", "23", "135", "139", "445", "3389", "5900", "5800"}

_RFC1918_NETWORKS = [
    ("10.0.0.0", "255.0.0.0"),
    ("172.16.0.0", "255.240.0.0"),
    ("192.168.0.0", "255.255.0.0"),
]


@dataclass
class _Rule:
    element: ET.Element
    interface: str
    action: str
    protocol: str
    ipprotocol: str
    source: str
    destination: str
    src_port: str
    dst_port: str
    description: str
    disabled: bool


@dataclass
class _PortForward:
    element: ET.Element
    interface: str
    protocol: str
    target: str
    local_port: str
    external_port: str
    source: str
    description: str


@dataclass
class _AnalyzerState:
    config: FirewallConfig
    findings: List[Finding] = field(default_factory=list)
    checks: List[Check] = field(default_factory=list)


def parse_pfsense(path: str) -> FirewallConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise FirewallError("Configuration file not found: %s" % path)
    text = config_path.read_text(encoding="utf-8", errors="replace")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise PfSenseParseError("Invalid XML in %s: %s" % (path, exc)) from exc
    if root.tag != "pfsense":
        raise PfSenseParseError("Root element is not <pfsense>: %s" % root.tag)
    version = root.findtext("version")
    return FirewallConfig(path=path, text=text, root=root, vendor="pfsense", version=version)


def _element_text(element: Optional[ET.Element], default: str = "") -> str:
    if element is None:
        return default
    return (element.text or "").strip() or default


def _bool_element(element: Optional[ET.Element]) -> bool:
    if element is None:
        return False
    if element.text:
        return element.text.strip().lower() in ("1", "true", "enabled", "yes")
    return True


def _address_spec(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    for child in element:
        if child.tag == "any":
            return "any"
        if child.tag in ("network", "thisfirewall"):
            return child.text or child.tag
        if child.tag == "address":
            return child.text or "address"
    return ""


def _port_spec(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    fallback = ""
    for child in element:
        if child.tag == "port" and (child.text or "").strip():
            # An explicit port is more precise than a bare <any/> sibling
            # (pfSense writes <destination><any/><port>445</port></destination>).
            return child.text.strip()
        if child.tag == "any":
            fallback = "any"
    return fallback


def _is_disabled(rule_elem: ET.Element) -> bool:
    return _bool_element(rule_elem.find("disabled"))


def _parse_filter_rules(config: FirewallConfig) -> List[_Rule]:
    rules: List[_Rule] = []
    for elem in config.findall("./filter/rule"):
        rules.append(
            _Rule(
                element=elem,
                interface=_element_text(elem.find("interface")).lower(),
                action=_element_text(elem.find("type"), "pass").lower(),
                protocol=_element_text(elem.find("protocol"), "any").lower(),
                ipprotocol=_element_text(elem.find("ipprotocol"), "inet").lower(),
                source=_address_spec(elem.find("source")),
                destination=_address_spec(elem.find("destination")),
                src_port=_port_spec(elem.find("source")),
                dst_port=_port_spec(elem.find("destination")),
                description=_element_text(elem.find("descr")),
                disabled=_is_disabled(elem),
            )
        )
    return rules


def _parse_port_forwards(config: FirewallConfig) -> List[_PortForward]:
    forwards: List[_PortForward] = []
    for elem in config.findall("./nat/rule"):
        forwards.append(
            _PortForward(
                element=elem,
                interface=_element_text(elem.find("interface")).lower(),
                protocol=_element_text(elem.find("protocol"), "tcp").lower(),
                target=_element_text(elem.find("target")),
                local_port=_element_text(elem.find("local-port")),
                external_port=_port_spec(elem.find("destination")),
                source=_address_spec(elem.find("source")),
                description=_element_text(elem.find("descr")),
            )
        )
    return forwards


def _interface_names(config: FirewallConfig) -> Set[str]:
    interfaces = config.find("interfaces")
    if interfaces is None:
        return set()
    return {child.tag.lower() for child in interfaces if isinstance(child, ET.Element)}


def _is_rfc1918(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    for network, mask in _RFC1918_NETWORKS:
        net_octets = [int(p) for p in network.split(".")]
        mask_octets = [int(p) for p in mask.split(".")]
        if all((octets[i] & mask_octets[i]) == net_octets[i] for i in range(4)):
            return True
    return False


def _webgui_protocol(config: FirewallConfig) -> str:
    webgui = config.find("./system/webgui")
    if webgui is None:
        return "https"
    return _element_text(webgui.find("protocol"), "https").lower()


def _webgui_port(config: FirewallConfig) -> str:
    webgui = config.find("./system/webgui")
    if webgui is None:
        return "443"
    return _element_text(webgui.find("port"), "443")


def _ssh_enabled(config: FirewallConfig) -> bool:
    ssh = config.find("./system/ssh")
    if ssh is None:
        return False
    return _bool_element(ssh.find("enable")) or _bool_element(ssh.find("enabled"))


def _ssh_port(config: FirewallConfig) -> str:
    ssh = config.find("./system/ssh")
    if ssh is None:
        return "22"
    return _element_text(ssh.find("port"), "22")


def _add_finding(
    state: _AnalyzerState,
    rule_id: str,
    control: str,
    title: str,
    severity: str,
    result: Status,
    message: str,
    remediation: str,
    evidence: Evidence,
) -> None:
    evidence.snippet = redact_config_snippet(evidence.snippet)
    finding = Finding(
        rule_id=rule_id,
        control=control,
        title=title,
        severity=severity,
        confidence="high",
        result=result,
        message=message,
        remediation=remediation,
        cwe=[],
        asvs=[],
        owasp=[],
        evidence=evidence,
    )
    state.findings.append(finding)


def _classify_sensitive_port_rule(rule: _Rule) -> Tuple[str, Status, str]:
    """Classify a pass rule on a sensitive port by exposure context.

    Returns ``(severity, result, context)`` where context is one of
    ``wan-any``, ``wan-restricted``, ``internal-any-origin``,
    ``internal-broad`` or ``internal-restricted``.  Internal rules that are
    restricted to specific source networks and specific destination hosts are
    legitimate service access and must not be reported as high-severity
    exposures.

    Exposure is determined by the rule interface: only rules on ``wan``
    (inbound from the Internet) are WAN exposures; rules on internal
    interfaces are egress/service access and are judged by their source and
    destination scope instead.
    """
    if rule.interface == "wan":
        if rule.source == "any":
            return "critical", Status.FAIL, "wan-any"
        return "high", Status.FAIL, "wan-restricted"
    if rule.source == "any":
        return "high", Status.FAIL, "internal-any-origin"
    if rule.destination == "any":
        return "medium", Status.UNVERIFIED, "internal-broad"
    return "low", Status.UNVERIFIED, "internal-restricted"


_SENSITIVE_RULE_COPY = {
    "wan-any": (
        "Sensitive administrative port exposed to any source",
        "A WAN rule allows any source to reach sensitive port %s.",
        "Restrict the source network and expose management ports through a VPN or bastion host only.",
    ),
    "wan-restricted": (
        "Sensitive administrative port exposed on WAN",
        "A rule on the %s interface allows %s to reach sensitive port %s.",
        "Restrict the source to a trusted management network and expose management ports through a VPN or bastion host only.",
    ),
    "internal-any-origin": (
        "Sensitive port reachable from any origin",
        "An internal rule allows any source to reach sensitive port %s.",
        "Restrict the source networks to the hosts that legitimately require this service.",
    ),
    "internal-broad": (
        "Sensitive port reachable toward any destination",
        "A rule on %s allows %s to reach sensitive port %s on any destination.",
        "Limit the destination to the specific hosts that provide this service.",
    ),
    "internal-restricted": (
        "Internal access to a sensitive service",
        "Rule on %s allows %s to reach sensitive port %s on host %s. Confirm this internal access is intentional.",
        "Document and review this internal service access, and keep the source and destination sets as small as possible.",
    ),
}


def _aggregate(findings: List[Finding], checks: List[Check], has_surface: bool) -> Status:
    if any(f.result == Status.FAIL for f in findings):
        return Status.FAIL
    if any(f.result == Status.UNVERIFIED for f in findings):
        return Status.UNVERIFIED
    if any(c.status == Status.FAIL for c in checks):
        return Status.FAIL
    if any(c.status == Status.UNVERIFIED for c in checks):
        return Status.UNVERIFIED
    if not has_surface:
        return Status.NOT_APPLICABLE
    return Status.PASS


def _analyze_admin_exposure(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    webgui = config.find("./system/webgui")
    protocol = _webgui_protocol(config)
    port = _webgui_port(config)

    if webgui is not None and protocol == "http":
        _add_finding(
            state,
            "FW-ADMIN-001",
            "admin-exposure",
            "WebGUI uses cleartext HTTP",
            "high",
            Status.FAIL,
            "The pfSense WebGUI is configured to use HTTP, exposing credentials and session tokens to interception.",
            "Change system/webgui/protocol to 'https' and restrict administrative access to a trusted interface.",
            config.evidence(webgui),
        )
    else:
        state.checks.append(
            Check(
                id="webgui-protocol",
                title="WebGUI protocol",
                status=Status.PASS,
                detail="WebGUI is configured to use HTTPS.",
                evidence=[config.evidence_at_path("./system/webgui")] if webgui is not None else [],
            )
        )

    if webgui is not None and port not in ("443", "8443"):
        _add_finding(
            state,
            "FW-ADMIN-002",
            "admin-exposure",
            "WebGUI listens on a non-standard port",
            "low",
            Status.UNVERIFIED,
            "The WebGUI port (%s) is not the standard HTTPS port. Verify that this is intentional and documented." % port,
            "Consider using port 443 or 8443 for the WebGUI unless a compensating control exists.",
            config.evidence(webgui),
        )

    ssh = config.find("./system/ssh")
    if _ssh_enabled(config):
        ssh_port = _ssh_port(config)
        rules = _parse_filter_rules(config)
        wan_allow = any(
            not r.disabled
            and r.action == "pass"
            and r.interface == "wan"
            and r.protocol in ("tcp", "any")
            and (r.dst_port == ssh_port or r.dst_port == "any")
            and r.destination in ("any", "wanip", "wan")
            for r in rules
        )
        if wan_allow:
            _add_finding(
                state,
                "FW-ADMIN-003",
                "admin-exposure",
                "SSH administrative access allowed from WAN",
                "critical",
                Status.FAIL,
                "A firewall rule permits SSH access on the WAN interface.",
                "Remove the WAN SSH rule or restrict SSH to a trusted management network / VPN.",
                config.evidence(ssh) if ssh is not None else config.evidence(config.root),
            )
        else:
            state.checks.append(
                Check(
                    id="ssh-wan-access",
                    title="SSH WAN access",
                    status=Status.UNVERIFIED,
                    detail="SSH is enabled but no WAN allow rule was found. Verify management access is restricted.",
                    evidence=[config.evidence(ssh)] if ssh is not None else [],
                )
            )
    else:
        state.checks.append(
            Check(
                id="ssh-enabled",
                title="SSH enabled",
                status=Status.NOT_APPLICABLE,
                detail="SSH is not enabled in the configuration.",
            )
        )

    has_surface = webgui is not None or _ssh_enabled(config)
    status = _aggregate(state.findings, state.checks, has_surface)
    reason = _reason_for_status(status, "administrative services", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_rule_permissiveness(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    rules = _parse_filter_rules(config)
    if not rules:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No firewall rules were found in the configuration.",
            checks=[Check(id="rules-present", title="Rules present", status=Status.NOT_APPLICABLE, detail="No filter rules.")],
        )

    permissive_wan = []
    any_to_lan = []
    sensitive_port_rules = []
    conflicts: List[Tuple[_Rule, _Rule]] = []

    for index, rule in enumerate(rules):
        if rule.disabled:
            continue
        source_any = rule.source == "any"
        dest_any = rule.destination == "any"
        protocol_any = rule.protocol == "any"
        if rule.interface == "wan" and rule.action == "pass" and source_any and dest_any and protocol_any:
            permissive_wan.append(rule)
        if rule.action == "pass" and source_any and rule.destination in ("lan", "dmz", "opt1") and protocol_any:
            any_to_lan.append(rule)
        if rule.action == "pass" and rule.dst_port in _SENSITIVE_PORTS:
            sensitive_port_rules.append(rule)
        # Conflict detection: same interface, source, destination, protocol but different actions.
        for other in rules[index + 1 :]:
            if (
                rule.interface == other.interface
                and rule.source == other.source
                and rule.destination == other.destination
                and rule.protocol == other.protocol
                and rule.dst_port == other.dst_port
                and rule.action != other.action
                and not other.disabled
            ):
                conflicts.append((rule, other))

    for rule in permissive_wan:
        _add_finding(
            state,
            "FW-RULE-001",
            "rule-permissiveness",
            "Overly permissive WAN allow rule",
            "critical",
            Status.FAIL,
            "A WAN rule allows any source, any destination and any protocol.",
            "Replace with least-privilege rules that limit source networks, destination addresses and protocols/ports.",
            config.evidence(rule.element),
        )

    for rule in any_to_lan:
        _add_finding(
            state,
            "FW-RULE-002",
            "rule-permissiveness",
            "Any-to-internal network allow rule",
            "high",
            Status.FAIL,
            "A rule allows any source to reach the %s network with any protocol." % rule.destination,
            "Restrict the source to specific networks and limit the destination ports.",
            config.evidence(rule.element),
        )

    for rule in sensitive_port_rules:
        severity, result, context = _classify_sensitive_port_rule(rule)
        title, message_tpl, remediation = _SENSITIVE_RULE_COPY[context]
        if context == "wan-any":
            message = message_tpl % rule.dst_port
        elif context == "wan-restricted":
            message = message_tpl % (rule.interface, rule.source, rule.dst_port)
        elif context == "internal-any-origin":
            message = message_tpl % rule.dst_port
        elif context == "internal-broad":
            message = message_tpl % (rule.interface, rule.source, rule.dst_port)
        else:
            message = message_tpl % (rule.interface, rule.source, rule.dst_port, rule.destination)
        _add_finding(
            state,
            "FW-RULE-003",
            "rule-permissiveness",
            title,
            severity,
            result,
            message,
            remediation,
            config.evidence(rule.element),
        )

    for rule_a, rule_b in conflicts:
        _add_finding(
            state,
            "FW-RULE-004",
            "rule-permissiveness",
            "Conflicting firewall rules",
            "medium",
            Status.UNVERIFIED,
            "Two rules match the same interface, source, destination and protocol but have different actions (%s vs %s)."
            % (rule_a.action, rule_b.action),
            "Review rule ordering and remove or consolidate conflicting rules.",
            config.evidence(rule_b.element),
        )

    if not state.findings:
        state.checks.append(
            Check(
                id="rule-permissiveness",
                title="Rule permissiveness",
                status=Status.PASS,
                detail="No overly permissive WAN rules, any-to-internal rules or sensitive-port exposures were found.",
            )
        )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "firewall rules", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_nat_security(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    forwards = _parse_port_forwards(config)
    if not forwards:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No port forward rules were found.",
            checks=[Check(id="nat-present", title="NAT present", status=Status.NOT_APPLICABLE, detail="No port forwards.")],
        )

    for fwd in forwards:
        if fwd.external_port in _SENSITIVE_PORTS:
            _add_finding(
                state,
                "FW-NAT-001",
                "nat-security",
                "Port forward to sensitive administrative port",
                "critical",
                Status.FAIL,
                "A port forward exposes port %s from WAN to internal host %s." % (fwd.external_port, fwd.target),
                "Remove the forward or restrict it to a VPN/bastion source and use a non-administrative port.",
                config.evidence(fwd.element),
            )
        elif fwd.source == "any":
            _add_finding(
                state,
                "FW-NAT-002",
                "nat-security",
                "Port forward accepts any source",
                "medium",
                Status.UNVERIFIED,
                "Port forward %s -> %s:%s accepts traffic from any source." % (fwd.external_port, fwd.target, fwd.local_port),
                "Restrict the source address/network in the NAT rule or associated filter rule.",
                config.evidence(fwd.element),
            )

    if not state.findings:
        state.checks.append(
            Check(
                id="nat-security",
                title="NAT security",
                status=Status.PASS,
                detail="No port forwards to sensitive ports were found; sources are restricted or documented.",
            )
        )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "NAT rules", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_segmentation(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    names = _interface_names(config)
    interfaces_elem = config.find("interfaces")
    internal = names - {"wan", "lan"}
    has_extra_ifaces = any(
        name.startswith("dmz") or name.startswith("opt") or name.startswith("vlan") for name in internal
    )

    descr_by_name: Dict[str, str] = {}
    if interfaces_elem is not None:
        for iface in interfaces_elem:
            if isinstance(iface, ET.Element):
                descr_by_name[iface.tag.lower()] = _element_text(iface.find("descr")).lower()

    if has_extra_ifaces:
        state.checks.append(
            Check(
                id="segmentation-present",
                title="Segmentation present",
                status=Status.PASS,
                detail="At least one DMZ or optional/VLAN interface is configured: %s." % ", ".join(sorted(internal)),
                evidence=[config.evidence(interfaces_elem)] if interfaces_elem is not None else [],
            )
        )
    else:
        _add_finding(
            state,
            "FW-SEG-001",
            "segmentation",
            "No DMZ or VLAN segmentation",
            "medium",
            Status.UNVERIFIED,
            "Only LAN and WAN interfaces are present. Segmentation of servers or guest networks cannot be verified.",
            "Consider adding a DMZ or VLAN interface for untrusted or public-facing systems.",
            config.evidence(interfaces_elem if interfaces_elem is not None else config.root),
        )

    rules = _parse_filter_rules(config)

    def _active(rule: _Rule) -> bool:
        return not rule.disabled

    # DMZ-like interfaces (by name or description) require an explicit block
    # toward the LAN network.
    dmz_like = sorted(
        name
        for name in internal
        if name == "dmz" or name.startswith("dmz") or "dmz" in descr_by_name.get(name, "")
    )
    if dmz_like:
        dmz_blocks = [
            rule
            for rule in rules
            if _active(rule)
            and rule.action in ("block", "reject")
            and rule.interface in dmz_like
            and rule.destination in ("lan", "any")
        ]
        if dmz_blocks:
            state.checks.append(
                Check(
                    id="dmz-to-lan-block",
                    title="DMZ to LAN block",
                    status=Status.PASS,
                    detail="A rule blocks traffic from DMZ interface(s) %s to the LAN network." % ", ".join(dmz_like),
                    evidence=[config.evidence(rule.element) for rule in dmz_blocks],
                )
            )
        else:
            filter_elem = config.find("filter")
            _add_finding(
                state,
                "FW-SEG-002",
                "segmentation",
                "No block rule from DMZ to LAN",
                "high",
                Status.UNVERIFIED,
                "DMZ interface(s) %s exist but no explicit block rule to LAN was found." % ", ".join(dmz_like),
                "Add a block rule preventing DMZ hosts from initiating connections to the LAN network.",
                config.evidence(filter_elem if filter_elem is not None else config.root),
            )

    # Guest/WiFi isolation: evaluate whether allow rules let the guest network
    # reach the LAN (or any destination) before any explicit block is hit.
    guest_like = sorted(
        name
        for name in internal
        if any(key in (name + " " + descr_by_name.get(name, "")) for key in ("wifi", "wi-fi", "guest", "hotspot"))
    )
    for guest in guest_like:
        guest_rules = [rule for rule in rules if rule.interface == guest and _active(rule)]
        candidates = [
            rule
            for rule in guest_rules
            if (rule.action == "pass" and rule.destination in ("any", "lan"))
            or (rule.action in ("block", "reject") and rule.destination in ("lan", "any"))
        ]
        if not candidates:
            filter_elem = config.find("filter")
            state.checks.append(
                Check(
                    id="guest-isolation",
                    title="Guest/WiFi isolation",
                    status=Status.PASS,
                    detail=(
                        "No allow rules from %s toward the LAN network or any destination were found; "
                        "the default deny posture applies (specific-host service rules may still exist)."
                    )
                    % guest,
                    evidence=[config.evidence(filter_elem if filter_elem is not None else (interfaces_elem or config.root))],
                )
            )
            continue
        first = candidates[0]
        if first.action == "pass":
            _add_finding(
                state,
                "FW-SEG-003",
                "segmentation",
                "Guest/WiFi network can reach internal networks",
                "medium",
                Status.UNVERIFIED,
                "Interface %s has an allow rule toward %s (%s) with no preceding block to LAN. "
                "Guest clients may reach internal hosts." % (guest, first.destination, first.description or "no description"),
                "Add an explicit block rule from %s to the LAN network before broad allow rules, or restrict the allow rules to specific external destinations." % guest,
                config.evidence(first.element),
            )
        else:
            state.checks.append(
                Check(
                    id="guest-isolation",
                    title="Guest/WiFi isolation",
                    status=Status.PASS,
                    detail="Interface %s is explicitly blocked from LAN/any before any allow rule." % guest,
                    evidence=[config.evidence(rule.element) for rule in candidates if rule.action in ("block", "reject")][:3],
                )
            )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "network segmentation", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_logging_ntp(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    syslog = config.find("syslog")
    remote = _element_text(syslog.find("remoteserver")) if syslog is not None else ""

    if syslog is not None and remote:
        state.checks.append(
            Check(
                id="remote-syslog",
                title="Remote syslog configured",
                status=Status.PASS,
                detail="Syslog events are forwarded to %s." % remote,
                evidence=[config.evidence(syslog)],
            )
        )
    elif syslog is not None:
        _add_finding(
            state,
            "FW-LOG-001",
            "logging-ntp",
            "No remote syslog server configured",
            "medium",
            Status.UNVERIFIED,
            "Logs are kept locally. Centralized logging is recommended for tamper resistance and incident response.",
            "Configure a remote syslog server under <syslog><remoteserver>.",
            config.evidence(syslog),
        )
    else:
        _add_finding(
            state,
            "FW-LOG-002",
            "logging-ntp",
            "Syslog configuration not found",
            "medium",
            Status.UNVERIFIED,
            "The configuration does not contain a <syslog> section. Verify that logging is enabled.",
            "Add syslog configuration and a remote log collector.",
            config.evidence(config.root),
        )

    # Time sync evidence: legacy <ntp><timeservers> and pfSense >= 24.0
    # <system><timeservers> both count as valid configuration.
    timeservers = ""
    timeservers_elem: Optional[ET.Element] = None
    ntp = config.find("ntp")
    system_timeservers = config.find("./system/timeservers")
    if ntp is not None:
        candidate = ntp.find("timeservers")
        if candidate is not None and _element_text(candidate):
            timeservers = _element_text(candidate)
            timeservers_elem = candidate
    if not timeservers and system_timeservers is not None and _element_text(system_timeservers):
        timeservers = _element_text(system_timeservers)
        timeservers_elem = system_timeservers

    if timeservers:
        state.checks.append(
            Check(
                id="ntp-servers",
                title="NTP servers configured",
                status=Status.PASS,
                detail="NTP servers: %s" % timeservers,
                evidence=[config.evidence(timeservers_elem)] if timeservers_elem is not None else [],
            )
        )
    elif ntp is not None or system_timeservers is not None:
        if ntp is not None:
            evidence_elem = ntp.find("timeservers") if ntp.find("timeservers") is not None else ntp
        else:
            evidence_elem = system_timeservers
        _add_finding(
            state,
            "FW-LOG-003",
            "logging-ntp",
            "NTP servers not configured",
            "medium",
            Status.FAIL,
            "A time sync section exists but no time servers are defined. Clock drift breaks log correlation and certificate validation.",
            "Configure the timeservers element with reliable NTP sources.",
            config.evidence(evidence_elem),
        )
    else:
        _add_finding(
            state,
            "FW-LOG-004",
            "logging-ntp",
            "NTP configuration not found",
            "medium",
            Status.UNVERIFIED,
            "No time synchronization configuration was found (<ntp> or <system><timeservers>). Verify that the firewall synchronizes time.",
            "Add NTP configuration.",
            config.evidence(config.root),
        )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "logging and time sync", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_vpn_security(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    ipsec = config.find("ipsec")
    openvpn = config.find("openvpn")
    # An <ipsec> or <openvpn> element alone is not evidence of a configured
    # VPN; the tunnel-defining children must exist.
    phase1s = list(ipsec.findall("phase1")) if ipsec is not None else []
    ovpn_tunnels = (
        [child for child in openvpn if isinstance(child, ET.Element) and child.tag in ("openvpn-server", "openvpn-client")]
        if openvpn is not None
        else []
    )
    has_vpn = bool(phase1s) or bool(ovpn_tunnels)

    if not has_vpn:
        if ipsec is not None or openvpn is not None:
            detail = "VPN elements exist but contain no IPsec phase1 or OpenVPN tunnel definitions."
        else:
            detail = "No VPN tunnels."
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No IPsec or OpenVPN tunnels are configured.",
            checks=[Check(id="vpn-present", title="VPN present", status=Status.NOT_APPLICABLE, detail=detail)],
        )

    for phase1 in phase1s:
        mode = _element_text(phase1.find("mode")).lower()
        if mode == "aggressive":
            _add_finding(
                state,
                "FW-VPN-001",
                "vpn-security",
                "IPsec aggressive mode",
                "high",
                Status.FAIL,
                "IPsec phase 1 is configured in aggressive mode, which is vulnerable to offline pre-shared-key attacks.",
                "Use main mode with certificate-based authentication or migrate to IKEv2.",
                config.evidence(phase1),
            )

    for server in ovpn_tunnels:
        mode = _element_text(server.find("mode")).lower()
        if mode == "p2p_shared_key":
            _add_finding(
                state,
                "FW-VPN-002",
                "vpn-security",
                "OpenVPN shared-key mode",
                "medium",
                Status.UNVERIFIED,
                "OpenVPN is using a pre-shared key. Key distribution and rotation are harder than with TLS.",
                "Use OpenVPN TLS mode with certificates and unique client keys.",
                config.evidence(server),
            )

    if not state.findings:
        tunnel_elems = phase1s + ovpn_tunnels
        state.checks.append(
            Check(
                id="vpn-security",
                title="VPN security",
                status=Status.PASS,
                detail="No obviously weak VPN modes were detected across %d configured tunnel(s)." % len(tunnel_elems),
                evidence=[config.evidence(elem) for elem in tunnel_elems[:5]],
            )
        )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "VPN configuration", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_interface_security(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    interfaces = config.find("interfaces")
    if interfaces is None:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No interfaces section found.",
            checks=[Check(id="interfaces-present", title="Interfaces present", status=Status.NOT_APPLICABLE, detail="No interfaces.")],
        )

    enabled_missing: List[str] = []
    wan_elem: Optional[ET.Element] = None
    wan_ip = ""
    iface_count = 0
    for iface in interfaces:
        if not isinstance(iface, ET.Element):
            continue
        iface_count += 1
        name = iface.tag.lower()
        ip = _element_text(iface.find("ipaddr"))
        enabled = _bool_element(iface.find("enable"))
        if name == "wan":
            wan_elem = iface
            wan_ip = ip
        if not enabled:
            enabled_missing.append(name)
            _add_finding(
                state,
                "FW-IFACE-002",
                "interface-security",
                "Interface is disabled",
                "info",
                Status.UNVERIFIED,
                "Interface %s is not enabled. Verify this is intentional." % name,
                "Enable the interface or remove unused configuration.",
                config.evidence(iface),
            )

    if not enabled_missing:
        state.checks.append(
            Check(
                id="interface-enabled",
                title="Interfaces enabled",
                status=Status.PASS,
                detail="All %d configured interface(s) are enabled." % iface_count,
                evidence=[config.evidence(interfaces)],
            )
        )

    if wan_elem is not None:
        if wan_ip in ("", "dhcp", "pppoe"):
            # Dynamically addressed WAN: the RFC 1918 question cannot be
            # answered from the exported configuration alone.
            state.checks.append(
                Check(
                    id="wan-address",
                    title="WAN address",
                    status=Status.UNVERIFIED,
                    detail=(
                        "WAN address is assigned dynamically (%s); whether the runtime address is "
                        "public or private cannot be verified from the configuration." % (wan_ip or "unspecified")
                    ),
                    evidence=[config.evidence(wan_elem)],
                )
            )
        elif _is_rfc1918(wan_ip):
            _add_finding(
                state,
                "FW-IFACE-001",
                "interface-security",
                "WAN interface uses RFC 1918 address",
                "low",
                Status.UNVERIFIED,
                "WAN IP %s is in a private range. This may indicate double NAT; verify the deployment context." % wan_ip,
                "Confirm the upstream connection and document whether double NAT is intentional.",
                config.evidence(wan_elem),
            )
        else:
            state.checks.append(
                Check(
                    id="wan-address",
                    title="WAN address",
                    status=Status.PASS,
                    detail="WAN uses a static non-private address (%s)." % wan_ip,
                    evidence=[config.evidence(wan_elem)],
                )
            )
    else:
        state.checks.append(
            Check(
                id="wan-address",
                title="WAN address",
                status=Status.NOT_APPLICABLE,
                detail="No WAN interface was found in the configuration.",
            )
        )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "interface configuration", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _analyze_ipv6_security(config: FirewallConfig) -> ControlOutcome:
    state = _AnalyzerState(config)
    interfaces = config.find("interfaces")
    if interfaces is None:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="No interfaces section found.",
            checks=[Check(id="ipv6-present", title="IPv6 present", status=Status.NOT_APPLICABLE, detail="No interfaces.")],
        )

    ipv6_enabled = False
    for iface in interfaces:
        if not isinstance(iface, ET.Element):
            continue
        ipv6 = _element_text(iface.find("ipaddrv6"))
        if ipv6 and ipv6.lower() not in ("none", ""):
            ipv6_enabled = True
            break

    if not ipv6_enabled:
        return ControlOutcome(
            status=Status.NOT_APPLICABLE,
            reason="IPv6 does not appear to be enabled on any interface.",
            checks=[Check(id="ipv6-enabled", title="IPv6 enabled", status=Status.NOT_APPLICABLE, detail="IPv6 not enabled.")],
        )

    rules = _parse_filter_rules(config)

    def _is_ipv6_rule(rule: _Rule) -> bool:
        return rule.ipprotocol in ("inet6", "inet46") or rule.protocol in ("icmp6", "ipv6-icmp")

    active_ipv6_rules = [rule for rule in rules if _is_ipv6_rule(rule) and not rule.disabled]
    if not active_ipv6_rules:
        filter_elem = config.find("filter")
        _add_finding(
            state,
            "FW-IPV6-001",
            "ipv6-security",
            "IPv6 enabled but no active IPv6 firewall rules",
            "medium",
            Status.UNVERIFIED,
            "IPv6 is configured on at least one interface, but no active (non-disabled) IPv6-specific "
            "rules were identified. Disabled rules do not provide protection.",
            "Add explicit IPv6 block rules on WAN and review ICMPv6 handling.",
            config.evidence(filter_elem if filter_elem is not None else config.root),
        )
    else:
        state.checks.append(
            Check(
                id="ipv6-rules",
                title="IPv6 rules",
                status=Status.PASS,
                detail="IPv6 is enabled and %d active IPv6-specific rule(s) were found." % len(active_ipv6_rules),
                evidence=[config.evidence(rule.element) for rule in active_ipv6_rules[:5]],
            )
        )

    status = _aggregate(state.findings, state.checks, True)
    reason = _reason_for_status(status, "IPv6 configuration", state.findings)
    return ControlOutcome(status=status, reason=reason, checks=state.checks, findings=state.findings)


def _reason_for_status(status: Status, topic: str, findings: List[Finding]) -> str:
    if status == Status.PASS:
        return "%s passed all configured checks." % topic.capitalize()
    if status == Status.FAIL:
        return "%s failed %d check(s)." % (topic, sum(1 for f in findings if f.result == Status.FAIL))
    if status == Status.UNVERIFIED:
        return "%s has unresolved checks that require manual review." % topic.capitalize()
    return "%s is not applicable to this configuration." % topic.capitalize()


_ANALYZERS = [
    ("admin-exposure", _analyze_admin_exposure),
    ("rule-permissiveness", _analyze_rule_permissiveness),
    ("nat-security", _analyze_nat_security),
    ("segmentation", _analyze_segmentation),
    ("logging-ntp", _analyze_logging_ntp),
    ("vpn-security", _analyze_vpn_security),
    ("interface-security", _analyze_interface_security),
    ("ipv6-security", _analyze_ipv6_security),
]


def analyze_pfsense(config: FirewallConfig) -> List[Tuple[str, ControlOutcome]]:
    return [(control_id, analyzer(config)) for control_id, analyzer in _ANALYZERS]


def control_ids() -> List[str]:
    return [control_id for control_id, _ in _ANALYZERS]
