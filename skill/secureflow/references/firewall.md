# Firewall Security Assessment

This reference describes the SecureFlow firewall module. It is currently implemented for
**pfSense** configurations. Other vendors require their own parser and analyzer plugins.

## Scope

The firewall module reads a configuration file (XML for pfSense) and evaluates it without
connecting to a live device. It is designed for:

- Configuration audits before deployment.
- Baseline verification of existing exports.
- Change planning and dry-run impact analysis.

It is **not** a live vulnerability scanner and it does not replace packet-level testing.

## Modes

`secureflow-gate firewall audit --config config.xml`
: Read-only assessment. Generates a report with `PASS`, `FAIL`, `UNVERIFIED`, or
  `NOT_APPLICABLE` statuses.

`secureflow-gate firewall plan --config config.xml --changes changes.json`
: Proposes configuration changes, explains consequences, and writes a change plan. Does not
  modify the source file.

`secureflow-gate firewall apply --config config.xml --plan changes.json --output new.xml --backup backup.xml --confirm`
: Applies a previously approved plan, writes the modified configuration, keeps a backup, and
  re-audits the result. `--confirm` is required. Without it the command prints the plan and
  exits.

Dry-run is the default behavior for `audit` and `plan`. `apply` is the only mode that writes a
new configuration, and it always requires an explicit flag.

## Controls

| Control | What it checks |
| --- | --- |
| `admin-exposure` | WebGUI/SSH listening on WAN or unencrypted HTTP, default/weak ports. |
| `rule-permissiveness` | Rules with source/destination `any`, overbroad protocols, shadowed rules. |
| `nat-security` | Port forwards to sensitive ports or without source restrictions. |
| `segmentation` | Presence of DMZ/VLAN interfaces and block rules between segments. |
| `logging-ntp` | Syslog forwarding, local logging retention, NTP configuration. |
| `vpn-security` | IPsec/OpenVPN weak or uncommon settings. |
| `interface-security` | Interface IP configuration, enabled/disabled state, description. |
| `ipv6-security` | IPv6 enablement and minimal policy presence. |

## Report schema

Firewall reports use `schema_version: secureflow.firewall.report/v1`. The structure mirrors the
gate report: `summary`, `controls`, `findings`, `recommendations`, `changes`, `integrity`. Each
finding includes the XML element path, line, and a redacted snippet.

## Redaction

Passwords, shared secrets, pre-shared keys, certificates, and token-like values are masked in
report snippets. The original file is never modified by `audit` or `plan`.

## Limitations

- Only pfSense XML is supported. OPNsense, FortiGate, PAN-OS, Cisco ASA are not implemented.
- The parser is heuristic. Complex aliases, schedules, floating rules, and custom packages may be
  skipped.
- `apply` rewrites XML using element replacement; namespace changes or unsupported elements may be
  lost. Always review the output and keep the backup.
- The module cannot prove that a rule is actively hit or that traffic behaves as intended.
- Credentials in the XML are redacted in reports, but the source XML still contains them. Protect
  configuration exports accordingly.
