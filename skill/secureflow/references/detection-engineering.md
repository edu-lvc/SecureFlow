# Detection Engineering

SecureFlow can turn gate findings into detection guidance. This is not a SIEM and it does not
replace a SOC, but it closes the loop between code review and detectable telemetry.

## How it works

1. A rule or analyzer tags a finding with `mitre_attack` technique IDs and `telemetry_sources`.
2. The engine aggregates active findings into a coverage ledger.
3. For every technique that has a curated mapping and a compatible telemetry source, SecureFlow
   can emit a Sigma rule stub.
4. Security teams review the stub, refine the `logsource` and `detection` sections, and deploy it
   to a SIEM.

## MITRE ATT&CK mapping

Mappings are stored in `data/mitre-mapping.json`. Each technique record contains:

- `technique_id` — e.g. `T1190`.
- `tactics` — e.g. `["Initial Access"]`.
- `applicable_controls` — SecureFlow controls that can surface the technique.
- `telemetry_sources` — recommended data sources for detection.
- `description` and `rationale` — why the mapping is justified.

Only mappings with a documented rationale are used. Speculative mappings are not generated.

## Telemetry sources

`data/telemetry-sources.json` lists sources such as `wazuh`, `sysmon`, `web_server_logs`,
`windows_security`, `azure_ad`, `sentinel`, `elastic`, `splunk`, `okta`, `network_ids`, and
`endpoint_files`. Each source records the products, log formats, and typical log locations.

A Sigma rule is generated only when a finding's control, its technique mapping, and a telemetry
source all align.

## Commands

Generate Sigma rules during a scan:

```powershell
python skill/secureflow/scripts/secureflow-gate.py scan `
  --root examples\csharp-vulnerable\VulnerableOrders.Api `
  --sigma-out sigma-rules --sigma-format yaml
```

Generate Sigma rules from an existing report:

```powershell
python skill/secureflow/scripts/secureflow-gate.py generate-sigma `
  --report report.json --out sigma-rules --format yaml
```

## Coverage ledger

The gate report contains a `detections` section:

- `covered_controls` — controls with at least one generated Sigma rule.
- `uncovered_controls` — controls surfaced by the scan but without a detection mapping.
- `mitre_techniques` — techniques covered, with tactics and sources.
- `sigma_rules_generated` — count of generated rules.
- `missing_detection_justifications` — reasons why a control has no detection yet.

## Sigma rule contents

Each generated rule includes:

- `title`, `id`, `status: experimental`
- `logsource` mapped from the telemetry source
- `detection` block with placeholder selection logic
- `falsepositives`
- `level` derived from severity
- `tags` with MITRE technique and tactic
- `references` pointing to the source file and line
- `metadata` with the originating SecureFlow rule and control

## Limitations

- Generated rules are **stubs**. They must be reviewed and tuned before deployment.
- The log source mapping is generic; real environments need field names and indices.
- A finding with no `mitre_attack` or no compatible telemetry source cannot generate a rule.
- The gate cannot prove that the SIEM actually receives the events.
- Sigma YAML is emitted with a minimal stdlib emitter. Complex strings are double-quoted and
  escaped; validate the output with a Sigma parser before production use.
