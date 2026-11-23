# Incident Response Templates

SecureFlow provides lightweight, structured templates for documenting security incidents. The
templates are designed to be filled by a human analyst, not generated automatically from a scan.

## Templates

- `incident-response-template.md` — full incident record.
- `ioc-template.md` — indicators of compromise.
- `timeline-template.md` — event timeline.

## Creating a response package

```powershell
python skill/secureflow/scripts/secureflow-gate.py init-incident --output incident-2026-11-22
```

This copies the three templates into the output directory. Use `--force` to overwrite an existing
directory.

## Required fields

`incident-response-template.md` expects:

- `id` — incident identifier.
- `detected_at` — date and time of detection.
- `reporter` — who reported it.
- `summary` — one-paragraph description.
- `affected_systems` — hosts, applications, networks.
- `attack_description` — what the attacker did.
- `iocs` — link to `ioc-template.md`.
- `timeline` — link to `timeline-template.md`.
- `mitre_attack` — mapped techniques and tactics.
- `containment` — actions taken to limit impact.
- `eradication` — actions taken to remove the threat.
- `recovery` — actions taken to restore service.
- `root_cause` — why the incident was possible.
- `lessons_learned` — process or control improvements.
- `evidence_location` — where evidence is stored.
- `status` — open, contained, closed.

## Relationship with the gate

The gate does not create incidents. It provides:

- Verified findings to include in the incident record.
- MITRE ATT&CK mappings to copy into the template.
- Sigma rule stubs that may become detection items in the timeline.
- A deterministic report with hashes that can be attached as evidence.

## Safety rules

- No template triggers automatic containment, deletion, or network changes.
- The `init-incident` command only writes Markdown files.
- The analyst must decide what to do with the documented information.
