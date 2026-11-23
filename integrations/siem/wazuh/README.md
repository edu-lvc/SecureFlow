# Wazuh adapter for SecureFlow Sigma rules

This is an optional, desacoplada adapter. It transforms SecureFlow-generated Sigma
rules into Wazuh rule XML stubs. The stubs must be reviewed before deployment.

## What it does

- Reads Sigma rules (YAML or JSON) from a directory.
- Emits Wazuh XML rule fragments with `<group>`, `<rule>`, `<match>`, and `<description>` tags.
- Maps Sigma `logsource` fields to Wazuh `location` hints when possible.
- Preserves MITRE technique IDs in `<mitre>` tags where supported by the Wazuh version.

## What it does NOT do

- It does not install rules into a Wazuh manager.
- It does not validate against Wazuh's XML schema.
- It does not replace Sigma; it is a translation helper.

## Usage

```powershell
python integrations/siem/wazuh/sigma-to-wazuh.py --sigma-out sigma-rules --out wazuh-rules.xml
```

Copy the generated XML into your Wazuh manager's custom rule directory
(typically `/var/ossec/etc/rules/`) and restart the manager after review.

## Limitations

- Sigma `detection` logic is reduced to a set of `<match>` and `<field>` hints.
- Complex condition trees (`and`, `or`, `not`, `near`) are emitted as comments for manual review.
- Only `windows`, `sysmon`, `webserver`, and `okta` logsource products have coarse mappings.
