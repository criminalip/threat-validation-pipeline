# Enforcement Flow

## Evaluation Engine

Core function:

evaluate_rules(...)

Example return structure:

{
  "ip": "1.2.3.4",
  "port": 22,
  "suspicious": true,
  "reasons": [...]
}

If suspicious == true:

- Firewall API is invoked
- SOAR playbook may be executed
- SIEM may be enriched with decision context

## Enforcement Options

- Firewall API block
- SOAR orchestration
- Cloud security policy update
- Alert notification (Slack, Email)

This ensures consistent and repeatable automated decisions.
