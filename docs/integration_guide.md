# Integration Guide

## Firewall Integration

Example:

```python
if suspicious:
    firewall_api.block_ip(dest_ip)

Supported integrations may include:

- Palo Alto API
- Fortinet API
- iptables
- AWS WAF
- Azure NSG
- Cloudflare
- Kubernetes NetworkPolicy
```
## SOAR Integration

If suspicious:
- Trigger SOAR webhook
- Execute response playbook
- Update ticketing system

## SIEM Enrichment

- Append risk indicators
- Add infrastructure metadata
- Record automated decision context
