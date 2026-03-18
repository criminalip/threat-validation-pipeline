# Threat Validation & Auto-Blocking Pipeline

> Most security alerts represent the result of malicious activity — not the beginning.

Event-driven public IP validation framework that applies multi-factor infrastructure risk evaluation and automated enforcement.

---

## Overview

When a security event is triggered (e.g., malware alert, phishing detection, privileged login), the relevant infrastructure may already have communicated with additional malicious systems.

This framework:

- Retrieves outbound connections from a defined time window (e.g., previous five minutes)
- Extracts externally routable public IP addresses
- Validates them using the Criminal IP API
- Applies multi-factor infrastructure risk evaluation
- Automatically enforces blocking decisions when required

---

## Selective Validation Strategy

This framework does **not** perform full traffic inspection.

Instead, it validates only:

- Time-bound traffic (event-triggered windows)
- Contextually relevant outbound connections
- Statistically abnormal traffic (e.g., non-80/443 ports)
- Operationally low-noise segments (e.g., after-hours activity)

This selective validation approach minimizes API usage while maximizing detection precision.

All operational profiles follow the same principle:

**Event-Driven + Timeline-Based + Selective Threat Validation**

---

## Architecture
The pipeline operates as a contextual validation workflow:
```text
┌──────────────────────────────────────────┐
│              Security Event              │
│        (EDR / URL Filter / Login)        │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│        Firewall Log Backtracking         │
│              (Time-bound)                │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│        Criminal IP API Validation        |
|          (/v1/asset/ip/report)           │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│        Multi-Factor Risk Evaluation      │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│  Automated Firewall / SOAR Enforcement   │
└──────────────────────────────────────────┘
```

---

## Risk Evaluation Model
>This is **not** a reputation-only lookup.

An IP may be classified as suspicious if one or more of the following conditions are met:

- Reputation score: `Dangerous` or `Critical`
- SSL anomalies (self-signed / expired)
- Vulnerability exposure (e.g., directory listing)
- Mining infrastructure detection
- VPN / Tor / Proxy detection
- SSH exposure (port-based or product-based)

---
## Full API Endpoint Reference

All IP validations are performed using the following endpoint:

https://api.criminalip.io/v1/asset/ip/report

Ensure proper authentication headers are included in production deployments.

---

# 🚀[Quick Start]
Run a simple validation test.
### 1. Install dependencies
pip install requests

### 2. Configure API key
```bash
{
  "api_key": "YOUR_CRIMINAL_IP_API_KEY"
}
```

### 3. Run single IP validation
python cip_ip_report_check.py --ip 1.2.3.4 --pretty

### 4. Include port(optional)
python cip_ip_report_check.py --ip 1.2.3.4 --port 22 --pretty

### 5. Include product hint (optional, non-standard SSH ports)
python cip_ip_report_check.py --ip 1.2.3.4 --port 2022 --product OpenSSH --pretty

### 6. Debug (full JSON)
python cip_ip_report_check.py --ip 1.2.3.4 --dump-json

## Example Output

[SUSPICIOUS] 1.2.3.4:22
- Reputation: Critical
- SSL: Self-signed certificate
- Service: OpenSSH
- Anonymity: Proxy detected

---

## Production Considerations

When deploying in operational environments, consider:

- Whitelist management  
- Block duration (TTL) policies  
- False-positive handling  
- API rate limit management  

See `docs/production_considerations.md` for detailed guidance.

---
## Practical Use Cases

- SOC automated response workflows  
- MSSP blacklist automation  
- Enterprise firewall automation  
- Kubernetes ingress protection  
- DNS anomaly validation  
---

## Documentation

Detailed documentation is available in:

- [Architecture document](docs/architecture.md)
- [Validation Model](docs/validation_model.md)
- [Operational Scenarios](docs/operational_scenarios.md)
- [Blocking Criteria](docs/blocking_criteria.md)
- [Production Considerations](docs/production_considerations.md)
- [Integration Guide](docs/integration_guide.md)

---

## Core Value Proposition

This is not a simple IP reputation lookup.

The system performs multi-factor infrastructure risk validation by combining:

- Reputation scoring
- SSL certificate anomaly detection
- Vulnerability tag analysis
- Mining infrastructure detection
- Anonymity infrastructure detection (VPN/Tor/Proxy)
- SSH exposure detection (port-based and product-based)

This results in a multi-indicator automated blocking model suitable for:

- Security automation demonstrations
- SOC production workflows
- Enterprise defensive architecture design
