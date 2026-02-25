# Architecture 

This project implements an event-driven threat validation and automated blocking pipeline designed for enterprise office network environments. 

## High-Level Flow
```text
┌──────────────────────────────────────────┐
│              Security Event              │
│        (EDR / URL Filter / Login)        │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│            SIEM Detection &              |
|         Timestamp Identification         │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│        Firewall Log Backtracking         |
|           (Time-Bound Window)            │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│           Public IP Extraction           |
|         (Exclude Internal Ranges)        │
└──────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────┐
│        Criminal IP API Validation        |
|         (/v1/asset/ip/report)            │
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
                    │
                    ▼
┌──────────────────────────────────────────┐
│     Continuous Monitoring & Logging      │
└──────────────────────────────────────────┘
```

---

## Key Design Components 

1. Event Trigger The system activates only when a security-relevant event is detected. 

2. Timeline-Based Backtracking A defined time window (e.g., five minutes prior to the event) is analyzed to identify related outbound connections. 

3. Selective Public IP Extraction Only externally routable IP addresses are evaluated. Internal traffic is excluded. 

4. Multi-Factor Risk Evaluation Infrastructure risk is evaluated using multiple indicators rather than reputation alone. 

5. Automated Enforcement If risk conditions are met, blocking actions are executed automatically via firewall or SOAR integration. 

This design ensures contextual validation, operational efficiency, and repeatable enforcement. 

---

## Operational Overview

The system operates as an event-driven validation and enforcement pipeline.

1. Public IP addresses are extracted from firewall logs collected by SIEM.
2. Internal and private ranges are excluded.
3. Each public IP is validated using:

   https://api.criminalip.io/v1/asset/ip/report

4. Multi-factor rule logic evaluates infrastructure risk.
5. If risk conditions are met, automated enforcement is triggered.

This ensures consistent, repeatable, and auditable security decisions.
