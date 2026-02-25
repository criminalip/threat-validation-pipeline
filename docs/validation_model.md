# Validation Model

## Core Principle

All operational profiles share a unified model:

Event-Driven + Timeline-Based + Selective Threat Validation

## Why Event-Driven?

Security alerts typically indicate that malicious activity has already occurred.  
Validating traffic immediately preceding the alert enables identification of associated malicious infrastructure.

---

## API Endpoint Used

The validation engine uses:

https://api.criminalip.io/v1/asset/ip/report

Validation is performed per extracted public IP address and evaluated against defined blocking criteria.

---

## Timeline-Based Analysis

Instead of continuous monitoring, the model focuses on a defined time window prior to a triggering event (e.g., five minutes).

This reduces noise and concentrates analysis on relevant activity.

## Selective Validation Strategy

The system does not inspect all traffic indiscriminately.

Traffic is validated only when it meets contextual criteria:

- Event-triggered windows
- Non-HTTP/HTTPS ports
- Critical service ports
- After-hours activity

This approach:

- Reduces API usage
- Minimizes operational overhead
- Improves detection precision

## Not a Reputation-Only Model

Validation combines multiple infrastructure-level indicators rather than relying on reputation scores alone.
