# Operational Scenarios

## 1. Malware Infection Alert

**Trigger:** Endpoint malware alert recorded in SIEM.

**Process:**
- Retrieve firewall logs from previous five minutes
- Filter by affected source IP
- Extract public IP connections
- Validate using Criminal IP API
- Block confirmed high-risk IPs

---

## 2. Phishing or Malicious Link Click

**Trigger:** URL filter or proxy alert.

**Process:**
- Retrieve outbound traffic for five minutes prior
- Extract related public IP connections
- Validate each IP
- Block malicious infrastructure beyond initial domain

---

## 3. Developer Login to Critical Systems

**Trigger:** Login to servers, databases, audit systems.

**Process:**
- Retrieve outbound traffic prior to login
- Validate public IP communications
- Block high-risk infrastructure to prevent lateral movement

---

## 4. After-Hours Traffic

**Trigger:** Late-night outbound traffic from endpoints.

**Process:**
- Validate all outbound public IP connections
- Focus on low-noise environment
- Block suspicious infrastructure

---

## 5. Non-80/443 Traffic

**Trigger:** Outbound traffic excluding ports 80 and 443.

**Rationale:**

Over 95% of normal office traffic uses HTTP/HTTPS.

Non-standard ports are statistically more likely to indicate abnormal behavior.

---

## 6. Critical Well-Known Ports

**Trigger:** Outbound connections to ports such as:

- 22 (SSH)
- 3389 (RDP)
- 445 (SMB)
- 3306 (MySQL)
- 1104 and similar ports

External public IPs on these ports are validated and blocked if suspicious.
