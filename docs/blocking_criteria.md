# Blocking Criteria
All validation checks are based on:

https://api.criminalip.io/v1/asset/ip/report

---

## 1. Reputation Score

Block if score is:

- Dangerous
- Critical



## 2. SSL Certificate Anomalies

Block if certificate is:

- Self-signed
- Expired



## 3. Directory Listing Exposure

Block if tag includes:

- directory listing



## 4. Mining Infrastructure Detection

Block if tag includes:

- mining



## 5. VPN / Tor / Proxy Detection

Block if indicators show:

- vpn
- anonymous vpn
- tor
- proxy

Detection fields may include:

- issues.is_vpn
- issues.is_tor
- issues.is_proxy
- ip_category.type



## 6. SSH Exposure

Block if:

- Destination port = 22
- OpenSSH detected on any port


Blocking logic is implemented within the evaluation engine.

If `suspicious == true`, automated enforcement is triggered.
