# SIEM Investigations

A collection of SIEM investigation reports and detection engineering case studies from hands-on lab exercises.

## Investigations

- [SSH Brute Force and Lateral Movement](siem-brute-force-lateral-movement-lab-report.md) — synthetic Docker SIEM case covering authentication failures, a successful login, lateral movement, threshold rule validation, alert review, and ATT&CK mapping.
- [Data Exfiltration via DNS Tunneling](siem-dns-tunneling-data-exfiltration-lab-report.md) — synthetic DNS TXT tunneling case covering query review, ATT&CK mapping, and threshold-rule validation.
- [Phishing to C2 Beaconing](siem-phishing-c2-beaconing-lab-report.md) — synthetic attachment execution, encoded PowerShell, payload launch, repeated proxy callbacks, and alert review.
- [Privilege Escalation and Persistence](siem-privilege-escalation-persistence-lab-report.md) — synthetic kernel escalation, privileged account creation, cron persistence, cleanup, and log-tampering investigation.

## Detection rules

Portable event detections are stored as Sigma YAML under [detections](detections/). The rules use the lab's normalized field names and are marked test; map those fields to the target SIEM and validate them against representative production telemetry before deployment. App-native threshold JSON and validation results are included in each report.

The reports use an incident-record structure informed by [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) and map observed behavior to [MITRE ATT&CK](https://attack.mitre.org/).

## Scope and attribution

The reports use synthetic lab telemetry; no production systems were accessed or remediated. Each report identifies and credits the SIEM or lab project it uses. This repository contains the investigation write-ups and detection artifacts, not the underlying tools.
