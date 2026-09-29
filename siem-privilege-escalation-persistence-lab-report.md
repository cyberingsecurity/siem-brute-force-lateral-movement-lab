# SIEM Investigation Report: Privilege Escalation and Persistence

Portfolio lab report · Environment: local Dockerized SIEM training lab · Data: synthetic playbook telemetry · Run date: 2026-09-29

## Executive summary

The Privilege Escalation and Persistence playbook generated 20 events on **app-server-01** (10.1.2.10). A successful service-account login was followed by a High privilege_escalation event as root, with /bin/bash -p launched under the .exploit parent. The sequence then created local account sysadm1n and added it to the sudo group, installed a cron reverse shell targeting 203.0.113.42:4444, removed the exploit files, and truncated /var/log/syslog.

Two High-severity rules were tested and produced one New alert each after replay: **Kernel Privilege Escalation** and **Unexpected Account Creation**. Both alerts remained New at capture. The existing **Sequence - Exec to Privilege Escalation** rule returned zero in its test preview, so it was not treated as validated coverage.

Assessment: the generated event chain represents privilege escalation, account-based persistence, scheduled execution, and defense evasion. This was synthetic lab telemetry; no containment or remediation was applied to real systems.

## Scope and evidence

- Scenario: Privilege Escalation and Persistence (20 generated events per playbook run).
- SIEM views used: Dashboard, Log Viewer, Rules, rule-test preview, and Alerts.
- Event sources observed: auth, endpoint, and IDS.
- Evidence reviewed: login and account events, usernames, host, command lines, parent processes, file paths, timestamps, severities, rule conditions, alert matched-event summaries, and ATT&CK tags.
- Time handling: times below are copied from the SIEM UI. The UI did not show a timezone, so they are not normalized to UTC.
- Validation: the playbook was replayed after rule creation. Counts below describe one run.

## Investigation timeline

| UI time (Sep 29) | Evidence | Interpretation |
|---|---|---|
| 10:03:51 | auth/login_success to 10.1.2.10 as svc-webapp, source 10.1.3.25. | Service-account access to the affected host. |
| 10:04:02 | High endpoint/privilege_escalation as root; command /bin/bash -p, parent .exploit, host app-server-01; tagged T1068. | Successful simulated kernel exploit and privilege escalation. |
| 10:04:03 | auth/account_created by root; local useradd succeeded; message says sysadm1n was added to the sudo group. | New privileged local account, tagged T1136.001. |
| 10:04:05 | crontab command installs */5 * * * * reverse shell to 203.0.113.42:4444; tagged T1053.005. | Scheduled-task persistence. |
| 10:04:05 | rm -f /tmp/.exploit /tmp/.exploit.c; message says exploit binary and source were removed; tagged T1070.004. | Removal of exploit artifacts. |
| 10:04:06 | truncate -s 0 /var/log/syslog; tagged T1070.002. | System log clearing. |
| 10:04:07 | Medium IDS alert from 10.1.2.10 toward 203.0.113.42. | Additional network-security telemetry observed after persistence and cleanup actions. |

## Detection rules and validation

### Kernel Privilege Escalation

**Severity / type:** High / Threshold  
**Logic:** one endpoint privilege_escalation event for a host within 300 seconds.

~~~json
{
  "event_filter": {
    "source_type": "endpoint",
    "event_type": "privilege_escalation"
  },
  "threshold": 1,
  "window_seconds": 300,
  "group_by": "hostname"
}
~~~

The preview evaluated 272 events and predicted one alert. After replay, Alerts showed one High/New alert for app-server-01 with one matched event at 10:04:02.

### Unexpected Account Creation

**Severity / type:** High / Threshold  
**Logic:** one auth account_created event for a host within 300 seconds.

~~~json
{
  "event_filter": {
    "source_type": "auth",
    "event_type": "account_created"
  },
  "threshold": 1,
  "window_seconds": 300,
  "group_by": "hostname"
}
~~~

The preview evaluated 272 events and predicted one alert. After replay, Alerts showed one High/New alert for app-server-01 with one matched event at 10:04:03.

The existing **Sequence - Exec to Privilege Escalation** rule filtered on mitre_tactic: TA0004 and tested with zero alerts. The two rules above use event fields that produced confirmed results. The portable Sigma rule is [privilege_escalation_persistence.yml](detections/privilege_escalation_persistence.yml); it includes separate selections for privilege escalation, account creation, cron persistence, and log clearing.

The two app-native rules are event-type detections. They do not by themselves correlate account creation, cron installation, and log clearing to the earlier service-account login. The analyst timeline provides that context.

## ATT&CK mapping

| Technique | Observed behavior |
|---|---|
| [T1068 – Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | /bin/bash -p as root under .exploit. |
| [T1136.001 – Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) | Local sysadm1n account added to the sudo group. |
| [T1053.005 – Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | crontab installs a five-minute reverse shell. |
| [T1070.002 – Indicator Removal: Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002/) | /var/log/syslog truncated. |
| [T1070.004 – Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/) | Exploit binary and source removed from /tmp. |

## Analyst assessment

- Initial access to the host: successful login as svc-webapp from 10.1.3.25.
- Privilege escalation: root shell via /bin/bash -p after .exploit.
- Persistence: sudo-group account sysadm1n and a cron reverse shell to 203.0.113.42:4444.
- Defense evasion: exploit files removed and /var/log/syslog truncated.
- Alert status at capture: both new rules produced High/New alerts; neither was acknowledged or resolved.
- Confidence: high for the simulated attack path; all records are generated lab telemetry.

## Recommended response actions

These are recommendations for a comparable real incident; they were not executed in the lab:

1. Isolate the host while preserving volatile evidence and endpoint, authentication, cron, and system logs.
2. Validate the svc-webapp login, rotate its credentials, and review sudo membership for sysadm1n and other new accounts.
3. Preserve the crontab and process ancestry before disabling persistence; investigate outbound traffic to 203.0.113.42:4444.
4. Review other hosts for the .exploit parent, /tmp artifacts, equivalent cron entries, and truncated or missing logs.
5. Restore trusted logging and compare the host against a known-good image after incident scoping.

## Limitations

- All event details and addresses belong to synthetic playbook telemetry.
- The rule tester showed zero for the pre-existing sequence rule; it did not establish that the rule detects an ordered process-to-escalation chain.
- The app-native rules detect privilege escalation and account creation separately; cron and log-clearing details were identified through event review and are represented in the Sigma file.
- No real system was isolated, modified, or remediated.

## Standards and references

- Incident-record structure informed by [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- Portable event detection follows the [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).
- ATT&CK references: [T1068](https://attack.mitre.org/techniques/T1068/), [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1070.002](https://attack.mitre.org/techniques/T1070/002/), and [T1070.004](https://attack.mitre.org/techniques/T1070/004/).

## Portfolio summary

Investigated a synthetic privilege-escalation and persistence chain, created and validated direct event rules for kernel privilege escalation and local account creation, reviewed generated alerts, and documented cron persistence and log-tampering evidence.

## Repository attribution

This report documents an independent lab exercise using the SIEM dashboard from [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/siem-dashboard). It records investigation and detection-rule validation work; it does not claim authorship of the underlying application.
