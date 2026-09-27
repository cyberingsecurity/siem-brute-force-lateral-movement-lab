# SIEM Investigation Report: SSH Brute Force and Lateral Movement


> **Portfolio lab report** · **Environment:** local Dockerized SIEM training lab · **Data:** synthetic playbook telemetry · **Run date:** 2026-09-27
## Executive summary


The `Brute Force with Lateral Movement` playbook simulated repeated SSH authentication failures against perimeter host `10.1.1.50`. The attacker source `203.0.113.42` then authenticated as `deploy`. Subsequent successful remote logins and endpoint activity originated from `10.1.1.50` and reached internal hosts `10.1.2.10` and `10.1.2.20`, consistent with lateral movement.


A High-severity threshold rule was validated against the lab data. The initial rule draft used the wrong source-field name and matched no events. After changing the filter from `source` to the event schema’s `source_type`, the rule test predicted a match. A playbook replay then produced two High/New alerts, each grouping five failed authentication events from `203.0.113.42`.


**Assessment:** the simulated sequence demonstrates password guessing followed by successful access and internal remote access. No containment or remediation was applied to real systems; this was a synthetic lab exercise.


## Scope and evidence


- **Scenario:** Brute Force with Lateral Movement (29 generated events per playbook run).
- **SIEM views used:** Dashboard, Log Viewer, Rules, rule-test preview, and Alerts.
- **Event sources observed:** `auth`, `firewall`, `ids`, and `endpoint`.
- **Evidence reviewed:** event timestamps, source and destination IPs, usernames, event types, severity, rule conditions, and alert matched-event summaries.
- **Time handling:** times below are copied from the SIEM UI. The UI did not show a timezone, so they are not normalized to UTC.


## Investigation timeline


| UI time (Sep 27) | Evidence | Interpretation |
| --- | --- | --- |
| 10:20:27 | Firewall allowed TCP from `203.0.113.42` to `10.1.1.50:22` (`fw-edge-01`, rule `ssh-management`). | External SSH access reached the perimeter host. |
| 10:20:28–10:20:30 | Medium `auth/login_failure` events from `203.0.113.42` to `10.1.1.50`, with multiple attempted usernames (including `backup`, `sysadmin`, `devops`, and `ansible`). | Password-guessing pattern. |
| 10:20:31 | Medium `ids/ids_alert` from `203.0.113.42` to `10.1.1.50`. | IDS telemetry also flagged the activity. |
| 10:20:33 | `auth/login_success` from `203.0.113.42` to `10.1.1.50` as `deploy`. | The simulated access attempt succeeded. |
| 10:20:36–10:20:38 | `endpoint/process_execution` activity on `10.1.1.50` as `deploy`. | Post-login activity on the perimeter host. |
| 10:20:41–10:20:42 | Firewall allowed a connection from `10.1.1.50` to `10.1.2.10`, followed by `auth/login_success` as `deploy`. | First observed internal remote login. |
| 10:20:44–10:20:45 | Firewall allowed a connection from `10.1.1.50` to `10.1.2.20`, followed by `auth/login_success` as `deploy`. | A second internal host was reached. |
| 10:20:48 | `endpoint/process_execution` on `10.1.2.20` as `deploy`. | Activity continued on the second internal host. |


## Detection rule and validation


**Rule:** `SSH Brute Force - Auth Failures (Corrected)`  
**Severity:** High  
**Type:** Threshold  
**Logic:** five or more authentication failures from one source IP within 300 seconds.


```json
{
  "event_filter": {
    "source_type": "auth",
    "event_type": "login_failure"
  },
  "threshold": 5,
  "window_seconds": 300,
  "group_by": "source_ip"
}
```


The first draft filtered on `source: "auth"`; the event records use `source_type: "auth"`. The app’s rule-test preview returned zero matches for the first draft. With the corrected field, the preview evaluated 87 events and reported one alert would fire. After replaying the playbook, the Dashboard showed 116 total events and two alerts. The Alerts view listed two High-severity New alerts from the corrected rule, each with five matched `login_failure` events grouped under `203.0.113.42`.


**Detection limitation:** this threshold rule detects repeated failures by source IP. It does not itself correlate a later successful login or the subsequent internal logins; those behaviors were identified by reviewing the event timeline.


## ATT&CK mapping


| Technique | Observed behavior |
| --- | --- |
| [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Repeated authentication failures using multiple usernames, followed by a successful login. |
| [T1021.004 – SSH](https://attack.mitre.org/techniques/T1021/004/) | Remote login activity from the accessed host to internal systems, consistent with SSH-based lateral movement in this playbook. |


The playbook UI lists tactic tags `TA0001` and `TA0008`; this report maps the observed behaviors to the ATT&CK techniques above.


## Analyst assessment


- **Initial access:** simulated password guessing against `10.1.1.50` from `203.0.113.42`; the `deploy` login succeeded.
- **Lateral movement:** the accessed host `10.1.1.50` subsequently connected to `10.1.2.10` and `10.1.2.20`, with successful `deploy` logins and later endpoint execution.
- **Alert status at capture:** New. The alert was not marked resolved in the captured evidence.
- **Confidence:** high for the playbook’s simulated attack path; the data is generated lab telemetry, not a real-world incident.


## Recommended response actions


These are analyst recommendations for a comparable real incident; they were not executed in the lab:


1. Validate whether `deploy` was authorized to access the affected hosts and confirm the activity with the system owner.
2. Contain the suspected source host and restrict SSH between network zones while preserving relevant logs.
3. Rotate or disable the affected credentials, review SSH keys and authorized-key files, and inspect authentication and process logs on all three hosts.
4. Add a separate correlation rule for failed logins followed by a success from the same source, and monitor successful remote logins from newly accessed hosts to additional internal destinations.
5. Tune the threshold against normal authentication volume to reduce false positives.


## Limitations


- All events and addresses in this report belong to the synthetic playbook run.
- The visible event details did not provide command lines or full process trees, so process execution is noted without attributing a specific command.
- The threshold rule is source-IP based and does not, by itself, prove that every failed login was SSH; SSH context comes from the scenario and the firewall event showing destination port 22.
- Two matching alert records were visible after replay. The report records the observed count and matched-event summaries without assuming why the application emitted two records.


## Standards and references


- This report uses an incident-record structure informed by [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), which integrates incident-response recommendations into cybersecurity risk management.
- ATT&CK technique references: [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) and [T1021.004 – SSH](https://attack.mitre.org/techniques/T1021/004/).


## Portfolio summary


> Deployed a Dockerized SIEM lab, investigated synthetic SSH password-guessing and lateral-movement telemetry, created and validated a threshold detection rule, reviewed generated alerts, and documented findings with MITRE ATT&CK mappings.
## Repository attribution


This report documents an independent lab exercise using the SIEM dashboard from [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/siem-dashboard). It records investigation and detection-rule validation work; it does not claim authorship of the underlying application.
