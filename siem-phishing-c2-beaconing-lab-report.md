# SIEM Investigation Report: Phishing to C2 Beaconing

Portfolio lab report · Environment: local Dockerized SIEM training lab · Data: synthetic playbook telemetry · Run date: 2026-09-29

## Executive summary

The Phishing to C2 Beaconing playbook generated 18 events. On workstation **ws-jdoe** (10.0.1.50), user jdoe, an Excel-launched cmd.exe started hidden, encoded PowerShell. The PowerShell process launched update.exe from the user’s Temp directory. Repeated proxy c2_communication events then connected to 203.0.113.99. Discovery and staging activity included local account and domain-group enumeration, network-share enumeration, and file access.

The High-severity threshold rule **HTTP C2 Beaconing - Repeated Callbacks** matched three C2 events from 10.0.1.50 within five minutes. Its rule-test preview predicted one alert; after replay the Alerts view showed one High/New alert with three matched events.

Assessment: the synthetic sequence is consistent with a malicious attachment followed by PowerShell execution, payload launch, and HTTP C2. The event tagged T1059.003 records cmd.exe; the next PowerShell event is tagged T1059.001. This report preserves both event-level mappings. No containment or remediation was applied to real systems.

## Scope and evidence

- Scenario: Phishing to C2 Beaconing (18 generated events per playbook run).
- SIEM views used: Dashboard, Log Viewer, Rules, rule-test preview, and Alerts.
- Event sources observed: endpoint, proxy, and DNS.
- Evidence reviewed: process ancestry and command lines, host and user, C2 source and destination, timestamps, alert matched-event summary, rule conditions, and ATT&CK tags.
- Time handling: times below are copied from the SIEM UI. The UI did not show a timezone, so they are not normalized to UTC.
- Validation: the playbook was replayed after rule creation. Counts below describe one run.

## Investigation timeline

| UI time (Sep 29) | Evidence | Interpretation |
|---|---|---|
| 10:03:13 | cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc ..., parent EXCEL.EXE, user jdoe, host ws-jdoe; tagged T1059.003. | Excel-launched command shell initiated hidden encoded PowerShell. |
| 10:03:14 | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc ..., parent cmd.exe; tagged T1059.001. | PowerShell download cradle execution. |
| 10:03:14 | C:\Users\jdoe\AppData\Local\Temp\update.exe, parent PowerShell; tagged T1204.002. | Second-stage payload executed from the Temp directory. |
| 10:03:19–10:03:26 | Three High proxy/c2_communication events from 10.0.1.50; the rule alert lists events at 10:03:19, 10:03:24, and 10:03:26. | Repeated C2 callbacks triggered the threshold rule. |
| 10:03:21 | whoami /all, net user, and net group "Domain Admins" /domain, parent update.exe; tagged T1087.002. | Account and group discovery via C2 tasking. |
| 10:03:22–10:03:23 | net.exe view \\FILE-SERVER-01 /all, followed by file-access activity; user jdoe. | Network-share discovery and data staging. |

## Detection rule and validation

**Rule:** HTTP C2 Beaconing - Repeated Callbacks  
**Severity / type:** High / Threshold  
**Logic:** three or more proxy C2 communication events from one source IP within 300 seconds.

~~~json
{
  "event_filter": {
    "source_type": "proxy",
    "event_type": "c2_communication"
  },
  "threshold": 3,
  "window_seconds": 300,
  "group_by": "source_ip"
}
~~~

The rule-test preview evaluated 272 events and reported one alert would fire. After replay, Alerts showed one High/New alert grouped under 10.0.1.50 with three matched c2_communication events. The alert was not acknowledged or resolved in the captured evidence.

The portable event-level rule is [phishing_c2_beaconing.yml](detections/phishing_c2_beaconing.yml). The app-native threshold adds the time-window and source grouping. The rule detects repeated C2 events; it does not by itself prove the phishing delivery path or correlate the initiating Excel and PowerShell processes.

## ATT&CK mapping

| Technique | Observed behavior |
|---|---|
| [T1566.001 – Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) and [T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) | Playbook delivery and execution stages; the endpoint records show Excel as the parent of the command shell and the second-stage payload. |
| [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Encoded, hidden PowerShell download cradle. |
| [T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | The Excel child process is cmd.exe; its command line invokes PowerShell. |
| [T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | Repeated proxy C2 callbacks listed by the playbook. |
| [T1087.002 – Domain Account](https://attack.mitre.org/techniques/T1087/002/) and [T1135 – Network Share Discovery](https://attack.mitre.org/techniques/T1135/) | Commands enumerate domain groups and the FILE-SERVER-01 share. |
| T1573.002 | Listed by the playbook as an encryption-related C2 technique; the reviewed event details do not expose cryptographic parameters. |

## Analyst assessment

- Initial execution: Excel to cmd.exe, then encoded PowerShell, then update.exe in the user Temp directory.
- C2: three High proxy callbacks from 10.0.1.50 to the lab destination 203.0.113.99 within the configured window.
- Follow-on activity: account/group and share discovery, followed by file access.
- Alert status at capture: New. It was not marked resolved.
- Confidence: high for the simulated attack path; all telemetry is synthetic.

## Recommended response actions

These are recommendations for a comparable real incident; they were not executed in the lab:

1. Preserve the attachment, email headers, endpoint process tree, PowerShell logs, proxy records, and file-access evidence.
2. Isolate the endpoint and block or sinkhole the confirmed C2 destination after validating its ownership and impact.
3. Review jdoe’s access, credentials, browser and mail activity, and any files accessed from FILE-SERVER-01.
4. Hunt for the same parent-child process chain, destination, and callback pattern across endpoints; tune against approved automation.

## Limitations

- All events, domains, addresses, and files are synthetic playbook data.
- The event metadata tags the cmd.exe record T1059.003 while the child PowerShell record is tagged T1059.001; the report retains the per-event tags.
- The threshold rule does not correlate proxy callbacks with the originating process or file-access events.
- The proxy records identify the C2 event type and endpoints but do not provide full HTTP request contents.

## Standards and references

- Incident-record structure informed by [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- Portable event detection follows the [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).
- ATT&CK references: [T1566.001](https://attack.mitre.org/techniques/T1566/001/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.003](https://attack.mitre.org/techniques/T1059/003/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1087.002](https://attack.mitre.org/techniques/T1087/002/), and [T1135](https://attack.mitre.org/techniques/T1135/).

## Portfolio summary

Investigated a synthetic phishing-to-C2 sequence, followed process ancestry from Excel to encoded PowerShell and a Temp-directory payload, validated repeated proxy callbacks, reviewed the generated alert, and mapped endpoint and network evidence to ATT&CK.

## Repository attribution

This report documents an independent lab exercise using the SIEM dashboard from [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/siem-dashboard). It records investigation and detection-rule validation work; it does not claim authorship of the underlying application.
