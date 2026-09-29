# SIEM Investigation Report: Data Exfiltration via DNS Tunneling

Portfolio lab report · Environment: local Dockerized SIEM training lab · Data: synthetic playbook telemetry · Run date: 2026-09-29

## Executive summary

The Data Exfiltration via DNS Tunneling playbook generated 22 events. The post-rule replay showed workstation **ws-compromised** (10.0.1.50) sending a burst of TXT queries through resolver 10.0.0.53 to the synthetic suffix .data.exfil-tunnel.tk. The SIEM records identify the final query as a DNS tunneling data chunk and map it to T1048.003. A separate A lookup for r4d58hj3c.cdn-services.example.net resolved to 203.0.113.99 and was tagged T1071.004.

The application’s core-field DNS threshold preview evaluated 361 events and predicted one alert. No matching DNS alert appeared in Alerts after replay. A more specific draft that filtered on query payload fields returned zero in the rule-test preview. The DNS analytic is therefore documented as a review signal, not as an end-to-end validated alert.

Assessment: the synthetic telemetry strongly demonstrates DNS tunneling behavior. The logs do not include transfer bytes or a complete response payload, so the amount of data transferred cannot be established. No containment or remediation was applied to real systems.

## Scope and evidence

- Scenario: Data Exfiltration via DNS Tunneling (22 generated events per playbook run).
- SIEM views used: Dashboard, Log Viewer, Rules, rule-test preview, and Alerts.
- Evidence reviewed: query type and name, source and resolver IPs, host, timestamp, response code, ATT&CK tags, rule conditions, and alert list.
- Time handling: times below are copied from the SIEM UI. The UI did not show a timezone, so they are not normalized to UTC.
- Validation: the playbook was replayed after rule creation. Event counts in this report describe one scenario run, not the sum of repeated runs.

## Investigation timeline

| UI time (Sep 29) | Evidence | Interpretation |
|---|---|---|
| 10:03:01 | Eight dns_query records from 10.0.1.50 to 10.0.0.53; ws-compromised; TXT queries to .data.exfil-tunnel.tk. | Burst of opaque, payload-like DNS labels consistent with the playbook’s tunneling stage. |
| 10:03:03 | Final TXT query to efbfbd000000efbfbdff00006efbfbd0.data.exfil-tunnel.tk; response absent; message says final data chunk and session teardown. | Final observed exfiltration chunk; the log does not establish how many bytes the query carried. |
| 10:03:15 | A query for r4d58hj3c.cdn-services.example.net from 10.0.1.50 to 10.0.0.53; response 203.0.113.99; host ws-jdoe. | DGA-like DNS lookup tagged T1071.004. It is distinct from the TXT data-chunk events. |

## Detection rule and validation

**Application rule:** DNS Query Burst - Exfiltration Review  
**Severity / type:** Medium / Threshold  
**Logic:** eight or more DNS dns_query events from one source IP within 300 seconds.

~~~json
{
  "event_filter": {
    "source_type": "dns",
    "event_type": "dns_query"
  },
  "threshold": 8,
  "window_seconds": 300,
  "group_by": "source_ip"
}
~~~

The rule-test preview evaluated 361 events and reported one alert would fire. After replay, no corresponding DNS alert was visible in Alerts. The app also has a High-severity draft named **DNS TXT Tunneling - Repeated Exfiltration** that filters on query_type and mitre_technique; its preview evaluated the same dataset and reported zero alerts. Those payload fields are visible in event details but did not match in the application rule tester. Do not rely on that draft for alerting.

The portable event-level Sigma rule is [dns_txt_tunneling.yml](detections/dns_txt_tunneling.yml). It matches TXT queries to the lab suffix. The app-native threshold is broader because its tested matcher accepted the source and event type fields but not the payload fields. In production, map the query fields in the SIEM and correlate repeated TXT queries, label entropy, destination domain, and bytes or response data before assigning High severity.

## ATT&CK mapping

| Technique | Observed behavior |
|---|---|
| [T1048.003 – Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003/) | TXT data chunks sent to the synthetic tunneling domain; the event is explicitly tagged T1048.003. |
| [T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) | DNS lookup for a DGA-like subdomain resolving to 203.0.113.99. |
| [T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/) and [T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/) | Listed by the playbook as additional behaviors; the timeline above focuses on DNS records directly inspected. |

## Analyst assessment

- Likely scenario path: reconnaissance and file access followed by TXT-based DNS transfer from 10.0.1.50 through 10.0.0.53.
- Supporting signal: the event message identifies a final tunnel chunk, and the query suffix and TXT type align with the playbook.
- Alert status at capture: no DNS rule alert was visible. The preview result alone is not evidence that the live alert pipeline fired.
- Confidence: high for the simulated technique; the data is generated lab telemetry, not a real incident.

## Recommended response actions

These are recommendations for a comparable real incident; they were not executed in the lab:

1. Confirm the host owner and preserve resolver, proxy, endpoint, and network-flow evidence before containment.
2. Isolate the suspected endpoint and restrict direct DNS egress to approved resolvers.
3. Hunt for the domain suffix, TXT query bursts, unusual label lengths or entropy, and related outbound connections from other hosts.
4. Tune the analytic against normal TXT use and require destination, query-type, and volume context before raising the alert severity.

## Limitations

- All addresses, domains, and events belong to synthetic playbook telemetry.
- The visible records do not include transferred byte counts or a complete DNS response payload.
- The SIEM’s threshold rule only checks source type and event type. It does not itself inspect query type, domain, label entropy, or sequence.
- The test preview predicted a match, but the replay did not produce a visible DNS alert; operational alerting remains unconfirmed.

## Standards and references

- Incident-record structure informed by [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), which integrates incident response into cybersecurity risk management.
- Portable event detection follows the [Sigma Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html).
- Technique references: [T1048.003](https://attack.mitre.org/techniques/T1048/003/), [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1046](https://attack.mitre.org/techniques/T1046/), and [T1005](https://attack.mitre.org/techniques/T1005/).

## Portfolio summary

Investigated a synthetic DNS-tunneling playbook, reviewed TXT data-chunk and DNS C2 lookup records, added and tested an app-native DNS volume threshold, and documented the mismatch between preview and replay alert behavior.

## Repository attribution

This report documents an independent lab exercise using the SIEM dashboard from [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/siem-dashboard). It records investigation and detection-rule validation work; it does not claim authorship of the underlying application.
