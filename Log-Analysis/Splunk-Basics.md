# Splunk Basics & SIEM Querying Writeup

- **Platform:** TryHackMe / Practical SIEM Lab
- **Category:** Log Analysis & SIEM Querying
- **Tools Used:** Splunk Enterprise, SPL (Search Processing Language)
- **Difficulty:** Easy / Medium

---

## 1. Objective & Scenario
The objective of this lab was to utilize Splunk SPL to search, filter, and correlate Windows Event Logs, Sysmon activity, and web server access logs to uncover malicious activity, build threat metrics, and construct custom detection dashboards.

---

## 2. Key Search Queries & Investigation Steps

### Phase 1: Detecting Brute-Force Authentication Attempts
To identify potential password-spraying or brute-force attacks against Active Directory user accounts:

index=win_logs EventCode=4625
| stats count by TargetUserName, src_ip
| where count > 10
| sort - count

* **Finding:** Identified `src_ip=10.10.20.45` attempting over 150 failed logins across multiple user accounts within 5 minutes.

### Phase 2: Threat Hunting for Suspicious Process Execution
Searching for Sysmon Event ID 1 (Process Creation) involving administrative shell tools:

index=sysmon EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe")
| table _time, host, User, Image, CommandLine
| sort - _time

* **Finding:** Uncovered an unauthorized execution of PowerShell spawning from an unexpected parent process (`w3wp.exe`), indicating successful web shell execution.

### Phase 3: Web Server Log Analysis (HTTP Status Codes)
Investigating directory brute-forcing attempts on web assets:

index=web_access status=404
| stats count by clientip, uri_path
| where count > 50
| top limit=10 clientip

* **Finding:** Isolated automated Gobuster scanning activity originating from an external host.

---

## 3. SIEM Dashboard & Alert Construction

To automate future detection, a custom alert was generated using the following alert rule criteria:
* **Trigger Condition:** Real-time search triggering whenever Event ID `4720` (User Account Created) occurs outside standard business hours.
* **Action:** Automatically trigger an email notification to the SOC Tier 1 queue and create a high-priority incident ticket.

---

## 4. Key Learnings
* Mastering pipe operators (`|`) in SPL to filter data progressively.
* Utilizing `stats` and `timechart` commands to build meaningful visualization panels for SOC dashboards.
* Leveraging Sysmon event correlation to map process inheritance.
