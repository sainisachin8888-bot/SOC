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

```spl
index=win_logs EventCode=4625
| stats count by TargetUserName, src_ip
| where count > 10
| sort - count
