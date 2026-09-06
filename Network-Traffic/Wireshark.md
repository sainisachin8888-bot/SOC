# Network Traffic Analysis & Wireshark Writeup

- **Platform:** TryHackMe / Network Forensics Lab
- **Category:** Packet Capture (PCAP) Analysis
- **Tools Used:** Wireshark, Tshark, NetworkMiner
- **Difficulty:** Medium

---

## 1. Incident Overview
A packet capture (`analysis_lab.pcap`) was analyzed to investigate an alert reporting unauthorized data exfiltration and potential Command & Control (C2) beaconing from an internal subnet.

---

## 2. Packet Analysis & Methodology

### Step 1: Protocol Hierarchy & Endpoint Triage
* Navigated to Statistics -> Protocol Hierarchy to determine top bandwidth-consuming protocols.
* Discovered an abnormally high volume of outbound DNS (UDP 53) and HTTP (TCP 80) traffic.

### Step 2: Uncovering HTTP Data Exfiltration
Applied Wireshark display filter to examine outbound POST requests:

http.request.method == "POST"

* **Observation:** The host `192.168.1.105` regularly sent HTTP POST requests containing Base64-encoded strings within the user-agent header to an external IP (`198.51.100.22`).

### Step 3: Following TCP Streams
* Right-clicked on packet #412 and selected Follow -> TCP Stream.
* **Stream Findings:** Reconstructed the session revealing plain-text file transfers containing confidential system directories (`C:\Users\Administrator\Desktop\passwords.txt`).

### Step 4: Investigating DNS Tunneling / Beaconing
Applied DNS filter to evaluate suspicious long domain name queries:

dns.flags.response == 0 && dns.qry.name contains "c2-server"

* **Observation:** Uncovered subdomains containing hexadecimal strings (e.g., `64617461.c2-server.com`), indicative of DNS tunneling for data exfiltration.

---

## 3. Extracted Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
| :--- | :--- | :--- |
| **Source IP** | `192.168.1.105` | Internal Compromised Workstation |
| **Destination IP** | `198.51.100.22` | External C2 Infrastructure |
| **Malicious Domain**| `c2-server.com` | DNS Tunneling Endpoint |
| **Exfiltrated File**| `passwords.txt` | Sensitive credential file |

---

## 4. Defensive Recommendations
1. Deploy strict egress filtering rules at the perimeter firewall blocking unauthorized outbound connections over non-standard ports.
2. Implement DNS Sinkholing and inspect DNS query lengths to block DNS tunneling attempts automatically.
3. Enforce TLS/SSL inspection on all web traffic to detect unencrypted file transfers and suspicious user agents.
