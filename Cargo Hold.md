# Threat Hunt Report: Operation Azuki Import/Export 
Date: December 13, 2025 Analyst: Brian Hardy Platform: Microsoft Sentinel / KQL Scenario: Azuki Import/Export (梓貿易株式会社) Incident Response

# 📋 Executive Summary
Situation: After establishing initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server azuki-fileserver01.

Objective: Investigate the full attack lifecycle—from Initial Access to Exfiltration—using Kusto Query Language (KQL) to hunt for Indicators of Compromise (IOCs) and reconstruct the attacker's actions.

## 🔎 Detailed Investigation
### Phase 1: Initial Access & Lateral Movement

Flag 1: Initial Access - Return Connection Source

- Investigative Thinking: The briefing mentions the attacker returned ~72 hours after the 19th. I need to look for external connections to the entry point (azuki-sl) around the 22nd to identify the threat actor's IP address.

```DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-25))
| where DeviceName == "azuki-sl"
| project Timestamp, RemoteIP, DeviceName, ActionType
```

<img width="750" height="750" alt="Screenshot 2025-12-06 at 10 32 51 PM" src="https://github.com/user-attachments/assets/f072afe0-b488-4f7e-b3e7-16f9f8d13c6c" />


- Answer: 159.26.106.98

Flag 2: Lateral Movement - Compromised Device
- Investigative Thinking: Once inside azuki-sl, the attacker likely moved laterally. RDP (mstsc.exe) is a common tool for this. I will look for RDP process execution on the entry device and correlate it with logon events on other servers.
my query

```DeviceProcessEvents
| where FileName contains "mstsc.exe"
| where DeviceName == "azuki-sl"
| project TimeGenerated, ProcessCommandLine
```
<img width="750" height="750" alt="Screenshot 2025-12-06 at 11 24 34 PM" src="https://github.com/user-attachments/assets/051bf9dd-3ac1-415a-9cb8-f0b245239613" />

Answer: azuki-fileserver01

Flag 3: Lateral Movement - Compromised Account
