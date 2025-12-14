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

<img width="1923" height="894" alt="image" src="https://github.com/user-attachments/assets/db032099-30f9-4a8c-8727-29e0ba36a9ff" />

