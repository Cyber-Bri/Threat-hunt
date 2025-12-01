# Azuki-SL — Threat Hunting Investigation (梓貿易株式会社)

**Investigation Timeline:** 2025-11-19 → 2025-11-20  
**Target Device:** `azuki-sl`  
**Primary Data Source:** Microsoft Defender for Endpoint (KQL)

---

## Table of Contents
- [Project Overview](#project-overview)
- [Incident Brief](#incident-brief)
- [Hunt Hypothesis (CISO Tasking)](#hunt-hypothesis-ciso-tasking)
- [Initial Access — Summary](#initial-access--summary)
- [Investigation Questions (Template)](#investigation-questions-template)
- [Flags (1–20) — Queries & Strategy](#flags-120--queries--strategy)
  - [🚩 Flag 1: Initial Access — Remote Access Source](#-flag-1-initial-access--remote-access-source)
  - [🚩 Flag 2: Initial Access — Compromised User Account](#-flag-2-initial-access--compromised-user-account)
  - [🚩 Flag 3: Discovery — Network Reconnaissance](#-flag-3-discovery--network-reconnaissance)
  - [🚩 Flag 4: Defense Evasion — Malware Staging Directory](#-flag-4-defense-evasion--malware-staging-directory)
  - [🚩 Flag 5: Defense Evasion — File Extension Exclusions](#-flag-5-defense-evasion--file-extension-exclusions)
  - [🚩 Flag 6: Defense Evasion — Temporary Folder Exclusion](#-flag-6-defense-evasion--temporary-folder-exclusion)
  - [🚩 Flag 7: Defense Evasion — Download Utility Abuse](#-flag-7-defense-evasion--download-utility-abuse)
  - [🚩 Flag 8: Persistence — Scheduled Task Name](#-flag-8-persistence--scheduled-task-name)
  - [🚩 Flag 9: Persistence — Scheduled Task Target](#-flag-9-persistence--scheduled-task-target)
  - [🚩 Flag 10: C2 — Server Address](#-flag-10-c2--server-address)
  - [🚩 Flag 11: C2 — Communication Port](#-flag-11-c2--communication-port)
  - [🚩 Flag 12: Credential Access — Credential Theft Tool](#-flag-12-credential-access--credential-theft-tool)
  - [🚩 Flag 13: Credential Access — Memory Extraction Module](#-flag-13-credential-access--memory-extraction-module)
  - [🚩 Flag 14: Collection — Data Staging Archive](#-flag-14-collection--data-staging-archive)
  - [🚩 Flag 15: Exfiltration — Exfiltration Channel](#-flag-15-exfiltration--exfiltration-channel)
  - [🚩 Flag 16: Anti-Forensics — Log Tampering](#-flag-16-anti-forensics--log-tampering)
  - [🚩 Flag 17: Impact — Persistence Account](#-flag-17-impact--persistence-account)
  - [🚩 Flag 18: Execution — Malicious Script](#-flag-18-execution--malicious-script)
  - [🚩 Flag 19: Lateral Movement — Secondary Target](#-flag-19-lateral-movement--secondary-target)
  - [🚩 Flag 20: Lateral Movement — Remote Access Tool](#-flag-20-lateral-movement--remote-access-tool)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Analyst Notes & Screenshots](#analyst-notes--screenshots)
- [Recommendations & Next Steps](#recommendations--next-steps)
- [KQL Notes](#kql-notes)

---

## Project Overview

This repository documents a comprehensive threat hunting investigation conducted using **Kusto Query Language (KQL)** within **Microsoft Defender for Endpoint**. The investigation follows the **Cyber Kill Chain** to analyze a compromised endpoint (`azuki-sl`), covering:

- **Initial Access**
- **Persistence**
- **Privilege Escalation**
- **Command & Control (C2)**
- **Exfiltration**

---

## Incident Brief

**Company:** Azuki Import/Export Trading Co. (梓貿易株式会社) — 23 employees; shipping logistics in Japan/SE Asia.  
**Situation:** Competitor undercut a 6-year shipping contract by exactly **3%**. Azuki’s supplier contracts and pricing data appeared on underground forums.  
**Compromised System:** **AZUKI-SL** (IT admin workstation)  
**Evidence Available:** Microsoft Defender for Endpoint telemetry (and Windows logs via MDE)

---

## Hunt Hypothesis (CISO Tasking)

**Tasking by CISO:** Identify **Indicators of Compromise (IOCs)** in MDE telemetry to confirm/deny a targeted breach and scope attacker activity.

**Hypothesis:**  
> An external threat actor accessed **AZUKI-SL** via RDP (RemoteInteractive), established **C2**, evaded defenses (e.g., Defender exclusions), staged and exfiltrated supplier pricing data, and left persistence artifacts (e.g., scheduled tasks).

**Goals:**
1. Confirm **initial access** vector and source.  
2. Identify **compromised accounts**.  
3. Determine what **data was stolen** and how it was **exfiltrated**.  
4. Detect **persistence** and **defense evasion** changes.  
5. Compile IOCs (hashes, IPs, registry keys, tasks) for response.

---

## Initial Access — Summary

A **RemoteInteractive (RDP)** session to **AZUKI-SL** was confirmed using account **`Kenji.sato`** from external IP **`88.97.178.12`** at **`2025-11-19T18:36:21.0122833Z`**.  
This is identified as the **initial access point**. RDP (**LogonType 10**) provides full interactive control of the workstation. Given the external IP and subsequent data leak, this is treated as a **confirmed compromise**.

**Key Facts**
- Device: `AZUKI-SL`  
- User Account: `Kenji.sato`  
- Logon Type: `10` (RemoteInteractive / RDP)  
- Remote IP: `88.97.178.12`  
- Timestamp: `2025-11-19T18:36:21.0122833Z`  
- Assessment: 🔴 *Confirmed unauthorized access*

---

## Investigation Questions (Template)

Use this template to capture your queries, results, and screenshots.

### 1) Initial access method?
**Query used**
```kql
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, RemoteIP, RemotePort, LogonType
| sort by Timestamp asc
```
# 🚩 Flag 2: INITIAL ACCESS - Compromised User Account

**Scenario:** Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

* **Question:** Identify the user account that was compromised for initial access?

### 🔎 Hunting Strategy

Using the same logic as the previous step, I examined the `AccountName` associated with the remote RDP session. This identifies exactly which user identity was stolen or brute-forced to gain entry.

### 💻 KQL Query

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project AccountName, AccountDomain, RemoteIP```
```
# 🚩 Flag 3: DISCOVERY - Network Reconnaissance

**Scenario:** Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

* **Question:** Identify the command and argument used to enumerate network neighbours?

### 🔎 Hunting Strategy

I searched `DeviceProcessEvents` for the execution of standard Windows discovery tools like `arp.exe`, `net.exe`, or `ipconfig.exe`. Attackers often use `arp -a` immediately after access to map the local subnet.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in~ ("arp.exe", "net.exe", "ipconfig.exe")
| project Timestamp, FileName, ProcessCommandLine
```
# 🚩 Flag 4: DEFENCE EVASION - Malware Staging Directory

**Scenario:** Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

* **Question:** Identify the PRIMARY staging directory where malware was stored?

### 🔎 Hunting Strategy

I hunted for the creation of hidden folders by looking for the `attrib` command with the `+h` (hide) flag. This is a common technique to conceal staging directories from standard users.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "mkdir" or (ProcessCommandLine has "attrib" and ProcessCommandLine has "+h")
| project Timestamp, ProcessCommandLine, FolderPath
```
# 🚩 Flag 5: DEFENCE EVASION - File Extension Exclusions

**Scenario:** Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

* **Question:** How many file extensions were excluded from Windows Defender scanning?

### 🔎 Hunting Strategy

I queried the `DeviceRegistryEvents` table, specifically filtering for the `Windows Defender\Exclusions\Extensions` key path. Counting the distinct values here reveals how many file types the attacker successfully whitelisted.

### 💻 KQL Query

```kusto
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey has "Windows Defender\\Exclusions\\Extensions"
| distinct RegistryValueName
| count
```
# 🚩 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion

**Scenario:** Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

* **Question:** What temporary folder path was excluded from Windows Defender scanning?

### 🔎 Hunting Strategy

Similar to Flag 5, I investigated the registry, but this time focused on `Windows Defender\Exclusions\Paths`. This reveals the specific directory path the attacker wanted Defender to ignore.

### 💻 KQL Query

```kusto
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey has "Windows Defender\\Exclusions\\Paths"
| project RegistryValueName
```
# 🚩 Flag 7: DEFENCE EVASION - Download Utility Abuse

**Scenario:** Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

* **Question:** Identify the Windows-native binary the attacker abused to download files?

### 🔎 Hunting Strategy

This hunt targeted "Living off the Land" (LOLBins). I searched for native tools like `certutil.exe`, `bitsadmin.exe`, or `curl.exe` that were executed with "http" in the command line, indicating a file download attempt.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "http"
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "curl.exe", "powershell.exe")
| project Timestamp, FileName, ProcessCommandLine
```
### 📊 Analysis & Findings

The query highlights instances where trusted Windows binaries were misused to fetch files from the internet. The `FileName` identifies the specific LOLBin (e.g., `certutil.exe`), and `ProcessCommandLine` shows the remote URL of the malicious payload.

# 🚩 Flag 8: PERSISTENCE - Scheduled Task Name

**Scenario:** Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

* **Question:** Identify the name of the scheduled task created for persistence?

### 🔎 Hunting Strategy

I filtered `DeviceProcessEvents` for `schtasks.exe` executions using the `/create` flag. Analyzing the `/tn` (Task Name) parameter reveals the deceptive name the attacker used.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, ProcessCommandLine
```

# 🚩 Flag 9: PERSISTENCE - Scheduled Task Target

**Scenario:** The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

* **Question:** Identify the executable path configured in the scheduled task?

### 🔎 Hunting Strategy

Using the results from the previous search (Flag 8), I examined the `/tr` (Task Run) parameter within the command line arguments. This parameter points directly to the malware executable that the system is instructed to run every time the scheduled task triggers.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, ProcessCommandLine
// Look specifically for the value following the "/tr" switch
```
### 📊 Analysis & Findings

By parsing the command line from the previous finding, specifically the /tr parameter, we identify the full path to the malicious executable. This confirms what payload persists across system reboots and allows us to locate the malware on the disk for isolation.

# 🚩 Flag 10: COMMAND & CONTROL - C2 Server Address

**Scenario:** Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

* **Question:** Identify the IP address of the command and control server?

### 🔎 Hunting Strategy

I used `DeviceNetworkEvents` to trace outbound traffic from the suspicious processes identified in previous steps (like the malware running from the staging folder). Filtering out local IPs (10.x, 192.168.x) exposed the external C2 node.

### 💻 KQL Query

```kusto

DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName == "certutil.exe" 
```
📊 Analysis & Findings

The query filters for outbound connections initiated by the suspicious process. The RemoteIP column identifies the external destination, revealing the IP address of the attacker's Command and Control (C2) server.

# 🚩 Flag 11: COMMAND & CONTROL - C2 Communication Port

**Scenario:** C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

* **Question:** Identify the destination port used for command and control communications?

### 🔎 Hunting Strategy

I analyzed the `RemotePort` column from the C2 connections identified in Flag 10. Non-standard ports (like 8080, 4444, or specific high ports) are strong indicators of C2 frameworks like Cobalt Strike or Metasploit.

### 💻 KQL Query

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
// Filter by the suspicious RemoteIP identified in Flag 10 if available
| project RemotePort, RemoteIP, RemoteUrl
```
📊 Analysis & Findings

By examining the RemotePort associated with the C2 traffic, we can determine the communication channel used. This port number can often pinpoint the specific malware family or C2 framework being employed by the attacker.
