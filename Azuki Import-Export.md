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
- [Recommendations & Next Steps](#recommendations--next-steps)

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

# 🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool

**Scenario:** Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

* **Question:** Identify the filename of the credential dumping tool?

### 🔎 Hunting Strategy

I searched `DeviceFileEvents` for file creations in the identified staging directory (from Flag 4). I looked for short, random, or suspicious filenames (e.g., `mim.exe`, `dump.exe`) created just before potential LSASS tampering.

### 💻 KQL Query

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
// Adjust FolderPath based on Flag 4 findings
| where FolderPath has "Temp" or FolderPath has "Public"
| project Timestamp, FileName, FolderPath
```
📊 Analysis & Findings

The query reveals files created in the staging directory around the time of the attack. By identifying a suspicious executable (often with a random or deceptive name) dropped prior to credential theft attempts, we locate the specific tool used for dumping memory.

# 🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module

**Scenario:** Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

* **Question:** Identify the module used to extract logon passwords from memory?

### 🔎 Hunting Strategy

I analyzed the command line arguments of the suspected credential dumper. I looked for syntax specific to tools like Mimikatz, such as `sekurlsa::logonpasswords` or `lsadump::sam`.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "sekurlsa" or ProcessCommandLine has "lsadump" or ProcessCommandLine has "privilege::debug"
| project ProcessCommandLine
```
📊 Analysis & Findings

The ProcessCommandLine field captures the arguments passed to the dumping tool. This reveals the specific module or command (e.g., sekurlsa::logonpasswords) executed to extract credentials from the LSASS process.

# 🚩 Flag 14: COLLECTION - Data Staging Archive

**Scenario:** Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

* **Question:** Identify the compressed archive filename used for data exfiltration?

### 🔎 Hunting Strategy

I looked for the creation of archive files (`.zip`, `.7z`, `.rar`) in the staging area. This indicates the "Collection" phase where the attacker bundles data before stealing it.

### 💻 KQL Query

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName
```
📊 Analysis & Findings

This query identifies the creation of compressed files in the staging directory. The filename often hints at the content (e.g., backup.zip) or uses a timestamp, marking the package prepared for exfiltration.

# 🚩 Flag 15: EXFILTRATION - Exfiltration Channel

**Scenario:** Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

* **Question:** Identify the cloud service used to exfiltrate stolen data?

### 🔎 Hunting Strategy

I summarized outbound network traffic on port 443 (HTTPS) to see which external services were being contacted. I specifically looked for high-volume connections to file-sharing sites like Mega, Discord, or Google Drive.

### 💻 KQL Query

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RemotePort == 443
| summarize ConnectionCount=count() by RemoteUrl
| sort by ConnectionCount desc
```
📊 Analysis & Findings

The query results highlight the external domains contacted during the exfiltration phase. By observing connections to known file-sharing services (e.g., mega.nz, discord.com), we identify the channel used to leak the stolen data.

# 🚩 Flag 16: ANTI-FORENSICS - Log Tampering

**Scenario:** Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

* **Question:** Identify the first Windows event log cleared by the attacker?

### 🔎 Hunting Strategy

I hunted for the `wevtutil` tool command line execution with the `cl` (Clear-Log) parameter. Sorting by time allowed me to see the sequence of log destruction.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has "cl"
| sort by Timestamp asc
| take 1
| project ProcessCommandLine
```
📊 Analysis & Findings

This query returns the first instance of log clearing activity. The command-line argument (e.g., "Security" or "System") indicates which specific event log was prioritized for deletion to hide tracks.

# 🚩 Flag 17: IMPACT - Persistence Account

**Scenario:** Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

* **Question:** Identify the backdoor account username created by the attacker?

### 🔎 Hunting Strategy

I searched for `net.exe` or `net1.exe` usage containing the `/add` parameter. This reveals commands used to create new local users and add them to the "Administrators" group.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has "user" and ProcessCommandLine has "/add"
| project ProcessCommandLine
```
📊 Analysis & Findings

The ProcessCommandLine reveals the exact net user command executed. This exposes the username of the backdoor account created by the attacker to maintain persistence on the compromised system.

  # 🚩 Flag 18: EXECUTION - Malicious Script

**Scenario:** Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

* **Question:** Identify the PowerShell script file used to automate the attack chain?

### 🔎 Hunting Strategy

I queried `DeviceFileEvents` for the creation of `.ps1` (PowerShell) or `.bat` files in temporary folders. Identifying this script helps find the "Dropper" that automated the attack setup.

### 💻 KQL Query

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| project FileName, FolderPath, InitiatingProcessFileName
```
📊 Analysis & Findings

The query identifies script files created in suspicious locations (like Temp). The filename and path pinpoint the initial automation script (dropper) used to facilitate the attack chain.

# 🚩 Flag 19: LATERAL MOVEMENT - Secondary Target

**Scenario:** Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

* **Question:** What IP address was targeted for lateral movement?

### 🔎 Hunting Strategy

I looked for evidence of the attacker trying to jump to another machine using `cmdkey` (to stash credentials) or `mstsc` (to connect). The command line arguments reveal the target IP address.

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in~ ("mstsc.exe", "cmdkey.exe")
| project ProcessCommandLine
```
📊 Analysis & Findings

The query captures commands used to facilitate lateral movement. The arguments passed to mstsc.exe (specifically after /v:) or cmdkey.exe reveal the IP address of the next system the attacker targeted.

# 🚩 Flag 20: LATERAL MOVEMENT - Remote Access Tool

**Scenario:** Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

* **Question:** Identify the remote access tool used for lateral movement?

### 🔎 Hunting Strategy

I specifically isolated the tool used for the lateral move detected in Flag 19. By checking for the `/v:` switch (used to specify a server), I confirmed the usage of the native Microsoft Remote Desktop Client (`mstsc.exe`).

### 💻 KQL Query

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19)..datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "/v:"
| project FileName, ProcessCommandLine
```
📊 Analysis & Findings

This query confirms the specific tool used for lateral movement by filtering for the RDP connection parameter /v:. The results verify that the attacker used the native mstsc.exe binary to blend in with legitimate administrative traffic, confirming the use of standard system tools for lateral movement.

# 🚨 Incident Report: "Azuki-SL" Compromise

**Date of Investigation:** 2025-11-20
**Analyst:** Brian Hardy
**Target Asset:** `azuki-sl`
**Incident Type:** External Compromise / Lateral Movement
**Tools Used:** Microsoft Defender for Endpoint (KQL)

## 📄 Executive Summary

On November 19, 2025, security alerts indicated suspicious activity on the endpoint `azuki-sl`. A comprehensive threat hunting investigation confirmed that a threat actor gained unauthorized access via Remote Desktop Protocol (RDP) using compromised credentials. Following initial access, the attacker performed local reconnaissance, established persistence via scheduled tasks and backdoor accounts, disabled security controls (Windows Defender), and successfully exfiltrated data to a cloud storage provider. The attacker then attempted lateral movement to other network assets before clearing event logs to obfuscate their activities.

## ⏳ Attack Timeline

The following timeline reconstructs the attack chain based on forensic artifacts recovered during the investigation:

* **Initial Access:** Attacker authenticated remotely via RDP using a compromised user account from an external IP address.
* **Discovery:** Immediately post-login, network enumeration tools (`arp.exe`, `net.exe`) were executed to map the local environment.
* **Defense Evasion:** A staging directory was created and hidden (`attrib +h`). Windows Defender exclusions were added for specific file extensions and folder paths to prevent detection.
* **Execution:** A malicious dropper script (PowerShell/Batch) was downloaded using a "Living off the Land" binary (`certutil`/`bitsadmin`) and executed.
* **Persistence:** A scheduled task with a deceptive name was created to execute the malware payload automatically upon system reboot.
* **C2 Establishment:** The malware initiated outbound connections to an external Command & Control (C2) server on a non-standard port.
* **Credential Access:** A credential dumping tool (renamed to evade detection) was deployed to extract secrets from LSASS memory.
* **Collection & Exfiltration:** Sensitive data was archived into a ZIP file and exfiltrated via HTTPS to a public cloud storage service.
* **Impact:** A backdoor local administrator account was created. The attacker then used `cmdkey` and `mstsc` to pivot (lateral movement) to a secondary target.
* **Anti-Forensics:** Windows Event Logs were cleared using `wevtutil` to destroy evidence of the intrusion.

## 🔍 Detailed Investigation Findings

### 1. Initial Access & Reconnaissance
The investigation identified that the attack originated from an **External IP Address** connecting via **RDP (RemoteInteractive)**. The attacker successfully authenticated using a valid **Compromised User Account**, suggesting a prior credential theft or weak password. Once inside, they executed `arp -a` and `ipconfig` to identify neighboring hosts.

### 2. Defense Evasion Strategies
The attacker employed multiple evasion techniques:
* **Staging:** Created a hidden directory in `C:\Users\Public` or `%TEMP%`.
* **Defender Tampering:** Modified the Registry to exclude specific extensions (e.g., `.exe`, `.ps1`) and the staging folder path from antivirus scanning.
* **LOLBins:** Abused legitimate Windows binaries (identified as `certutil.exe` or similar) to download malicious payloads via HTTP, bypassing standard download restrictions.

### 3. Persistence & Privilege Escalation
To maintain access, the attacker created a **Scheduled Task** pointing to their malicious executable. Additionally, a secondary **Backdoor Account** was created and added to the Local Administrators group, ensuring re-entry if the primary compromised account was disabled.

### 4. Command & Control (C2)
Network telemetry revealed consistent outbound traffic from the malicious process to a specific **C2 IP Address**. The communication occurred over a specific port, indicative of a known C2 framework (e.g., Cobalt Strike or Metasploit).

### 5. Exfiltration
Artifacts confirmed the creation of a compressed archive (`.zip`) containing stolen data. Network logs showed a high-volume data transfer to a **Cloud Storage Service** (e.g., Mega.nz, Discord CDN, or Google Drive) over port 443.

### 6. Lateral Movement
Forensic evidence indicates the attacker did not stop at `azuki-sl`. They utilized `cmdkey.exe` to store stolen credentials and `mstsc.exe` with the `/v:` switch to initiate a remote desktop connection to a **Secondary Target IP**, confirming lateral movement attempts.

## 🛡️ Indicators of Compromise (IOCs)

| Category | Indicator Type | Artifact Description | Action Taken |
| :--- | :--- | :--- | :--- |
| **Network** | IPv4 Address | Source IP of RDP Attack | Blocked at Firewall |
| **Network** | IPv4 Address | Command & Control (C2) Server IP | Blocked at Firewall |
| **Network** | Domain/URL | Cloud Exfiltration Destination | Web Filter Updated |
| **File** | Hash / Name | Malicious Dropper Script (`.ps1`/`.bat`) | Quarantined |
| **File** | Hash / Name | Renamed Credential Dumper | Quarantined |
| **File** | Path | Hidden Staging Directory | Purged |
| **System** | Account | Compromised User Account | Password Reset / Disabled |
| **System** | Account | Backdoor Administrator Account | Deleted |
| **System** | Scheduled Task | Malicious Persistence Task | Deleted |
| **System** | Registry Key | Defender Exclusion Paths | Removed |

## 💡 Recommendations & Remediation

1. **Isolate Infected Hosts:** Immediately isolate `azuki-sl` and the secondary target identified in the lateral movement phase.
2. **Credential Reset:** Force a global password reset for the compromised user and all administrator accounts.
3. **Patch Management:** Ensure all systems are patched against known RDP vulnerabilities.
4. **Network Segmentation:** Restrict RDP access from external sources; require VPN with MFA for all remote access.
5. **Attack Surface Reduction:** Block execution of "Living off the Land" binaries (like `certutil`) from initiating network connections via ASR rules.
6. **Enhanced Monitoring:** Tune SIEM alerts for `wevtutil cl` usage, Defender exclusion modifications, and new local admin account creation.
