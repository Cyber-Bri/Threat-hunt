#  Threat Hunt Report  
### **Incident:** Azuki Import/Export 
**Case ID:** GH-AZUKI-2411  
**Date:** November 29 2025  
**Analyst:** Brian Hardy  
**Data Source:** Microsoft Defender for Endpoint (MDE) 

---

## 1. Incident Brief

**Summary:**  
Azuki Import/Export Trading Co. (梓貿易株式会社) is a mid-sized logistics company based in Japan with 23 employees, specializing in maritime shipping operations across Japan and Southeast Asia. The company experienced a suspected data breach when proprietary supplier contract and pricing data appeared on underground forums.

Shortly after the leak, a direct competitor underbid Azuki’s six-year shipping contract renewal by exactly **3%**, strongly suggesting insider knowledge or exfiltration of Azuki’s confidential cost structures.

**Affected System:**  
- **AZUKI-SL** — IT Administrator Workstation

**Indicators of Compromise Source:**  
- Microsoft Defender for Endpoint telemetry (primary evidence)
- System logs from the compromised endpoint

**Initial Assessment:**  
Early investigation suggests that an attacker gained unauthorized access to the IT admin workstation (AZUKI-SL) and exfiltrated internal contract data. The attacker likely employed **Command and Control (C2)** infrastructure for data transmission and used **defense evasion** tactics such as altering Windows Defender exclusions.

---

