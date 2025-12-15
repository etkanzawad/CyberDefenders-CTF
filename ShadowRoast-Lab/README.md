# ShadowRoast Lab: Active Directory Attack Investigation

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Splunk-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

[ShadowRoast Challenge](https://cyberdefenders.org/blueteam-ctf-challenges/shadowroast/)

---

## 🔍 Project Overview

This repository documents my investigation into the **ShadowRoast Lab** challenge on CyberDefenders, focusing on detecting and analyzing a sophisticated multi-stage Active Directory attack involving AS-REP Roasting, DCShadow, and data exfiltration.

**Objective:** Analyze Sysmon telemetry and Windows Security logs to identify initial access vectors, persistence mechanisms, credential harvesting through Kerberos exploitation, lateral movement, and data exfiltration techniques employed by the attacker.

**MITRE ATT&CK Techniques:** [T1558.004 - AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/), [T1207 - Rogue Domain Controller](https://attack.mitre.org/techniques/T1207/)

---

## 📋 Scenario

As a cybersecurity analyst at TechSecure Corp, you have been alerted to unusual activities within the company's Active Directory environment. Initial reports suggest unauthorized access and possible privilege escalation attempts.

Your task is to analyze the provided logs to uncover the attack's extent and identify the malicious actions taken by the attacker. Your investigation will be crucial in mitigating the threat and securing the network.

---

## 🎯 Investigation Summary

### Attack Chain Overview

1. **Initial Access:** Phishing payload disguised as legitimate Adobe updater delivered to user workstation
2. **Persistence Establishment:** Registry Run key created with obfuscated PowerShell for logon persistence
3. **Tool Staging:** Malicious utilities dropped to system template directory for stealth
4. **Credential Harvesting:** AS-REP Roasting attack executed to obtain domain account credentials
5. **Privilege Escalation:** Mimikatz deployed for DCShadow capability and AD manipulation
6. **Lateral Movement:** Remote Desktop Protocol enabled on target systems via registry modification
7. **Data Exfiltration:** Confidential data compressed and staged for extraction

---

## 📊 Questions & Solutions

### Q1: Initial Access Vector

**Question:** What's the malicious file name utilized by the attacker for initial access?

* **Answer:** `AdobeUpdater.exe`
* **SPL:**
    ```spl
    index="shadowroast" event.code=1
    | search winlog.event_data.Image="*\\Users\\*" OR winlog.event_data.Image="*\\AppData\\*" OR winlog.event_data.Image="*\\Downloads\\*"
    | sort @timestamp
    | table @timestamp, winlog.event_data.Image, winlog.event_data.ParentImage, winlog.event_data.CommandLine
    | head 50
    ```
* **Analysis:**
  - Examined process creation events (Sysmon Event ID 1) for executables in user-writable directories
  - Identified `AdobeUpdater.exe` executing from `C:\Users\sanderson\Downloads\` as earliest suspicious process
  - Demonstrates masquerading technique (MITRE T1036) - named to impersonate legitimate Adobe software
  - Upon execution, functioned as self-extracting archive creating temporary directories and dropping additional tools

**Key Insight:** Monitor for executables with vendor names executing from non-standard locations like Downloads or AppData folders, especially when lacking valid digital signatures.

---

### Q2: Persistence Mechanism

**Question:** What's the registry run key name created by the attacker for maintaining persistence?

* **Answer:** `wyW5PZyF`
* **SPL:**
    ```spl
    index="shadowroast" event.code=13
    | search winlog.event_data.TargetObject="*\\Run*" OR winlog.event_data.TargetObject="*\\RunOnce*"
    | table @timestamp, winlog.event_data.Image, winlog.event_data.TargetObject, winlog.event_data.Details
    ```
* **Analysis:**
  - Used Sysmon Event ID 13 (Registry Value Set) to identify registry modifications
  - Revealed `AdobeUpdater.exe` creating Run key at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\wyW5PZyF`
  - Implemented two-stage registry persistence: trigger key (wyW5PZyF) + payload storage (HKCU:Software\EdI86Dhr)
  - PowerShell command uses stealth parameters (`-nop`, `-w hidden`) and Base64-encoded payload
  - Separation of trigger from payload provides detection evasion

**Detection Pattern:** Alert on registry Run key modifications with random alphanumeric names (8+ characters) combined with PowerShell commands containing Base64 encoding or hidden window parameters.

---

### Q3: Tool Storage Location

**Question:** What's the full path of the directory used by the attacker for storing his dropped tools?

* **Answer:** `C:\Users\Default\AppData\Local\Temp\`
* **SPL:**
    ```spl
    index="shadowroast" event.code=11
    | search winlog.event_data.Image="*AdobeUpdater.exe"
    | table winlog.event_data.TargetFilename, winlog.event_data.Image
    ```
* **Analysis:**
  - File creation events (Sysmon Event ID 11) revealed three tools dropped: DefragTool.exe, SystemDiagnostics.ps1, BackupUtility.exe
  - All staged in `C:\Users\Default\AppData\Local\Temp\`
  - Default user profile is Windows template copied when creating new accounts
  - Demonstrates sophisticated tradecraft: stealth through template abuse, persistence across users, legitimate context blending

**Red Flag:** File creation in `C:\Users\Default\` is rare after OS installation. Monitor this location for unauthorized modifications.

---

### Q4: Credential Harvesting Tool

**Question:** What tool was used by the attacker for privilege escalation and credential harvesting?

* **Answer:** `Rubeus`
* **SPL:**
    ```spl
    index="shadowroast" event.code=1
    | search winlog.event_data.CommandLine="*asreproast*"
    | table @timestamp, winlog.event_data.Image, winlog.event_data.CommandLine, winlog.event_data.User
    ```
* **Analysis:**
  - Identified `BackupUtility.exe` (renamed Rubeus) executing with command: `asreproast /format:hashcat`
  - Rubeus is C# post-exploitation tool specializing in Kerberos abuse and manipulation
  - AS-REP Roasting (MITRE T1558.004) targets accounts with pre-authentication disabled
  - Extracts TGTs without credentials, outputs hashes in hashcat format for offline cracking
  - Lab name "ShadowRoast" directly references this technique

**Key Insight:** Monitor for command-line parameters containing `asreproast`, `kerberoast`, or references to hashcat/John the Ripper output formats.

---

### Q5: Compromised Account

**Question:** Was the attacker's credential harvesting successful? If so, can you provide the compromised domain account username?

* **Answer:** `tcooper`
* **SPL:**
    ```spl
    index="shadowroast" log.file.path="*Security.evtx" event.code=4768 
    | search winlog.event_data.IpAddress="*10.0.0.184" winlog.event_data.Status="0x0"
    | table @timestamp, winlog.event_data.TargetUserName, winlog.event_data.PreAuthType, winlog.event_data.Status
    | dedup winlog.event_data.TargetUserName
    ```
* **Analysis:**
  - Analyzed Windows Security Event ID 4768 (Kerberos TGT Request) for successful authentications
  - Identified multiple successful authentications from attacker's IP (10.0.0.184): tcooper, sanderson, FileShareService, Administrator
  - Based on 7-character pattern requirement, **tcooper** is the compromised account
  - Timestamp (01:13:28) occurs ~3 minutes after Rubeus execution (01:10:45), indicating offline password cracking then authentication
  - Account likely had pre-authentication disabled, making it vulnerable

**Detection Pattern:** Correlate Kerberos authentication failures (PreAuthType="-") followed by successful authentications from same source IP within short timeframes.

---

### Q6: Active Directory Manipulation Tool

**Question:** What's the tool used by the attacker for registering a rogue Domain Controller to manipulate Active Directory data?

* **Answer:** `Mimikatz`
* **SPL:**
    ```spl
    index="shadowroast" event.code=1
    | search winlog.event_data.Image="C:\\Users\\Default\\AppData\\Local\\Temp\\*"
    | table @timestamp, winlog.event_data.Image, winlog.event_data.CommandLine, winlog.event_data.OriginalFileName
    ```
* **Analysis:**
  - Mimikatz is industry-standard post-exploitation tool for Windows credential attacks and AD manipulation
  - Lab name "**Shadow**Roast" references DCShadow attack technique (MITRE T1207)
  - DCShadow temporarily registers rogue DC, manipulates AD objects without triggering normal monitoring
  - Requires Domain Admin privileges (obtained via tcooper compromise)
  - Capabilities include DCSync, DCShadow, Kerberos ticket forging, token manipulation

**Key Insight:** Monitor for unusual DC registration events (Event IDs 5137, 5141), LDAP modifications from non-DC sources, and processes accessing LSASS memory (Sysmon Event ID 10).

---

### Q7: Lateral Movement Preparation

**Question:** What's the first command used by the attacker for enabling RDP on remote machines for lateral movement?

* **Answer:** `reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0`
* **SPL:**
    ```spl
    index="shadowroast" event.code=1 
    | search winlog.event_data.CommandLine="*fDenyTSConnections*"
    | table @timestamp, winlog.event_data.Image, winlog.event_data.CommandLine
    ```
* **Analysis:**
  - Used Windows built-in `reg.exe` to modify registry controlling Remote Desktop Services
  - Registry path: `HKLM\System\CurrentControlSet\Control\Terminal Server`
  - `/f` = Force overwrite, `/v fDenyTSConnections` = Value controlling RDP access, `/d 0` = Enable RDP (1 would disable)
  - After compromising Domain Admin credentials, attacker enabled RDP for interactive GUI access
  - Represents lateral movement (MITRE T1021.001) preparation for data exfiltration

**Detection Pattern:** Alert on `reg.exe` modifying `fDenyTSConnections` registry value, especially on systems that don't normally use RDP.

---

### Q8: Data Exfiltration

**Question:** What's the file name created by the attacker after compressing confidential files?

* **Answer:** `CrashDump.zip`
* **SPL:**
    ```spl
    index="shadowroast" event.code=11
    | search (winlog.event_data.TargetFilename="*.zip" OR 
              winlog.event_data.TargetFilename="*.rar" OR 
              winlog.event_data.TargetFilename="*.7z")
    | table @timestamp, winlog.event_data.TargetFilename, winlog.event_data.Image, winlog.event_data.User
    | sort @timestamp
    ```
* **Analysis:**
  - File creation revealed: `C:\Users\Default\AppData\Local\Temp\CrashDump.zip`
  - Created by: `powershell.exe`, User: `CORPNET\tcooper` (Domain Admin), Timestamp: 01:21:04 UTC
  - Used PowerShell's `Compress-Archive` cmdlet to package confidential data
  - Filename demonstrates masquerading (MITRE T1036.005) - mimics legitimate Windows crash dumps
  - "CrashDump.zip" naming strategy: appears legitimate, less likely to trigger DLP alerts, blends with normal IT operations
  - Complete attack chain concluded ~15 minutes after initial access

**Red Flag:** Monitor for archive creation by PowerShell or command-line tools, especially by privileged accounts in temporary directories.

---

## 🔑 Key Findings

### Attack Timeline

| Time (UTC) | Event | Description | Question |
|------------|-------|-------------|----------|
| 01:05:58 | Initial Access | AdobeUpdater.exe executed from Downloads folder | Q1 ✓ |
| 01:06:15 | Persistence Created | Registry Run key wyW5PZyF with obfuscated PowerShell | Q2 ✓ |
| 01:06:30 | Tool Staging | Three malicious tools dropped to Default user template | Q3 ✓ |
| 01:10:45 | Credential Harvesting | Rubeus AS-REP Roasting executed | Q4 ✓ |
| 01:10:48 | Privilege Escalation | Mimikatz deployed for DCShadow capability | Q6 ✓ |
| 01:10:xx | Lateral Movement Prep | RDP enabled via registry modification | Q7 ✓ |
| 01:13:28 | Compromise Success | tcooper Domain Admin account authenticated | Q5 ✓ |
| 01:21:04 | Data Exfiltration | CrashDump.zip created with confidential data | Q8 ✓ |

### IOCs (Indicators of Compromise)

**Network:**
- Source IP: `10.0.0.184` (compromised workstation)
- Kerberos TGT requests from unusual sources
- LDAP traffic to/from non-DC systems (DCShadow)

**Accounts:**
- Compromised: `CORPNET\tcooper` (Domain Admin)
- Initial victim: `CORPNET\sanderson`
- Service accounts targeted: `FileShareService`, `Administrator`

**Host:**
- Files:
  - `C:\Users\sanderson\Downloads\AdobeUpdater.exe`
  - `C:\Users\Default\AppData\Local\Temp\DefragTool.exe`
  - `C:\Users\Default\AppData\Local\Temp\SystemDiagnostics.ps1`
  - `C:\Users\Default\AppData\Local\Temp\BackupUtility.exe` (Rubeus)
  - `C:\Users\Default\AppData\Local\Temp\CrashDump.zip`
- Registry Keys:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\wyW5PZyF`
  - `HKCU:Software\EdI86Dhr` (Base64 payload storage)
  - `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 0`

**Behavior:**
- AS-REP Roasting attempts (Event ID 4768, Status 0xE)
- Rogue DC registration indicators
- PowerShell with hidden windows and Base64 encoding
- Archive creation by privileged accounts in temp directories

---

## 🛡️ Detection & Hunting Guidance

### Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 1 | Sysmon | Process creation - detect malicious executables and command-line patterns |
| 3 | Sysmon | Network connections - identify C2 communications and lateral movement |
| 11 | Sysmon | File creation - monitor dropped tools and staged exfiltration archives |
| 13 | Sysmon | Registry modifications - detect persistence mechanisms and configuration changes |
| 4768 | Security | Kerberos TGT requests - identify AS-REP Roasting and authentication anomalies |
| 5137 | Security | Directory Service object created - detect rogue DC registration |
| 5141 | Security | Directory Service object deleted - monitor AD manipulation |

---

## 📚 Lessons Learned

### Technical Insights

**User Awareness Training:** Phishing remains the primary initial access vector. Organizations must implement regular security awareness training focusing on identifying fake software updates and verifying download sources before execution.

**Kerberos Security Hardening:** Accounts with pre-authentication disabled are vulnerable to AS-REP Roasting. Audit all domain accounts for this misconfiguration and enable pre-authentication unless specifically required for legacy application compatibility.

**Registry Run Key Monitoring:** Implement baseline monitoring for registry Run key modifications, alerting on random alphanumeric value names and PowerShell commands with obfuscation techniques (Base64, hidden windows, bypasses).

**Template Directory Protection:** The `C:\Users\Default\` profile template should be protected with enhanced monitoring. File creation in this location post-deployment indicates potential malware attempting to achieve multi-user persistence.

**Privileged Account Segmentation:** Domain Admin accounts like tcooper should never authenticate to workstations. Implement tiered administration models separating privileged access from daily operations to limit credential exposure.

**DLP for Archive Creation:** Monitor compression utility execution (PowerShell Compress-Archive, 7zip, WinRAR) by privileged accounts, especially when creating archives in temporary directories or with suspicious naming patterns.

### MITRE ATT&CK Mapping

| Tactic | Technique | Example from Lab |
|--------|-----------|------------------|
| Initial Access | T1566 - Phishing | AdobeUpdater.exe delivered via social engineering |
| Persistence | T1547.001 - Registry Run Keys | wyW5PZyF Run key with obfuscated PowerShell |
| Defense Evasion | T1036 - Masquerading | Tools named DefragTool, BackupUtility, CrashDump.zip |
| Credential Access | T1558.004 - AS-REP Roasting | Rubeus asreproast targeting tcooper account |
| Privilege Escalation | T1207 - Rogue Domain Controller | Mimikatz DCShadow capability deployment |
| Lateral Movement | T1021.001 - Remote Desktop Protocol | RDP enabled via fDenyTSConnections registry modification |
| Collection | T1560.001 - Archive via Utility | PowerShell Compress-Archive creating CrashDump.zip |
| Exfiltration | T1041 - Exfiltration Over C2 | Staged archive prepared for network transfer |

---

## 🔗 References

- [MITRE ATT&CK: AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/)
- [MITRE ATT&CK: Rogue Domain Controller (T1207)](https://attack.mitre.org/techniques/T1207/)
- [MITRE ATT&CK: Registry Run Keys (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [Microsoft: Kerberos Pre-Authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Rubeus Documentation - GhostPack](https://github.com/GhostPack/Rubeus)
- [Mimikatz Wiki - DCShadow](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump#dcshadow)
- [CyberDefenders Platform - ShadowRoast Lab](https://cyberdefenders.org/blueteam-ctf-challenges/)
- [Splunk Documentation - Windows Event Logs](https://docs.splunk.com/Documentation/Splunk/latest/Data/MonitorWindowseventlogdata)

---

## 📝 Conclusion

The ShadowRoast lab investigation successfully reconstructed a sophisticated multi-stage Active Directory attack demonstrating real-world threat actor tactics. The analysis revealed a well-planned operation progressing from initial phishing-based access through credential harvesting, privilege escalation, and ultimately data exfiltration—all within a 15-minute operational window.

The attacker demonstrated advanced tradecraft including masquerading techniques, dual-stage registry persistence, Kerberos exploitation via AS-REP Roasting, and Active Directory manipulation through DCShadow capabilities. The use of legitimate Windows utilities (reg.exe, PowerShell) alongside specialized security tools (Rubeus, Mimikatz) showcases the "living off the land" approach combined with purpose-built attack frameworks.

This investigation reinforces the critical importance of defense-in-depth strategies and proactive threat hunting. The attack chain included multiple opportunities for detection, from initial access through exfiltration, highlighting that comprehensive logging and behavioral analytics are essential for identifying sophisticated adversaries before mission completion.

**Key Takeaway - Organizations must:**

- **Implement robust Sysmon configuration** capturing process creation, network connections, file operations, and registry modifications with appropriate filtering to reduce noise while maintaining visibility
- **Deploy baseline alerting** for registry Run key modifications, Kerberos authentication anomalies (Event ID 4768 failures), and PowerShell obfuscation patterns including Base64 encoding and hidden window execution
- **Enforce Kerberos security** by auditing all domain accounts for pre-authentication settings, eliminating unnecessary disabled pre-auth configurations that enable AS-REP Roasting attacks
- **Segment privileged access** through tiered administration models preventing Domain Admin authentication to workstations and limiting credential exposure across network boundaries
- **Monitor template directories** with enhanced alerting for any file creation or modification in `C:\Users\Default\` outside of deployment windows
- **Correlate multi-stage attacks** using SIEM platforms to identify attack chains across initial access, persistence, credential harvesting, and exfiltration phases rather than isolated events

**Challenge Completed:** 8/8 Questions ✅

**Skills Demonstrated:**
- Advanced SPL query development and optimization
- Multi-source log correlation (Sysmon, Windows Security)
- Attack chain reconstruction and timeline analysis
- MITRE ATT&CK framework mapping and technique identification
- Kerberos protocol analysis and authentication anomaly detection
- Registry forensics and persistence mechanism identification
- Lateral movement tracking across network infrastructure
- Data exfiltration pattern recognition and staging detection
