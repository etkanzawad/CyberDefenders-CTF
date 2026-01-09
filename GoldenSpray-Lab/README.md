# GoldenSpray Lab: Multi-Stage Active Directory Intrusion Analysis

## 🔍 Project Overview

GoldenSpray is a blue team challenge that simulates a sophisticated multi-stage Active Directory compromise. The investigation requires analyzing Windows Security and Sysmon event logs within Elastic SIEM to reconstruct an attack timeline spanning initial access through data exfiltration. This challenge emphasizes credential-based attacks, lateral movement techniques, and persistence mechanisms commonly observed in enterprise network breaches.

**MITRE ATT&CK**: [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

**Platform**: CyberDefenders  
**Link**: https://cyberdefenders.org/blueteam-ctf-challenges/goldenspray/  
**Difficulty**: Medium  
**Tools**: Elastic SIEM, Splunk Query Language (SPL)

---

## 📋 Scenario

As a cybersecurity analyst at SecureTech Industries, you've been alerted to unusual login attempts and unauthorized access within the company's network. Initial indicators suggest a potential brute-force attack on user accounts. Your mission is to analyze the provided log data to trace the attack's progression, determine the scope of the breach, and identify the attacker's tactics, techniques, and procedures (TTPs).

---

## 🎯 Investigation Summary

### Attack Chain Overview:

1. **Initial Access (Password Spray)**: Attacker conducts password spraying attack against multiple user accounts from external IP
2. **Credential Access**: Successful compromise of domain user account through weak password
3. **Tool Deployment**: Malicious executables staged in public directories for persistence and credential dumping
4. **Privilege Escalation**: Mimikatz executed to extract credentials from LSASS memory
5. **Lateral Movement**: Stolen credentials used to compromise privileged domain account
6. **Domain Persistence**: Scheduled task created on Domain Controller with SYSTEM privileges
7. **Data Collection**: Sensitive data archived in preparation for exfiltration

---

## 📊 Questions & Solutions

### Q1: What is the attacker's IP address?

**Question**: What is the attacker's IP address?

**Answer**: `77.91.78.115`

**SPL**:
```
index=goldenspray event.code=4625
| stats count by winlog.computer_name
```

Then filter to most targeted host:
```
index=goldenspray event.code=4625 
  "winlog.computer_name"="ST-WIN02.SECURETECH.local"
| table winlog.event_data.IpAddress
```

**Analysis**:

The investigation began by searching for failed login attempts (Event ID 4625) across all systems. Aggregating by computer name revealed ST-WIN02.SECURETECH.local had the highest concentration of failed authentication events, indicating targeted attack activity.

Filtering to this specific host exposed the source IP address `77.91.78.115` in the `winlog.event_data.IpAddress` field. The high volume of failed attempts from a single external IP is a classic indicator of brute-force or password spraying attacks.

**Key Insight**: Event ID 4625 (Failed Logon) is critical for detecting authentication-based attacks. Aggregating by source IP helps identify distributed vs. concentrated attack patterns.

---

### Q2: What country is the attack originating from?

**Question**: What country is the attack originating from?

**Answer**: `Finland`

**Analysis**:

Using IP geolocation services (IP2Location.io), the attacker's IP `77.91.78.115` was geolocated to Finland. While the physical source could be legitimate infrastructure in Finland, it's more likely the attacker is using VPN exit nodes or compromised systems for anonymization.

Geographic attribution is valuable for:
- Identifying anomalous access patterns (e.g., logins from countries where the organization has no presence)
- Compliance requirements (GDPR, sanctions screening)
- Threat intelligence correlation (APT groups, regional threat actors)

**Detection Pattern**: Alerts should trigger when authentication attempts originate from unexpected geographic regions, especially when combined with failed login events.

---

### Q3: What's the compromised account username used for initial access?

**Question**: What's the compromised account username used for initial access?

**Answer**: `SECURETECH\mwilliams`

**SPL**:
```
index=goldenspray event.code=4624 
  "winlog.computer_name"="ST-WIN02.SECURETECH.local" 
  "winlog.event_data.IpAddress"="77.91.78.115"
| sort _time
| table _time, winlog.event_data.TargetUserName, winlog.event_data.LogonType
```

**Analysis**:

After identifying numerous failed login attempts (Event 4625), the search pivoted to successful authentications (Event 4624) from the attacker's IP. Sorting by timestamp revealed the earliest successful login was for user `michaelwilliams` (displayed as `mwilliams`) at `2024-09-09 16:56:05.672 UTC`.

The LogonType 3 (Network logon) indicates remote authentication, likely via SMB, WMI, or similar network protocols rather than interactive console access. This is typical for lateral movement and remote execution techniques.

**Password Spraying Success**: The attacker tested common passwords against multiple accounts (visible in earlier 4625 events), successfully guessing mwilliams' weak password. This highlights the importance of strong password policies and account lockout thresholds.

---

### Q4: What's the name of the malicious file utilized by the attacker for persistence on ST-WIN02?

**Question**: What's the name of the malicious file utilized by the attacker for persistence on ST-WIN02?

**Answer**: `OfficeUpdater.exe`

**SPL**:
```
index=goldenspray "winlog.computer_name"="ST-WIN02.SECURETECH.local" 
  event.code=11 
  "winlog.event_data.TargetFilename"="C:\\Windows\\Temp\\*.exe"
| table _time, winlog.event_data.TargetFilename, winlog.event_data.User, winlog.event_data.Image
| sort _time
```

**Analysis**:

Sysmon Event ID 11 (File Creation) tracking revealed `OfficeUpdater.exe` created in `C:\Windows\Temp\` at `2024-09-09 17:12:14.553` by PowerShell under the `mwilliams` account context.

The filename employs social engineering tactics - "OfficeUpdater" mimics legitimate Microsoft Office update processes, reducing suspicion during casual investigation. The file was created by `powershell.exe`, indicating download or script-based deployment.

While located in the Temp directory, this executable likely establishes persistence through Registry Run keys or Startup folder shortcuts. The temporal proximity to credential dumping activities (17 minutes before mimikatz) suggests coordinated multi-stage attack orchestration.

**Red Flag**: Executables dropped by PowerShell in Temp directories, especially with deceptive legitimate-sounding names, warrant immediate investigation.

---

### Q5: What is the complete path used by the attacker to store their tools?

**Question**: What is the complete path used by the attacker to store their tools?

**Answer**: `C:\Users\Public\Backup_Tools\`

**Analysis**:

The attacker created a centralized staging directory at `C:\Users\Public\Backup_Tools\` to organize their toolkit, including mimikatz.exe and other utilities. This location was chosen for several strategic reasons:

- **Universal Access**: The Public folder is readable/writable by all users without special permissions
- **Persistence**: Survives across user sessions and account changes
- **Deception**: "Backup_Tools" appears legitimate to administrators performing casual investigations
- **Operational Efficiency**: Centralized storage simplifies tool management during multi-stage operations

This directory housed mimikatz.exe and likely other post-exploitation tools. Monitoring file creation events in `C:\Users\Public\` can help detect adversary staging operations.

---

### Q6: What's the process ID of the tool responsible for dumping credentials on ST-WIN02?

**Question**: What's the process ID of the tool responsible for dumping credentials on ST-WIN02?

**Answer**: `3708`

**SPL**:
```
index=goldenspray "winlog.computer_name"="ST-WIN02.SECURETECH.local" 
  event.code=1 
  "winlog.event_data.OriginalFileName"="mimikatz.exe"
| table _time, winlog.event_data.ProcessId, winlog.event_data.CommandLine, winlog.event_data.User
```

**Analysis**:

Sysmon Event ID 1 (Process Creation) logs revealed two mimikatz.exe executions with PIDs 3708 and 528. The parent process command line for PID 3708 showed:

```
powershell.exe -noexit -command Set-Location -literalPath 'C:\Users\Public\Backup_Tools'
```

This PowerShell session navigated to the tools directory before executing mimikatz, confirming PID 3708 as the credential dumping process. The `-noexit` flag kept the PowerShell session open for additional commands.

Mimikatz targets the LSASS (Local Security Authority Subsystem Service) process to extract:
- Plaintext passwords (if WDigest enabled)
- NTLM hashes
- Kerberos tickets (TGTs/TGS)

**MITRE ATT&CK**: T1003.001 - OS Credential Dumping: LSASS Memory

---

### Q7: What's the second account username the attacker compromised and used for lateral movement?

**Question**: What's the second account username the attacker compromised and used for lateral movement?

**Answer**: `SECURETECH\jsmith`

**Analysis**:

After dumping credentials from ST-WIN02, the attacker extracted credentials for the `jsmith` account. Evidence of this compromise appeared in:

1. Startup folder file modifications for jsmith's profile
2. Process execution events on ST-DC01 under jsmith's context
3. Successful Event 4624 logins for jsmith from compromised systems

The jsmith account likely possessed elevated privileges (Domain Admin or similar), enabling access to the Domain Controller (ST-DC01). This represents classic lateral movement - using stolen credentials to pivot from an initial foothold to high-value targets.

**MITRE ATT&CK**: T1078 - Valid Accounts, T1021 - Remote Services

---

### Q8: Can you provide the scheduled task created by the attacker for persistence on the domain controller?

**Question**: Can you provide the scheduled task created by the attacker for persistence on the domain controller?

**Answer**: `FilesCheck`

**SPL**:
```
index=goldenspray source="ST-DC01.ndjson"
  event.code=1 
  "winlog.event_data.Image"="*schtasks.exe"
| table _time, winlog.event_data.CommandLine, winlog.event_data.User
```

**Analysis**:

On the Domain Controller (ST-DC01), the attacker created a scheduled task named "FilesCheck" at `2024-09-09 17:38:44.390` using schtasks.exe:

```
schtasks /create /tn "FilesCheck" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\FileCleaner.exe" /sc hourly /ru SYSTEM
```

**Critical Details**:
- **Task Name**: FilesCheck (deceptive, sounds like system maintenance)
- **Trigger**: Hourly execution
- **Action**: PowerShell executes FileCleaner.exe with bypassed execution policy
- **User Context**: SYSTEM (highest privileges on the DC)

Persistence on the Domain Controller represents complete domain compromise. The SYSTEM-level hourly execution ensures reliable command-and-control beacon or continuous data exfiltration capability.

**MITRE ATT&CK**: T1053.005 - Scheduled Task/Job: Scheduled Task

---

### Q9: What type of encryption is used for Kerberos tickets in the environment?

**Question**: What type of encryption is used for Kerberos tickets in the environment?

**Answer**: `RC4-HMAC`

**SPL**:
```
index=goldenspray event.code=4769
| stats count by winlog.event_data.TicketEncryptionType
```

**Analysis**:

Event ID 4769 (Kerberos Service Ticket Request) logs revealed all 24 ticket requests used encryption type `0x17` (RC4-HMAC). This represents a significant security weakness:

**RC4-HMAC Vulnerabilities**:
- Introduced in Windows 2000 (legacy algorithm)
- Weaker than AES-128/256 encryption
- Susceptible to Kerberoasting attacks
- Enables offline password cracking of service account tickets

**Kerberoasting Attack Vector**: Attackers can request service tickets encrypted with RC4, capture them from memory or network traffic, and crack them offline using tools like Hashcat. This allows discovery of service account passwords without triggering account lockout.

**Recommendation**: Modern Active Directory environments should enforce AES256 or AES128 encryption for Kerberos tickets through Group Policy.

**MITRE ATT&CK**: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

---

### Q10: Can you provide the full path of the output file in preparation for data exfiltration?

**Question**: Can you provide the full path of the output file in preparation for data exfiltration?

**Answer**: `C:\Users\Public\Documents\Archive_8673812.zip`

**SPL**:
```
index=goldenspray event.code=11 
  winlog.event_data.TargetFilename="*.zip"
| table _time, winlog.event_data.TargetFilename, winlog.event_data.User, winlog.event_data.Image
| sort _time
```

**Analysis**:

Sysmon Event 11 revealed two ZIP archives:
1. `C:\Users\Public\Backup_Tools.zip` (archived attack tools)
2. `C:\Users\Public\Documents\Archive_8673812.zip` (data exfiltration package)

The exfiltration file is distinguished by:
- **Location**: Documents folder (data storage vs. tools)
- **Naming**: Random numeric identifier (8673812) typical of automated exfil scripts
- **Purpose**: Compressed sensitive data for efficient transfer

Data compression reduces file size and transfer time, making exfiltration faster and less detectable by DLP solutions monitoring file transfers. The archive likely contains:
- Credential databases (SAM, NTDS.dit)
- Intellectual property documents
- Configuration files
- Email archives

**MITRE ATT&CK**: T1560.001 - Archive Collected Data: Archive via Utility

---

## 🔑 Key Findings

### Attack Timeline

| Time (UTC) | Event | Description | Question |
|------------|-------|-------------|----------|
| 2024-09-09 15:17:05 | File Creation | Attacker activity observed in jsmith profile | Q7 ✓ |
| 2024-09-09 16:56:05 | Successful Login | mwilliams account compromised from 77.91.78.115 (Finland) | Q1-Q3 ✓ |
| 2024-09-09 17:12:14 | File Creation | OfficeUpdater.exe deployed for persistence | Q4 ✓ |
| 2024-09-09 17:23:07 | File Creation | mimikatz.exe staged in C:\Users\Public\Backup_Tools\ | Q5 ✓ |
| 2024-09-09 17:23:07 | Process Execution | Mimikatz PID 3708 dumps credentials from LSASS | Q6 ✓ |
| 2024-09-09 17:38:44 | Scheduled Task | FilesCheck task created on DC with SYSTEM privileges | Q8 ✓ |
| 2024-09-09 (various) | Kerberos Tickets | RC4-HMAC encryption observed (vulnerable to Kerberoasting) | Q9 ✓ |
| 2024-09-09 (late) | Data Staging | Archive_8673812.zip created for exfiltration | Q10 ✓ |

### IOCs (Indicators of Compromise)

**Network**:
- Source IP: `77.91.78.115` (Finland)
- Multiple failed authentication attempts (Event 4625)
- Network logons (LogonType 3) from external IP

**Accounts**:
- Compromised: `SECURETECH\mwilliams` (initial access)
- Compromised: `SECURETECH\jsmith` (lateral movement, elevated privileges)

**Host**:
- Malicious File: `C:\Windows\Temp\OfficeUpdater.exe`
- Attack Tool: `C:\Users\Public\Backup_Tools\mimikatz.exe`
- Scheduled Task: `FilesCheck` (runs hourly as SYSTEM)
- Exfiltration Package: `C:\Users\Public\Documents\Archive_8673812.zip`
- Tool Staging: `C:\Users\Public\Backup_Tools\` (directory)

**Behavior**:
- Password spraying against multiple accounts
- PowerShell execution with `-ExecutionPolicy Bypass` flag
- LSASS memory access (credential dumping)
- Kerberos ticket requests using RC4-HMAC encryption
- Scheduled task creation on Domain Controller

---

## 🛡️ Detection & Hunting Guidance

### Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 4625 | Security | Failed logon attempts (detects password spraying) |
| 4624 | Security | Successful logon (correlate with 4625 for compromise detection) |
| 4769 | Security | Kerberos service ticket requests (Kerberoasting detection) |
| 4698 | Security | Scheduled task created (persistence mechanism) |
| Sysmon 1 | Sysmon | Process creation (tracks mimikatz, PowerShell abuse) |
| Sysmon 10 | Sysmon | Process access (LSASS access indicates credential dumping) |
| Sysmon 11 | Sysmon | File creation (malware deployment, data staging) |

---

## 📚 Lessons Learned

### Technical Insights:

**Password Spraying Detection**: Organizations must implement rate-limiting on failed authentication attempts and monitor for patterns where single IPs target multiple accounts with few attempts per account (evades traditional lockout policies).

**LSASS Protection**: Enable Windows Defender Credential Guard and LSA Protection to prevent memory-based credential extraction. Monitor Sysmon Event 10 for LSASS process access from non-system processes.

**PowerShell Security**: Implement PowerShell Constrained Language Mode, script block logging, and monitor for `-ExecutionPolicy Bypass` flag usage. Legitimate administrative scripts should be signed and approved.

**Kerberos Hardening**: Migrate from RC4-HMAC to AES256 encryption for Kerberos tickets. Implement monitoring for Event 4769 with RC4 encryption types as potential Kerberoasting indicators.

**Public Folder Monitoring**: The C:\Users\Public\ directory is a common staging location for adversaries due to universal write permissions. File creation events in this location should trigger alerts.

**Domain Controller Security**: Any unexpected scheduled task creation on DCs (Event 4698) or process executions under SYSTEM context require immediate investigation. Domain Controllers should have strict change control.

### MITRE ATT&CK Mapping

| Tactic | Technique | Example from Lab |
|--------|-----------|------------------|
| Initial Access | T1110.003 - Password Spraying | Failed logins (4625) from 77.91.78.115 targeting multiple accounts |
| Execution | T1059.001 - PowerShell | powershell.exe with -ExecutionPolicy Bypass deploying malware |
| Persistence | T1053.005 - Scheduled Task | FilesCheck task on DC running hourly as SYSTEM |
| Privilege Escalation | T1078 - Valid Accounts | Using stolen jsmith credentials for DC access |
| Defense Evasion | T1027 - Obfuscated Files | Deceptive naming (OfficeUpdater.exe, FilesCheck) |
| Credential Access | T1003.001 - LSASS Memory | Mimikatz PID 3708 dumping credentials |
| Discovery | T1087 - Account Discovery | Password spray revealed valid account names |
| Lateral Movement | T1021 - Remote Services | LogonType 3 from ST-WIN02 to ST-DC01 |
| Collection | T1560.001 - Archive Collected Data | Archive_8673812.zip compressed sensitive data |
| Exfiltration | T1041 - Exfiltration Over C2 | Staged archive ready for transfer |

---

## 🔗 References

- [MITRE ATT&CK - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK - LSASS Memory Dumping](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK - Scheduled Task Persistence](https://attack.mitre.org/techniques/T1053/005/)
- [Microsoft - Kerberos Encryption Types](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [Microsoft - Sysmon Event Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [CyberDefenders - GoldenSpray Lab](https://cyberdefenders.org/blueteam-ctf-challenges/goldenspray/)
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz/wiki)

---

## 📝 Conclusion

The GoldenSpray lab successfully simulates a sophisticated Active Directory breach combining password spraying, credential access, lateral movement, and persistence mechanisms. The investigation demonstrated the critical importance of comprehensive logging (Windows Security + Sysmon) and proficient SIEM query construction for threat hunting.

The attacker's methodology followed a textbook APT playbook: initial access via weak passwords, immediate credential dumping to expand access, lateral movement to high-value targets (Domain Controller), and establishment of persistent backdoors with SYSTEM privileges. The use of RC4-HMAC Kerberos encryption provided additional attack surface through Kerberoasting techniques.

This challenge highlighted how adversaries leverage legitimate system tools (PowerShell, schtasks) and deceptive naming conventions (OfficeUpdater, FilesCheck) to evade detection. The 17-minute window between initial compromise and credential dumping underscores the speed at which modern attacks unfold, emphasizing the need for real-time detection capabilities.

**Key Takeaway**: Organizations must:

1. **Enforce strong authentication controls** including password complexity, account lockout policies resistant to password spraying, and multi-factor authentication for privileged accounts
2. **Implement comprehensive logging** with Sysmon for process, file, and network monitoring supplementing native Windows Security logs
3. **Harden Kerberos infrastructure** by migrating from RC4-HMAC to AES256 encryption and monitoring for service ticket anomalies
4. **Monitor high-value targets** like Domain Controllers with strict alerting on scheduled task creation, unusual process execution, and credential access patterns
5. **Deploy endpoint protection** including LSASS protection mechanisms (Credential Guard, PPL) to prevent memory-based credential theft
6. **Establish detection rules** for PowerShell execution with bypass flags, file creation in Public directories, and LSASS process access events

**Challenge Completed**: 10/10 Questions ✅

**Skills Demonstrated**:
- Advanced SIEM query construction and log correlation
- Windows event log forensics (Security and Sysmon)
- Attack timeline reconstruction and pivot analysis
- MITRE ATT&CK framework mapping
- Credential dumping technique recognition
- Active Directory attack pattern identification
- Threat hunting methodology application

---

*Writeup Author: CTF Participant*  
*Lab Platform: CyberDefenders*  
*Completion Date: January 2026*
