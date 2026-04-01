# Rhysida - Vice Society Lab: Full Ransomware Attack Chain Reconstruction

## 🔍 Project Overview

This lab simulates a real-world Rhysida ransomware intrusion starting from a phishing credential theft and progressing through persistence, lateral movement, credential dumping, data exfiltration, and ransomware deployment. Using Splunk and CyberChef, the objective is to reconstruct the full attack chain across multiple endpoints. Analysis focuses on Sysmon telemetry across workstations and a Domain Controller to identify every stage of the compromise. The lab covers all major MITRE ATT&CK tactics from Initial Access through Impact.

**MITRE ATT&CK:** [https://attack.mitre.org/groups/G1003/](https://attack.mitre.org/groups/G1003/)

---

## 📋 Scenario

A system administrator unknowingly submitted their credentials to a realistic phishing page disguised as a Microsoft login portal. Within hours, multiple login attempts from external sources were observed using this privileged account. Internal monitoring soon flagged unusual process activity, registry modifications, and outbound traffic to unfamiliar destinations. Remote administration tools appeared across critical systems, and event logs began vanishing. The SOC suspects a full compromise is underway — spanning initial access, persistence, lateral movement, and potentially ransomware deployment. Your task is to uncover the attacker's path, identify persistence mechanisms, and assess the scope of data access and exfiltration.

---

## 🎯 Investigation Summary

### Attack Chain Overview

1. **Initial Access:** Admin credentials phished via typosquatted domain `microsoftoniine.ddns.net`, followed by SSH login from attacker IP `35.158.70.36`
2. **Execution:** Malicious DLL (`WindowsUpdate.dll`) dropped via SFTP; additional payloads downloaded using `certutil.exe`
3. **Persistence & Defense Evasion:** Registry Run key created; Defender disabled via encoded PowerShell; auditing and logs wiped
4. **Credential Access:** Browser credentials dumped via `BCleaner.exe`; LSASS dumped via renamed Mimikatz (`svchostt.exe`); AD dump attempted via `ntdsutil`
5. **Lateral Movement & C2:** PsExec (renamed `rdpcliip.exe`) spread malware across network; AnyDesk deployed for remote control; C2 beacon to `3.70.203.137`
6. **Exfiltration & Impact:** Sensitive data staged and zipped on Domain Controller; Rhysida ransomware (`Nbd6a7v.exe`) deployed across all machines

---

## 📊 Questions & Solutions

---

### Q1: Phishing Domain Identification

**Question:** What is the domain of the phishing page that captured the administrator's credentials?

**Answer:** `microsoftoniine.ddns.net`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=22
QueryName="*microsoft*"
```

**Analysis:**
- Sysmon Event ID 22 captures DNS queries, making it ideal for identifying domains visited before a network connection is established
- Filtered `QueryName` for Microsoft-themed domains to surface phishing infrastructure
- `microsoftoniine.ddns.net` stood out due to **typosquatting** ("oniine" vs "online") and use of a free DDNS service — legitimate Microsoft domains never use `.ddns.net`
- The query originated from **Firefox on ws3** under the `WS3\Administrator` account, confirming the compromised endpoint and user
- The domain resolved to IP `35.158.70.36`, which later appeared in SSH connection logs — tying phishing infrastructure directly to the attacker's access

> **🔴 Red Flag:** Browser-initiated DNS query to a typosquatted Microsoft domain using a dynamic DNS provider is a high-confidence phishing indicator

---

### Q2: SFTP File Drop — Process ID

**Question:** Following an unauthorized SSH login, a file appeared on the system, likely transferred via SCP or SFTP using OpenSSH. What is the Process ID of the process that wrote the file to disk?

**Answer:** `6936`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=29
```

**Analysis:**
- Sysmon Event ID 29 (File Executable Dropped) specifically captures executable/DLL files written to disk — more targeted than Event ID 11 which logs all file types
- `sftp-server.exe` wrote `C:\Users\Administrator\AppData\Local\Temp\WindowsUpdate.dll` to disk — suspicious because SFTP server processes should only handle file transfers, not write DLLs to Temp directories
- The `ProcessId` in the `EventData` section (`6936`) identifies `sftp-server.exe` as the actor — distinct from the Sysmon logger PID in the `System` header (`1448`)
- `WindowsUpdate.dll` is named to mimic a legitimate Windows component but placed in `%TEMP%` — a classic masquerading technique

> **🔑 Key Insight:** In Sysmon events, always distinguish between the `<Execution ProcessID>` (Sysmon's own PID) and `<Data Name='ProcessId'>` (the actual actor's PID)

---

### Q3: Initial Access Protocol

**Question:** After stealing the credentials, the attacker attempted to authenticate to the system using a specific protocol. What service was used to gain initial access?

**Answer:** `SSH`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=3 direction=inbound
```

**Analysis:**
- Filtered for inbound network connections (Event ID 3) on the compromised host ws3
- The `Image` field revealed `C:\Program Files\OpenSSH\sshd.exe` handling connections on **port 22** — confirming SSH as the access protocol
- The attacker's IP `35.158.70.36` (same IP that `microsoftoniine.ddns.net` resolved to) appeared as the source — directly linking phishing to initial access
- RDP connections (port 3389) and WinRM (port 5985) were also observed inbound but came later in the attack chain
- `Initiated=false` in Sysmon Event ID 3 confirms the connection was **inbound** (external party connecting in)

---

### Q4: First Successful Login Timestamp

**Question:** Based on log analysis, what was the exact timestamp of the attacker's first success login attempt using the compromised account?

**Answer:** `2025-04-20 11:02`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=3 direction=inbound
Image="C:\\Program Files\\OpenSSH\\sshd.exe"
SourceIp="35.158.70.36"
```

**Analysis:**
- Narrowed inbound SSH connections to the attacker's specific IP (`35.158.70.36`) identified in Q1/Q3
- Three SSH connections from this IP were recorded; sorting by earliest event identified the first login
- The `UtcTime` field in the earliest event shows `2025-04-20 11:02:34.218` — the platform accepted `2025-04-20 11:02` format
- Multiple connections in quick succession from the same IP indicate legitimate SSH session behaviour (not brute force)

---

### Q5: Payload Download Tool

**Question:** An attempt to use a deprecated download method failed. The attacker then switched to a native Windows utility to fetch their payloads. Which tool was successfully used?

**Answer:** `certutil.exe`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=1
CommandLine="*http*"
| dedup CommandLine
| table CommandLine
```

**Analysis:**
- Searched for process creation events (Event ID 1) involving HTTP in the command line to identify download attempts
- Results showed two download attempts for `AnyDesk.exe`:
  - PowerShell `Invoke-WebRequest` — failed (likely blocked by execution policy)
  - `certutil -urlcache -split -f` — succeeded
- `certutil.exe` is a **LOLBAS** (Living Off the Land Binary) — a legitimate Windows certificate utility that can download files, making it trusted by many security tools
- Also confirmed via Event ID 29 results showing `certutil.exe` as the `Image` writing `AnyDesk.exe` to disk

> **🔑 Key Insight:** LOLBAS tools like `certutil`, `bitsadmin`, and `mshta` are frequently used because they bypass application whitelisting and blend with legitimate system activity

---

### Q6: Persistence Registry Value

**Question:** To maintain persistence, the attacker created a registry value with a legitimate-sounding name. What is the name of the registry value used for persistence?

**Answer:** `Windows Update Manager`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=13
(registry_path="*Run*" OR registry_path="*RunOnce*")
```

**Analysis:**
- Sysmon Event ID 13 captures registry value set operations — ideal for hunting persistence via Run keys
- Single event returned showing `reg.exe` creating a value at `HKU\...\CurrentVersion\Run\Windows Update Manager`
- The value data: `rundll32 C:\Users\Administrator\AppData\Local\Temp\WindowsUpdate.dll,Start` — executes the malicious DLL dropped in Q2 on every user login
- Sysmon automatically tagged this with `technique_id=T1547.001` — demonstrating automated ATT&CK mapping in a well-configured SIEM
- Name "Windows Update Manager" is deliberate masquerading — indistinguishable from legitimate entries at a glance

**MITRE ATT&CK:** [T1547.001 - Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

---

### Q7: Defender Disable Command

**Question:** To evade detection, the attacker executed a command to disable endpoint protection. What command was used to weaken real-time monitoring?

**Answer:** `Set-MpPreference -DisableRealtimeMonitoring $true`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=1
Image="*powershell*"
| dedup CommandLine
| table CommandLine
```

**Analysis:**
- Identified a PowerShell command line using `-EncodedCommand` with a Base64 payload
- Decoded using **CyberChef** with "From Base64" → "Remove Null Bytes" operations:
  - Base64: `UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA=`
  - Decoded: `Set-MpPreference -DisableRealtimeMonitoring $true`
- Flags `-ExecutionPolicy Bypass -NoP -W Hidden` used to suppress execution restrictions and hide the window
- Encoding is used to evade simple string-based detections scanning for "DisableRealtimeMonitoring" in plain text

**MITRE ATT&CK:** [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

### Q8: Audit Policy Disable Utility

**Question:** The attacker disabled system auditing entirely. What command-line utility was used to achieve this?

**Answer:** `auditpol`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=1
Image="*cmd*"
CommandLine="*disable*"
| dedup CommandLine
| table CommandLine
```

**Analysis:**
- Searched `cmd.exe` process creations containing "disable" in the command line
- Single result: `cmd.exe /C auditpol /set /category:* /success:disable /failure:disable`
- `auditpol` is the Windows Audit Policy utility — the `/category:*` argument targets ALL audit categories simultaneously
- This completely blind Windows Security event logging for both successful and failed actions
- Executed after establishing persistence — attackers disable auditing before performing noisy operations like credential dumping

**MITRE ATT&CK:** [T1562.002 - Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)

---

### Q9: Cleared Event Log Categories

**Question:** Log records indicate several event categories were erased from the system. What logs did the attacker clear to cover their tracks?

**Answer:** `Application, Security, System`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=1
Image="*cmd*"
CommandLine="*wevtutil*"
| dedup CommandLine
| table CommandLine
```

**Analysis:**
- Three distinct `wevtutil cl` commands found — one per log category:
  - `wevtutil cl Application`
  - `wevtutil cl Security`
  - `wevtutil cl System`
- `wevtutil` (Windows Event Utility) with the `cl` (clear log) argument permanently wipes all events from the specified log
- These three logs are the most forensically valuable — covering application errors, logon events, and OS activity
- The attacker's anti-forensics sequence: Disable Defender → Disable auditing → Clear existing logs
- **Critical detection note:** Sysmon logs to its own channel (`Microsoft-Windows-Sysmon/Operational`) which was NOT cleared — this is why the full attack chain remained visible

---

### Q10: Credential Dumper SHA256 Hash

**Question:** A credential-dumping utility was executed to extract browser-stored credentials. What is the SHA256 hash of the malicious binary used?

**Answer:** `8E7A80FFC582E238F3828383594D9039C99157FA1313ABA58237CDAE3013FE69`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"*BCleaner*"
| table EventCode Image TargetFilename Hashes Computer
```

**Analysis:**
- Activity occurred on **ws2**, not ws3 — indicating lateral movement had already taken place
- `BCleaner.exe` was executed via `cmd.exe` with the `-greed` argument — a browser credential stealer flag
- Multiple Event ID 29 entries existed for `BCleaner.exe` due to chunked file writes — selected the entry with a valid `IMPHASH` (non-zero) indicating the complete, final file
- Parent process chain: `WindowsUpdate.dll` (via `rundll32.exe`) → `cmd.exe` → `BCleaner.exe` — showing the malicious DLL orchestrating further attack stages
- File placed in `C:\Windows\System32\` on ws2 for masquerading purposes

> **🔑 Key Insight:** When multiple hashes exist for the same file, the entry with a non-zero `IMPHASH` represents the complete file — partial writes produce zeroed import hashes

---

### Q11: Credential Dump Output Filename

**Question:** While expanding control over the network, a file containing dumped credentials was created. What is the name of the file used to store the stolen credentials?

**Answer:** `credentials.txt`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=1
Image="*cmd*"
CommandLine="*svchostt*"
| dedup CommandLine
| table CommandLine
```

**Analysis:**
- `svchostt.exe` is **Mimikatz renamed** — the double `t` is the masquerading tell
- Full command: `svchostt.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > %LOCALAPPDATA%\Temp\credentials.txt`
- Standard Mimikatz modules used: `privilege::debug` (elevate to debug rights) and `sekurlsa::logonpasswords` (extract LSASS cached credentials)
- Output redirected to `credentials.txt` — storing plaintext passwords and NTLM hashes for reuse
- Even renamed, Mimikatz's **command arguments** are highly distinctive and should always trigger SIEM alerts

**MITRE ATT&CK:** [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

### Q12: Failed AD Dump Process ID

**Question:** A failed credential dumping attempt triggered security alerts. What is the `ProcessId` of the process that performed this failed action?

**Answer:** `3516`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*ntdsutil*"
| table CommandLine Image ProcessId Computer
```

**Analysis:**
- `ntdsutil` is a legitimate Windows AD management tool abused to extract `NTDS.dit` (the Active Directory credential database)
- Command: `ntdsutil "activate instance ntds" "ifm" "create full C:\temp_l0gs" q q` — IFM (Install From Media) mode creates a full AD database snapshot
- Attempt failed because this was run on **ws2** (a workstation), not the Domain Controller — `ntdsutil` can only dump NTDS.dit when executed on the DC itself
- Two events returned: `cmd.exe` (PID 11076) as the launcher, and `ntdsutil.exe` (PID 3516) as the actual actor — the question asks for the process that **performed** the action

---

### Q13: AnyDesk Remote Access Password

**Question:** To restrict access to the remote session, the attacker configured a password. What password was set for the remote tool?

**Answer:** `Rhys1d@2025!`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=1
CommandLine="*AnyDesk*"
| dedup CommandLine
| table CommandLine
```

**Analysis:**
- AnyDesk's `--set-password` CLI argument used to lock the remote session to attacker-only access
- Results revealed the full AnyDesk deployment chain: download → silent install → set password → retrieve machine ID
- The attacker attempted the `--set-password` command multiple times with varying syntax (different quoting styles, direct vs cmd.exe invocation) — testing what worked
- Password `Rhys1d@2025!` references the ransomware group name "Rhysida" — a common attacker trademark

**MITRE ATT&CK:** [T1219 - Remote Access Software](https://attack.mitre.org/techniques/T1219/)

---

### Q14: Lateral Movement MITRE Sub-technique

**Question:** During lateral movement, the attacker used a service-based technique to execute commands on remote systems. What MITRE sub-technique did they use?

**Answer:** `T1569.002`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=29
TargetFilename="*rdpcliip*"
| table TargetFilename Image Hashes Computer
```

**Analysis:**
- PsExec was renamed to `rdpcliip.exe` (legitimate RDP clipboard process name) — downloaded via `certutil` and saved with this disguised name
- PsExec operates by temporarily installing a **Windows Service** on the remote target to execute commands — mapping directly to T1569.002
- Used with stolen credentials to spread `WindowsUpdate.dll` to other hosts: `rdpcliip.exe \\10.10.11.196 -u oneduca.local\kmiles -p [pass] -s cmd.exe /c "rundll32.exe ...\WindowsUpdate.dll,Start"`
- Targets included `10.10.11.196` and `10.10.11.178` — internal machines on the network

**MITRE ATT&CK:** [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

---

### Q15: C2 Server IP Address

**Question:** To establish ongoing access, a command and control beacon was deployed. What is the IP address of the C2 server the system communicated with?

**Answer:** `3.70.203.137`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
host="WS3" EventCode=3 direction=outbound
| stats count by DestinationIp
| sort -count
```

**Analysis:**
- Used frequency analysis on outbound connections — C2 beacons stand out through volume and regularity
- `3.70.203.137` had **292 connections** — massively exceeding the next highest IP (95 connections to internal address)
- Regular short-interval connections confirm classic **beaconing behaviour** — the implant checking in with the C2 server approximately every minute
- `169.254.169.254` (89 hits) is the AWS EC2 metadata service — expected and not suspicious in cloud environments
- `stats count by ... | sort -count` is one of the most powerful SPL patterns for surfacing anomalous communication

**MITRE ATT&CK:** [T1071 - Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

---

### Q16: Remote Access Tool Name

**Question:** A remote access tool was dropped on the system, allowing full remote control. What is the name of this tool?

**Answer:** `AnyDesk.exe`

**Analysis:**
- Identified across multiple earlier questions (Q5, Q13) through Event ID 29 file drop events and Event ID 1 command line analysis
- Downloaded via `certutil`, installed silently with `--start-with-win` flag for persistence, configured with a password
- AnyDesk is a legitimate remote desktop application — its abuse as a RAT (Remote Access Tool) is a common technique because it's trusted by firewalls and AV solutions

---

### Q17: AnyDesk System ID Argument

**Question:** After establishing the remote access session, the attacker issued a command to retrieve system-specific identifiers. What argument was passed to the tool?

**Answer:** `--get-id`

**Analysis:**
- Visible in Q13 SPL results: `cmd.exe /c "C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --get-id`
- `--get-id` retrieves the unique AnyDesk machine identifier — required by the attacker to connect remotely from their own AnyDesk client
- This is the final step before establishing full remote control: install → configure password → get ID → connect

---

### Q18: Staged Data File Path

**Question:** Sensitive documents were collected and saved in a public directory. What is the full file path of the text file used to store this staged data?

**Answer:** `C:\Users\Public\sensitive_files.txt`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
TargetFilename="*Users\\Public*"
TargetFilename="*.txt"
| table TargetFilename Computer Image
```

**Analysis:**
- Activity occurred on `DC01.oneduca.local` — confirming the attacker had achieved Domain Controller compromise
- PowerShell created `sensitive_files.txt` in `C:\Users\Public\` — a world-writable directory ideal for staging
- The `DataBackup` subdirectory contained actual exfiltrated files: contracts, invoices, NDAs, user databases, audit logs
- `C:\Users\Public\` is a common attacker staging location — accessible to all users, rarely monitored

**MITRE ATT&CK:** [T1074.001 - Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)

---

### Q19: Exfiltration Archive Name

**Question:** The attacker compressed the collected data into a single archive file for extraction. What is the name of the archive file?

**Answer:** `company_data.zip`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
TargetFilename="*Users\\Public*"
TargetFilename="*.zip"
| table TargetFilename Computer Image
```

**Analysis:**
- PowerShell's `Compress-Archive` cmdlet used to create `C:\Users\Public\company_data.zip` on the Domain Controller
- Compression serves dual purpose: reduces transfer size and bundles all staged files into a single exfiltration package
- Full staging chain: enumerate files → `sensitive_files.txt` → copy to `DataBackup\` → compress to `company_data.zip` → exfiltrate

**MITRE ATT&CK:** [T1560.001 - Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

---

### Q20: Ransomware Executable Name

**Question:** A ransomware payload was deployed to cause maximum damage. What is the name of the malicious executable launched during the final stage of the attack?

**Answer:** `Nbd6a7v.exe`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
Image="*Nbd6a7v*"
| stats count by Image Computer
| sort -count
```

**Analysis:**
- Random gibberish naming (`Nbd6a7v.exe`) is a classic ransomware payload convention — contrast with earlier masquerading attempts
- Deployed on ws3 from `%TEMP%`, on ws2 and DC01 from `C:\Windows\System32\`
- Generated thousands of file creation events — mass file modification is the ransomware encryption signature
- At this stage the attacker abandons stealth — maximum impact is the only objective

**MITRE ATT&CK:** [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

---

### Q21: Ransom Note Filename

**Question:** Instead of dropping a typical ransom note, the attacker left behind a uniquely named file. What is the name of the note that was dropped?

**Answer:** `CriticalBreachDetected.pdf`

**Analysis:**
- Instead of a standard `READ_ME.txt` or `DECRYPT_FILES.html`, Rhysida uses a psychologically alarming PDF name
- Thousands of `CriticalBreachDetected.pdf` files were created across all directories on all compromised machines
- The PDF format and alarming name are designed to maximise victim panic and ensure the ransom demand is seen
- Visible throughout the Q18 SPL results — `Nbd6a7v.exe` creating this file across every subdirectory of `C:\Users\Public\`

---

### Q22: Domain Controller Tool Staging Path

**Question:** After compromising the domain controller, the attacker stored tools in a sensitive location. What is the full path of the directory used for staging their tools?

**Answer:** `C:\Windows\System32\`

**SPL:**
```splunk
index="main" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=11
Image="*Nbd6a7v*"
Computer="DC01.oneduca.local"
| table Image TargetFilename Computer
```

**Analysis:**
- Ransomware executed from `C:\Windows\System32\Nbd6a7v.exe` on the Domain Controller
- `System32` is the home of legitimate Windows binaries — placing malware here makes it blend in and often bypasses directory-based exclusions
- This is **MITRE T1036.005** — Masquerading: Match Legitimate Name or Location
- On a Domain Controller, `System32` runs with the highest privilege level in the entire domain — making this the most dangerous possible staging location

---

## 🔑 Key Findings

### Attack Timeline

| Time (UTC) | Event | Details | Q# |
|---|---|---|---|
| ~10:52 | DNS query to phishing domain | Firefox on ws3 resolves `microsoftoniine.ddns.net` | Q1 ✓ |
| 11:02:34 | First successful SSH login | Attacker IP `35.158.70.36` connects to ws3 port 22 | Q4 ✓ |
| 11:05:14 | Malicious DLL dropped via SFTP | `sftp-server.exe` (PID 6936) writes `WindowsUpdate.dll` | Q2 ✓ |
| 12:04:08 | Registry persistence created | `Windows Update Manager` Run key set via `reg.exe` | Q6 ✓ |
| ~12:05 | Defender disabled | Encoded PowerShell executes `Set-MpPreference` | Q7 ✓ |
| ~12:06 | Auditing disabled | `auditpol /set /category:* /success:disable /failure:disable` | Q8 ✓ |
| ~12:07 | Event logs cleared | `wevtutil cl` on Application, Security, System | Q9 ✓ |
| ~12:10 | AnyDesk downloaded & installed | `certutil` downloads after PowerShell fails | Q5 ✓ |
| ~12:11 | AnyDesk configured | Password `Rhys1d@2025!` set; `--get-id` run | Q13/Q17 ✓ |
| ~12:51 | Mimikatz credential dump | `svchostt.exe` dumps LSASS to `credentials.txt` | Q11 ✓ |
| ~12:56 | PsExec lateral movement | `rdpcliip.exe` spreads `WindowsUpdate.dll` to network | Q14 ✓ |
| ~13:52 | Ongoing C2 beaconing | 292 connections to `3.70.203.137` | Q15 ✓ |
| ~13:58 | Browser credential dump on ws2 | `BCleaner.exe -greed` runs on ws2 | Q10 ✓ |
| ~14:25 | RDP access established | Inbound RDP to ws3 from external IP | — |
| ~14:55 | Ransomware deployed on ws3 | `Nbd6a7v.exe` begins mass file encryption | Q20 ✓ |
| DC stage | Data exfiltration | `sensitive_files.txt` → `company_data.zip` on DC01 | Q18/Q19 ✓ |
| Final | Ransom notes dropped | `CriticalBreachDetected.pdf` across all machines | Q21 ✓ |

---

### IOCs (Indicators of Compromise)

| Category | Indicator | Details |
|---|---|---|
| **Domain** | `microsoftoniine.ddns.net` | Phishing domain — typosquatted Microsoft |
| **IP** | `35.158.70.36` | Attacker SSH origin / phishing server |
| **IP** | `3.70.203.137` | C2 beacon server (292 connections) |
| **IP** | `3.123.36.183` | Payload download server |
| **File** | `WindowsUpdate.dll` | Malicious DLL — SFTP dropped, rundll32 executed |
| **File** | `Nbd6a7v.exe` | Rhysida ransomware payload |
| **File** | `BCleaner.exe` | Browser credential stealer |
| **File** | `svchostt.exe` | Renamed Mimikatz |
| **File** | `rdpcliip.exe` | Renamed PsExec |
| **File** | `credentials.txt` | Dumped LSASS credentials |
| **File** | `company_data.zip` | Exfiltration archive |
| **File** | `CriticalBreachDetected.pdf` | Rhysida ransom note |
| **Registry** | `HKCU\...\Run\Windows Update Manager` | Persistence Run key |
| **Hash (SHA256)** | `8E7A80FFC582E238F3828383594D9039C99157FA1313ABA58237CDAE3013FE69` | BCleaner.exe |
| **Account** | `WS3\Administrator` | Compromised admin account |
| **Password** | `Rhys1d@2025!` | AnyDesk remote access password |

---

## 🛡️ Detection & Hunting Guidance

### Event IDs to Monitor

| Event ID | Source | Description |
|---|---|---|
| 1 | Sysmon | Process Creation — captures command lines, parent processes, hashes |
| 3 | Sysmon | Network Connection — inbound/outbound with process attribution |
| 11 | Sysmon | File Created — all file writes with creating process |
| 13 | Sysmon | Registry Value Set — modifications to registry keys |
| 22 | Sysmon | DNS Query — domain resolution with requesting process |
| 29 | Sysmon | File Executable Dropped — PE/DLL files written to disk with hashes |
| 4688 | Windows Security | Process Creation (native, less detail than Sysmon) |
| 4624 | Windows Security | Successful Logon |
| 4625 | Windows Security | Failed Logon |
| 1102 | Windows Security | Audit Log Cleared |
| 7045 | Windows System | New Service Installed (PsExec indicator) |

---

## 📚 Lessons Learned

### Technical Insights

1. **Sysmon is Your Safety Net:** The attacker cleared Application, Security, and System logs but forgot Sysmon logs in its own channel. Always forward Sysmon logs to a SIEM separately — it's the forensic source of truth that attackers often overlook.

2. **LOLBAS Awareness is Critical:** `certutil`, `auditpol`, `wevtutil`, `reg.exe`, and `rundll32` were all used maliciously — these are legitimate Windows binaries. Detection must focus on **context** (what are they doing, where, spawned by what) not just the binary name.

3. **Frequency Analysis Reveals C2:** The `stats count by DestinationIp | sort -count` pattern immediately surfaced the C2 server with 292 connections. Baseline normal connection patterns and alert on statistical outliers.

4. **Masquerading is Pervasive:** Every malicious file was named to appear legitimate — `WindowsUpdate.dll`, `svchostt.exe`, `rdpcliip.exe`, `BCleaner.exe`. File name alone is never sufficient for triage; always verify hash, path, parent process, and behaviour.

5. **Dual PID Awareness in Sysmon:** Every Sysmon event contains two PIDs — the Sysmon logger PID in `<Execution>` and the actual actor PID in `<EventData>`. Hunting for responsible processes requires reading `<Data Name='ProcessId'>`, not `<Execution ProcessID>`.

6. **Privileged Accounts Need Extra Protection:** A single phished administrator account unlocked the entire attack chain. Privileged accounts should require MFA, have login restrictions, and be monitored with zero-trust principles.

---

### MITRE ATT&CK Mapping

| Tactic | Technique | Example from Lab |
|---|---|---|
| Initial Access | T1566.002 - Spearphishing Link | Phishing page `microsoftoniine.ddns.net` |
| Initial Access | T1078 - Valid Accounts | Stolen admin credentials used for SSH |
| Execution | T1059.001 - PowerShell | Encoded PowerShell to disable Defender |
| Execution | T1569.002 - Service Execution | PsExec (`rdpcliip.exe`) lateral movement |
| Persistence | T1547.001 - Registry Run Keys | `Windows Update Manager` Run key |
| Defense Evasion | T1562.001 - Disable Security Tools | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| Defense Evasion | T1562.002 - Disable Event Logging | `auditpol` disabling all audit categories |
| Defense Evasion | T1070.001 - Clear Windows Event Logs | `wevtutil cl` on all three primary logs |
| Defense Evasion | T1036.005 - Masquerading | Renaming Mimikatz, PsExec, malware binaries |
| Defense Evasion | T1218.011 - Rundll32 | DLL execution via `rundll32.exe` |
| Credential Access | T1003.001 - LSASS Memory | Mimikatz (`svchostt.exe`) credential dump |
| Credential Access | T1555.003 - Credentials from Web Browsers | `BCleaner.exe -greed` browser dump |
| Lateral Movement | T1569.002 - Service Execution | PsExec spreading `WindowsUpdate.dll` |
| Command & Control | T1219 - Remote Access Software | AnyDesk with `--set-password` |
| Command & Control | T1071 - Application Layer Protocol | C2 beaconing to `3.70.203.137` |
| Collection | T1074.001 - Local Data Staging | `sensitive_files.txt` and `DataBackup\` on DC |
| Exfiltration | T1560.001 - Archive via Utility | `company_data.zip` via PowerShell |
| Impact | T1486 - Data Encrypted for Impact | Rhysida ransomware (`Nbd6a7v.exe`) |

---

## 🔗 References

- [MITRE ATT&CK - Rhysida Group](https://attack.mitre.org/groups/G1003/)
- [MITRE ATT&CK - T1547.001 Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK - T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK - T1569.002 Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [LOLBAS Project - certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [Microsoft Docs - auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)
- [Microsoft Docs - wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [CyberDefenders - Rhysida Lab](https://cyberdefenders.org/blueteam-ctf-challenges/rhysida/)
- [Featured Writeup by Muhammed Alaa](https://medium.com/@muuhammedalaa/cyberdefenders-rhysida-lab-writeup-bc815bac4e8a)

---

## 📝 Conclusion

This lab provided an end-to-end reconstruction of a Rhysida ransomware intrusion — one of the most complete attack chains available for blue team training. Starting from a single phished credential, the attacker methodically established access, disabled all defensive telemetry, spread across the network, exfiltrated sensitive data, and deployed ransomware across all reachable endpoints including the Domain Controller. Every stage was traceable through Sysmon telemetry, demonstrating that a well-configured Sysmon deployment can survive even deliberate log destruction attempts.

The investigation highlighted how attackers blend malicious activity with legitimate-looking tools and filenames — every piece of malware was disguised as a Windows component. Detection in this environment required looking beyond binary names to examine command line arguments, parent processes, network frequencies, and file paths in combination. The `stats count by` SPL pattern proved particularly powerful for surfacing C2 beaconing, while Event ID 29 was invaluable for payload delivery tracking with hash evidence.

**Key Takeaway:** Organizations must:
- Deploy Sysmon with a comprehensive configuration and forward logs to a SIEM separately from native Windows logs
- Implement MFA on all privileged accounts — a single phished credential enabled this entire compromise
- Establish baselines for outbound connection frequency to detect C2 beaconing anomalies
- Monitor LOLBAS tool usage in context — `certutil`, `auditpol`, `wevtutil`, and `rundll32` with unusual arguments are high-fidelity indicators
- Restrict SSH access on Windows endpoints — OpenSSH on a workstation is rarely legitimate and provides a powerful attacker foothold
- Apply the principle of least privilege — the compromised Administrator account had unrestricted access to all systems

---

**Challenge Completed: 22/22 Questions ✅**

**Skills Demonstrated:**
- Splunk SPL query construction and optimization
- Sysmon event analysis across multiple Event IDs (1, 3, 11, 13, 22, 29)
- Multi-host threat hunting and lateral movement tracing
- Base64 decoding with CyberChef for obfuscated command analysis
- MITRE ATT&CK technique identification and mapping
- C2 beacon detection via frequency analysis
- Full kill chain reconstruction from phishing to ransomware impact
