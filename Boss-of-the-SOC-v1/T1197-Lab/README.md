# T1197 Lab: BITS Job Abuse Investigation

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Splunk-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

[T1197 Lab Challenge](https://cyberdefenders.org/blueteam-ctf-challenges/t1197/)

---

## 🔍 Project Overview

This repository documents my investigation into the **T1197 Lab** challenge on CyberDefenders, focusing on detecting and analyzing the abuse of **Background Intelligent Transfer Service (BITS)** jobs.

**Objective:** Analyze SIEM logs from a compromised Windows endpoint to identify how an adversary exploited BITS jobs to persistently execute code and download malicious payloads.

**MITRE ATT&CK Technique:** [T1197 - BITS Jobs](https://attack.mitre.org/techniques/T1197/)

---

## 📋 Scenario

Adversaries can exploit BITS (Background Intelligent Transfer Service) jobs to persistently execute code and carry out various background tasks. BITS is a COM-exposed, low-bandwidth file transfer mechanism used by applications such as updaters and messengers, allowing them to operate in the background without interfering with other networked applications.

In this incident, an employee received multiple alerts from Windows Defender indicating the presence of malicious files on their PC. As the SOC analyst, your goal is to use SIEM to analyze the event logs from the suspicious machine and determine the nature of the events.

---

## 🎯 Investigation Summary

### Attack Chain Overview

1. **Initial Access:** Attacker gained access to victim machine (`MSEDGEWIN10`)
2. **Execution:** Used PowerShell to launch `bitsadmin.exe` for file downloads
3. **Persistence:** Created scheduled task named `eviltask` to maintain access
4. **Defense Evasion:** Leveraged LOLBAS (`bitsadmin.exe`) to blend in with legitimate traffic
5. **Command & Control:** Downloaded Metasploit backdoors from `192.168.190.136`

---

## 📊 Questions & Solutions

### Q1: Framework Identification

**Question:** What is the framework used to create the backdoors?

* **Answer:** `Metasploit`
* **SPL:**
    ```
    index="mitre-t1197" (event.code=1116 OR event.code=1117)
    ```
* **Analysis:** 
  - Windows Defender Event IDs 1116/1117 contain malware detection logs
  - Threat name showed: `Trojan:Win32/Meterpreter.O!MTB`
  - **Meterpreter** is the signature payload of the Metasploit Framework
  - Metasploit was used to generate the backdoor files (like `ignite.png`)

---

### Q2: Persistence Mechanism

**Question:** What is the name of the scheduled task that the attacker tried to create?

* **Answer:** `eviltask`
* **SPL:**
    ```
    index="mitre-t1197" event.code=4698
    | table _time, winlog.event_data.TaskName, winlog.event_data.TaskContent
    ```
* **Analysis:**
  - Event ID 4698 logs scheduled task creation
  - Task Name: `\eviltask`
  - Command: `C:\shell.cmd`
  - Trigger: Every 1 minute (`<Interval>PT1M</Interval>`)
  - This provides persistence even if initial access is lost

---

### Q3: LOLBAS Identification

**Question:** What is the LOLBAS used by the malicious actor to move the backdoors to the targeted machine?

* **Answer:** `bitsadmin.exe`
* **SPL:**
    ```
    index="mitre-t1197" event.code=4688
    | top winlog.event_data.NewProcessName
    ```
* **Analysis:**
  - LOLBAS = Living Off The Land Binary and Script
  - `bitsadmin.exe` appeared 34 times in process creation logs
  - This legitimate Windows binary manages BITS file transfers
  - Attackers abuse it because it's trusted and built-in (T1197 technique)
  - Allows download/upload without triggering immediate suspicion

---

### Q4: Initial Execution Timeline

**Question:** When was the first attempt made by the attacker to execute the LOLBAS?

* **Answer:** `2023-07-31 17:39`
* **SPL:**
    ```
    index="mitre-t1197" event.code=4688 winlog.event_data.NewProcessName="C:\\Windows\\System32\\bitsadmin.exe"
    | sort 0 _time
    | table _time
    | head 1
    ```
* **Analysis:**
  - Sorted process creation events chronologically
  - First `bitsadmin.exe` execution: `2023-07-31 17:39:45.935`
  - This marks the beginning of the file transfer phase

---

### Q5: Attacker Infrastructure

**Question:** What is the IP address of the attacker?

* **Answer:** `192.168.190.136`
* **SPL:**
    ```
    index="mitre-t1197" sourcetype="*bits*" "transfer" "http"
    | table _time, message
    ```
* **Analysis:**
  - Process creation logs (Event ID 4688) did not capture command line arguments
  - BITS operational logs (Microsoft-Windows-Bits-Client/Operational) contained transfer details
  - Multiple BITS transfer jobs showed downloads from `http://192.168.190.136/`
  - This IP hosted the malicious Metasploit payloads
  - Files downloaded included backdoors later detected by Windows Defender

---

### Q6: Final Download Timestamp

**Question:** When was the most recent file downloaded by the attacker to the targeted machine?

* **Answer:** `2023-07-31 18:16`
* **SPL:**
    ```
    index="mitre-t1197" "BITS" "transfer" "http"
    | sort 0 -_time
    | table _time, message
    | head 1
    ```
* **Analysis:**
  - Sorted BITS transfer events in descending order (newest first)
  - Latest file download completion: `2023-07-31 18:16`
  - This represents the final payload transferred before the attack transitioned to persistence/execution phases

---

## 🔑 Key Findings

### Attack Timeline

| Time | Event | Description |
|------|-------|-------------|
| 2023-07-31 17:39 | Initial Execution | First `bitsadmin.exe` launched via PowerShell |
| 2023-07-31 17:39 - 18:16 | File Transfers | Multiple BITS jobs download backdoors from `192.168.190.136` |
| 2023-07-31 18:16 | Final Download | Last malicious file transferred |
| 2023-07-31 18:23 | Persistence | Scheduled task `eviltask` created to execute `C:\shell.cmd` |
| Multiple timestamps | Detection | Windows Defender flagged Meterpreter payloads |

### IOCs (Indicators of Compromise)

**Network:**
- Attacker IP: `192.168.190.136`
- Victim IP: `192.168.19.129`
- Protocol: HTTP over BITS

**Host:**
- Malicious files: `ignite.png`, `shell.cmd`
- Scheduled Task: `\eviltask`
- Parent Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Child Process: `C:\Windows\System32\bitsadmin.exe` (34 executions)

**Malware:**
- Framework: Metasploit
- Payload: Meterpreter
- Detection: `Trojan:Win32/Meterpreter.O!MTB`

---

## 🛡️ Detection & Hunting Guidance

### Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 4688 | Security | Process Creation (detect `bitsadmin.exe`) |
| 4698 | Security | Scheduled Task Created |
| 1116/1117 | Windows Defender | Malware Detection/Action |
| 3 | BITS-Client/Operational | BITS Job Created |
| 59/60 | BITS-Client/Operational | BITS Transfer Started/Completed |

### SIEM Detection Rules

**Rule 1: Suspicious BITSAdmin Usage**
index=* EventCode=4688 NewProcessName="*bitsadmin.exe" ParentProcessName="*powershell.exe"
| stats count by Computer, User
| where count > 5

**Rule 2: BITS Job to Suspicious IP**
index=* sourcetype="bits" "transfer"
| rex field=message "http://(?<remote_ip>\d+.\d+.\d+.\d+)"
| where NOT (match(remote_ip, "^10.") OR match(remote_ip, "^192.168.") OR match(remote_ip, "^172.(1[6-9]|2[0-9]|3​)."))


**Rule 3: Scheduled Task + BITSAdmin Correlation**
index=* (EventCode=4698 OR (EventCode=4688 NewProcessName="*bitsadmin.exe"))
| transaction maxspan=1h Computer
| where mvcount(EventCode) > 1


---

## 📚 Lessons Learned

### Technical Insights

1. **Command Line Logging Gaps:** Process creation logs (Event ID 4688) showed blank command lines. Ensure "Command Line Process Auditing" is enabled via GPO.

2. **BITS Operational Logs are Critical:** The most valuable forensic data was in `Microsoft-Windows-Bits-Client/Operational`, not Security logs.

3. **LOLBAS Detection Requires Context:** `bitsadmin.exe` is legitimate, but suspicious when:
   - Spawned by PowerShell/cmd.exe
   - High execution frequency
   - Transfers to/from external IPs

4. **Persistence Hunts:** Always correlate suspicious file downloads with scheduled task creation (Event ID 4698/4699).

### MITRE ATT&CK Mapping

| Tactic | Technique | Example from Lab |
|--------|-----------|------------------|
| Execution | T1059.001 (PowerShell) | PowerShell spawned bitsadmin |
| Persistence | T1053.005 (Scheduled Task) | `eviltask` created |
| Defense Evasion | T1197 (BITS Jobs) | Used bitsadmin for stealth |
| Command & Control | T1071.001 (Web Protocols) | HTTP downloads via BITS |

---

## 🔗 References

- [MITRE ATT&CK T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197/)
- [Microsoft Docs: BITSAdmin Tool](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin)
- [LOLBAS Project: BITSAdmin](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)
- [CyberDefenders Platform](https://cyberdefenders.org/)

---

## 📝 Conclusion

This investigation successfully reconstructed an attack leveraging BITS job abuse (T1197) to download Metasploit backdoors and establish persistence via scheduled tasks. The attacker demonstrated knowledge of LOLBAS techniques to evade detection, but left clear forensic artifacts in Windows event logs.

**Key Takeaway:** Organizations must monitor BITS operational logs and correlate process execution, network connections, and scheduled task creation to detect this increasingly common attack vector.


