# PacketDetective Lab: Network Forensics & SMB Attack Analysis

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Wireshark-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

[PacketDetective Challenge](https://cyberdefenders.org/blueteam-ctf-challenges/packetdetective/)

---

## 🔍 Project Overview

PacketDetective is a network forensics challenge focused on analyzing malicious SMB traffic across three PCAP files to reconstruct an attacker's lateral movement and persistence tactics. The challenge involves identifying compromised credentials, accessed files, defense evasion techniques, and remote execution tools used during the attack. Key analysis tasks include dissecting SMB authentication flows, named pipe communications via DCE/RPC, and identifying attacker-created backdoor accounts. This lab directly maps to real-world SOC investigation workflows for detecting lateral movement and insider threat scenarios.

**MITRE ATT&CK:** [TA0008 - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)

---

## 📋 Scenario

In September 2020, your SOC detected suspicious activity from a user device, flagged by unusual SMB protocol usage. Initial analysis indicates a possible compromise of a privileged account and remote access tool usage by an attacker. Your task is to examine network traffic in the provided PCAP files to identify key indicators of compromise (IOCs) and gain insights into the attacker's methods, persistence tactics, and goals. Construct a timeline to better understand the progression of the attack.

---

## 🎯 Investigation Summary

### Attack Chain Overview

1. **Initial Access via SMB:** Attacker authenticates to target using the built-in Administrator account over SMB, gaining privileged access to the system.
2. **File Access:** Attacker opens the Windows Event Log file (`\eventlog`) via SMB to interact with logging infrastructure.
3. **Defense Evasion:** Attacker issues a `ClearEventLogW` request to wipe Windows Event Logs, destroying forensic evidence of their activity.
4. **Lateral Movement via Named Pipes:** Attacker uses DCE/RPC over the `atsvc` named pipe (Task Scheduler service) to move laterally across the network.
5. **Persistence via Backdoor Account:** Attacker authenticates using a newly created backdoor account (`3B\backdoor`) to maintain covert access.
6. **Remote Execution:** Attacker deploys `PSEXESVC.exe` (PsExec service binary) to execute processes remotely on the compromised system.

---

## 📊 Questions & Solutions

### Q1: SMB Protocol Byte Usage

**Question:** The attacker's activity showed extensive SMB protocol usage, indicating a potential pattern of significant data transfer or file access. What is the total number of bytes of the SMB protocol?

* **Answer:** `4406`
* **Analysis:**
  - Navigated to **Statistics → Protocol Hierarchy** in Wireshark to view a full breakdown of all protocols and their byte usage across the capture
  - SMB accounted for **70.4% of all traffic** — 4406 bytes out of 6262 total — immediately flagging it as the dominant and suspicious protocol
  - Protocol Hierarchy Statistics is one of the most valuable first-look tools in Wireshark, providing an instant fingerprint of network behavior without any filtering

**Key Insight:** DCE/RPC was also visible nested under SMB, foreshadowing the named pipe activity discovered in Traffic-2.

---

### Q2: SMB Authentication Username

**Question:** Authentication through SMB was a critical step in gaining access to the targeted system. Which username was utilized for authentication via SMB?

* **Answer:** `Administrator`
* **Wireshark Filter:**
  ```
  smb
  ```
* **Analysis:**
  - Applied `smb` display filter, then located the `NTLMSSP_AUTH` packet in the Info column
  - Username was visible directly in the Info column as `User: \Administrator`
  - The attacker authenticated using the built-in Windows Administrator account, confirming a privileged account compromise
  - Use of the built-in Administrator account suggests either credential theft (e.g., pass-the-hash) or brute force against a weak password

**Technical Detail:** The NTLMSSP handshake follows a 3-step process: `NTLMSSP_NEGOTIATE` → `NTLMSSP_CHALLENGE` → `NTLMSSP_AUTH`. The AUTH packet contains the actual credentials.

**Red Flag:** Built-in Administrator account usage for remote SMB authentication is almost always suspicious and should trigger a SOC alert.

---

### Q3: File Accessed via SMB

**Question:** During the attack, the adversary accessed certain files. What is the name of the file that was opened by the attacker?

* **Answer:** `eventlog`
* **Analysis:**
  - With the `smb` filter active, located a packet with `NT Create AndX Request` in the Info column — the SMB command used to open or create a file
  - The Path field showed `\eventlog`
  - The attacker directly accessed the Windows Event Log file, revealing intent to read or manipulate system logs

**Technical Detail:** The attacker first connected to `\\172.16.66.36\IPC$` (the interprocess communication share used for named pipes and remote admin) before creating the eventlog file handle. IPC$ share access is a common precursor to many SMB-based attack techniques.

---

### Q4: Event Log Clearing Timestamp

**Question:** Clearing event logs is a common tactic to hide malicious actions. What is the timestamp of the attempt to clear the event log? (24-hour UTC format)

* **Answer:** `2020-09-23 16:50`
* **Analysis:**
  - Located the `ClearEventLogW` request packet in the SMB-filtered view (visible in the EVENTLOG protocol rows)
  - Expanded Frame details to read the Arrival Time field in UTC
  - The attacker cleared event logs approximately 17 seconds after initially opening the eventlog file

**Detection Note:** Even when event logs are cleared on the host, network captures preserve the API call — demonstrating why network-based detection is a critical complement to host-based logging.

**Technical Detail:** `ClearEventLogW` is a Windows API function exposed via the EVENTLOG RPC interface over SMB. It wipes all records from the specified event log.

---

### Q5: Named Pipe Service Name

**Question:** The attacker used named pipes for communication. What is the name of the service that communicated using this named pipe?

* **Answer:** `atsvc`
* **Wireshark Filter:**
  ```
  dcerpc
  ```
* **Analysis:**
  - Opened `Traffic-2.pcapng` and applied the `dcerpc` display filter
  - Located a `RemoteCreateInstance` request packet, then drilled into packet details
  - Expanded `IActProperties → OxidBindingsPtr → OxidBindings → Bindings` to find `StringBinding` entries
  - `StringBinding[1]` revealed `\\PIPE\\atsvc` — the named pipe for the Windows Task Scheduler service

**MITRE Mapping:** [T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

**Technical Detail:** Named pipes over SMB with DCE/RPC allow attackers to invoke Windows service APIs remotely. The `ISystemActivator` interface is used to instantiate COM objects remotely. The Task Scheduler (`atsvc`) is abused to create scheduled tasks remotely, enabling persistent code execution without an interactive session.

---

### Q6: Communication Duration

**Question:** What was the duration of communication between the identified addresses 172.16.66.1 and 172.16.66.36?

* **Answer:** `11.7247`
* **Analysis:**
  - Navigated to **Statistics → Conversations** in Wireshark
  - Located the row for the conversation between `172.16.66.1` and `172.16.66.36` and read the Duration column
  - The attacker maintained a ~11.7 second communication window — sufficient time to create scheduled tasks, transfer files, and establish persistence

**Technical Detail:** The Conversations view aggregates all packets between two endpoints and calculates total duration, bytes transferred, and packet counts.

---

### Q7: Backdoor Account Username

**Question:** The attacker used a non-standard username to set up requests, indicating an attempt to maintain covert access. Which username was used?

* **Answer:** `backdoor`
* **Wireshark Filter:**
  ```
  dcerpc
  ```
* **Analysis:**
  - Opened `Traffic-3.pcapng` and applied the `dcerpc` filter
  - Located the `NTLMSSP_AUTH` packet which showed `User: 3B\backdoor` directly in the Info column
  - The attacker created and used a local account named `backdoor` on host `3B` to maintain persistent access independently of the original Administrator credentials
  - The hostname prefix `3B\` indicates a local machine account (not domain), making it harder to detect via domain-level monitoring

**MITRE Mapping:** [T1078.003 - Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/)

**Red Flag:** Account names like `backdoor`, `support`, or `svc_admin` are common attacker naming conventions and should be hunted for in Active Directory and local SAM databases.

---

### Q8: Remote Execution Executable

**Question:** The attacker leveraged a specific executable file to execute processes remotely. What is the name of that executable file?

* **Answer:** `PSEXESVC.exe`
* **Analysis:**
  - In `Traffic-3.pcapng`, navigated to **File → Export Objects → SMB** to list all files transferred over SMB
  - The exported object list revealed `PSEXESVC.exe` being written to the `ADMIN$` share
  - The attacker deployed `PSEXESVC.exe` — the PsExec service binary from Sysinternals — for remote process execution

**MITRE Mapping:** [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

**Technical Detail:** PsExec works by copying `PSEXESVC.exe` to the target's `ADMIN$` share, installing it as a service via SCM (Service Control Manager), and using named pipes for I/O redirection. It is a legitimate signed Microsoft binary, making it invisible to signature-based AV.

---

## 🔑 Key Findings

### Attack Timeline

| Time (UTC) | Event | Details | Q# |
|------------|-------|---------|-----|
| 2020-09-23 ~16:50 | SMB Authentication | Attacker authenticates as `Administrator` via NTLMSSP | Q2 ✓ |
| 2020-09-23 ~16:50 | File Access | `\eventlog` opened via NT Create AndX Request | Q3 ✓ |
| 2020-09-23 16:50 | Defense Evasion | `ClearEventLogW` request issued to wipe logs | Q4 ✓ |
| 2020-09-23 ~16:51 | Lateral Movement | DCE/RPC over `atsvc` named pipe for Task Scheduler access | Q5 ✓ |
| 2020-09-23 ~16:51 | Persistence | `backdoor` account (`3B\backdoor`) used for authentication | Q7 ✓ |
| 2020-09-23 ~16:51 | Remote Execution | `PSEXESVC.exe` deployed via `ADMIN$` share | Q8 ✓ |

### IOCs (Indicators of Compromise)

**Network:**
- Attacker Source IP: `172.16.66.1`
- Target/Victim IP: `172.16.66.36`
- Secondary Target IP: `172.16.66.37`
- `\\172.16.66.36\IPC$` — IPC$ share accessed for named pipes
- `\\172.16.66.36\ADMIN$` — Admin share used to drop PsExec binary

**Accounts:**
- `Administrator` — Compromised privileged account used for initial SMB auth
- `3B\backdoor` — Attacker-created local backdoor account

**Host:**
- `PSEXESVC.exe` — PsExec service binary dropped on target
- `\eventlog` — Windows Event Log accessed and cleared
- `\PIPE\atsvc` — Named pipe used for Task Scheduler RPC

**Behavior:**
- NTLMSSP Auth → eventlog access → ClearEventLogW (classic log-clearing pattern)
- ADMIN$ share write + PSEXESVC.exe deployment (PsExec lateral movement pattern)

---

## 🛡️ Detection & Hunting Guidance

### Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Successful logon — monitor for Type 3 (Network) with Administrator account |
| 4625 | Security | Failed logon — detect brute force attempts |
| 4648 | Security | Logon using explicit credentials — lateral movement indicator |
| 4697 | Security | Service installed on system — detects PSEXESVC.exe installation |
| 7045 | System | New service installed — PsExec creates a service on target |
| 1102 | Security | Audit log cleared — direct alert for ClearEventLogW |
| 4720 | Security | User account created — detects backdoor account creation |
| 5145 | Security | Network share access — monitor IPC$ and ADMIN$ share access |

### Wireshark Filters for Hunting

```wireshark
# Filter SMB traffic only
smb

# Filter DCE/RPC (named pipes)
dcerpc

# Filter NTLMSSP authentication packets
ntlmssp

# Find file creation requests (NT Create AndX)
smb.cmd == 0xa2

# Find event log clearing
eventlog
```

---

## 📚 Lessons Learned

### Technical Insights

1. **Protocol Hierarchy as First Triage Step:** Always open Statistics → Protocol Hierarchy first when examining an unknown PCAP. An anomalously high percentage of SMB, DNS, or ICMP traffic immediately signals where to focus investigation.

2. **NTLMSSP Reveals Usernames in Plaintext:** Even though NTLM hashes are not transmitted in plaintext, the username in NTLMSSP_AUTH packets is always visible in network captures. This makes network forensics a reliable method for identifying accounts used in lateral movement.

3. **Network Logs Survive Host-Based Evasion:** The attacker cleared Windows Event Logs to destroy host-based forensic evidence — but the API call itself was captured in the PCAP. Network monitoring cannot be erased by the attacker, making it a critical detection layer.

4. **Named Pipes Are a Lateral Movement Telltale:** DCE/RPC traffic over named pipes (especially `atsvc`, `svcctl`, `samr`) is a strong lateral movement indicator. Unusual source IPs or off-hours timing should trigger investigation.

5. **LOLBins (Living-off-the-Land Binaries):** PsExec (`PSEXESVC.exe`) is a legitimate, signed Microsoft Sysinternals tool — making it invisible to signature-based AV. Detection must rely on behavioral indicators: ADMIN$ write access + service creation + named pipe I/O.

6. **SMB Object Export for File Recovery:** Wireshark's File → Export Objects → SMB can recover files transferred over SMB — including malware, scripts, or tools dropped by attackers.

### MITRE ATT&CK Mapping

| Tactic | Technique | Example from Lab |
|--------|-----------|-----------------|
| Initial Access | T1078 - Valid Accounts | Administrator account used for SMB authentication |
| Lateral Movement | T1021.002 - SMB/Windows Admin Shares | Attacker accessed IPC$ and ADMIN$ shares |
| Defense Evasion | T1070.001 - Clear Windows Event Logs | ClearEventLogW API call issued at 2020-09-23 16:50 |
| Persistence | T1053.005 - Scheduled Task | atsvc named pipe used for Task Scheduler RPC |
| Persistence | T1078.003 - Local Accounts | 3B\backdoor local account created for persistent access |
| Execution | T1569.002 - Service Execution | PSEXESVC.exe deployed via ADMIN$ for remote execution |

---

## 🔗 References

- [MITRE ATT&CK - Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK - T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK - T1070.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK - T1569.002 Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [Microsoft Docs - NTLM Authentication](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm)
- [Microsoft Docs - Named Pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- [Sysinternals PsExec Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
- [CyberDefenders - PacketDetective Lab](https://cyberdefenders.org/blueteam-ctf-challenges/packetdetective/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)

---

## 📝 Conclusion

The PacketDetective lab presented a realistic multi-stage attack scenario spanning three PCAP files, requiring the analyst to reconstruct an attacker's full kill chain using only network traffic evidence. Starting with a privileged SMB authentication using the built-in Administrator account, the attacker methodically accessed event logs, wiped forensic evidence, moved laterally via DCE/RPC named pipes, established a backdoor account, and ultimately deployed PsExec for remote execution.

This investigation highlights a critical defensive principle: **host-based evasion techniques like log clearing do not affect network-layer forensics.** The `ClearEventLogW` API call, NTLMSSP authentication credentials, and PsExec binary transfer were all captured in full despite the attacker's evasion efforts.

The attack also demonstrated the dual-use risk of legitimate administrative tools. PsExec, Task Scheduler, and SMB Admin Shares are all standard Windows administration features — yet they form the backbone of this attacker's toolkit. Effective detection requires behavioural analytics, network monitoring, and anomaly detection rather than simple signature matching.

**Key Takeaway — Organizations must:**
- Enable and centralize network traffic logging (NetFlow, PCAP capture) as a complement to host-based SIEM
- Alert on Event ID 1102 (audit log cleared) and Event ID 7045 (new service installed) in real time
- Restrict and monitor access to IPC$ and ADMIN$ shares, especially from non-admin workstations
- Implement privileged account monitoring — alert on Administrator account usage for remote SMB authentication
- Hunt for LOLBin usage: `PSEXESVC.exe`, `wmic.exe`, `schtasks.exe` spawned remotely
- Audit local accounts on all endpoints regularly to detect attacker-created persistence accounts

**Challenge Completed:** 8/8 Questions ✅

**Skills Demonstrated:**
- Wireshark PCAP analysis and display filtering
- SMB protocol forensics and NTLMSSP authentication analysis
- DCE/RPC named pipe identification and service enumeration
- Attack timeline reconstruction from network evidence
- MITRE ATT&CK technique mapping
- IOC extraction and documentation
- Network-based defense evasion detection
