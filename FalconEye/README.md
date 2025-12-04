# FalconEye Lab: Active Directory Threat Hunting

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20Windows%20Event%20Logs-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

**Challenge:** FalconEye (CyberDefenders)  
**Role:** SOC Analyst  
**Objective:** Use **Splunk** to investigate a security breach in an Active Directory network, reconstructing the attacker’s actions from enumeration to privilege escalation and lateral movement.

---

## 🔍 Scenario Summary
**Key attacker phases:**
- **Initial Compromise & Enumeration:** Identification of compromised user + recon tooling.
- **Privilege Escalation:** Abuse of **Unquoted Service Path** to gain elevated execution.
- **Credential Abuse & Evasion:** Tool download + credential dumping (DCSync / PTH).
- **Lateral Movement & Persistence:** WinRM movement + ticket-based access.

---

## Phase 1: Initial Compromise & Enumeration
**Context:** Identify the attacker’s first foothold and the reconnaissance tooling used.

### Q1
**Question:** What is the name of the compromised account?  
**Answer:** `Abdullah-work\HelpDesk`  
**SPL:**
```splunk
index=folks sourcetype="XmlWinEventLog" EventCode=4688
| regex field=_raw "<Data Name='SubjectUserName'>(?<extracted_user>[^<]+)<"
| search extracted_user!="-" AND extracted_user!="*$"
| stats count by extracted_user
```
**Analysis:** Filtering out system accounts (ending with `$`) and null values in Process Creation logs highlights the HelpDesk account executing suspicious commands.

---

### Q2
**Question:** What is the name of the compromised machine?  
**Answer:** `Client02`  
**SPL:**
```splunk
index=folks sourcetype="XmlWinEventLog" SubjectUserName="HelpDesk"
| stats count by Computer
```
**Analysis:** Pivoting on the compromised HelpDesk user shows the malicious activity originating from the `Client02` host.

---

### Q3
**Question:** What tool did the attacker use to enumerate the environment?  
**Answer:** `bloodhound`  
**SPL:**
```splunk
index=folks host=CLIENT02 source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" (EventCode=4103 OR EventCode=4104)
| search ScriptBlockText=*bloodhound*
```
**Analysis:** PowerShell Script Block logging (notably Event ID `4104`) captures execution references to **SharpHound/BloodHound**, commonly used to map AD attack paths.

---

## Phase 2: Privilege Escalation
**Context:** The attacker escalates privileges on the compromised host.

### Q4
**Question:** The attacker used an Unquoted Service Path to escalate privileges. What is the name of the vulnerable service?  
**Answer:** `Automate-Basic-Monitoring.exe`  
**SPL:**
```splunk
index=folks host=CLIENT02 "program.exe"
| table CommandLine
```
**Analysis:** A service launch attempt like `C:\Program Files\Basic Monitoring\Automate-Basic-Monitoring.exe` without quotes can cause Windows to execute `C:\program.exe` first. The intended binary name is visible in command-line context.

---

### Q5
**Question:** What is the SHA256 of the executable that escalates the attacker's privileges?  
**Answer:** `F951F9FE207C2D9E412240BD0AEFF7233AB78712063EB1723DFAAA3B74BAA2EA`  
**SPL:**
```splunk
index=folks host=CLIENT02 "program.exe" EventCode=1
| table Hashes
```
**Analysis:** Sysmon Event ID `1` (Process Creation) records file hashes. The SHA256 value is extracted from the `Hashes` field.

---

## Phase 3: Credential Dumping & Evasion
**Context:** The attacker downloads additional tooling and performs credential abuse to expand access.

### Q6
**Question:** When did the attacker download fun.exe?  
**Answer:** `2023-05-10 05:08`  
**SPL:**
```splunk
index=folks "fun.exe"
| table _time, CommandLine
| sort _time
```
**Analysis:** The download is visible in process execution (e.g., `certutil.exe` usage). The first observed timestamp for the download-related command marks the event time.

---

### Q7
**Question:** What is the command line used to launch the DCSync attack?  
**Answer:** `"C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"`  
**SPL:**
```splunk
index=folks "fun.exe"
| table CommandLine
```
**Analysis:** The command line shows `lsadump::dcsync`, indicating replication-based credential retrieval targeting the Administrator account.

---

### Q8
**Question:** What is the original name of fun.exe?  
**Answer:** `mimikatz.exe`  
**SPL:**
```splunk
index=folks sourcetype="XmlWinEventLog" EventCode=1 Image="*fun.exe"
| table OriginalFileName
```
**Analysis:** Sysmon Event ID `1` preserves PE metadata (e.g., `OriginalFileName`), revealing the tool’s original identity.

---

### Q9
**Question:** The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked?  
**Answer:** `facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379`  
**SPL:**
```splunk
index=folks "fun.exe" "*aes256*"
| table CommandLine
```
**Analysis:** The command-line arguments include `sekurlsa::pth` with an explicit AES256 key used to request Kerberos tickets for the targeted user.

---

## Phase 4: Lateral Movement & Persistence
**Context:** The attacker pivots to additional systems and uses remote execution / ticket-based access.

### Q10
**Question:** What service did the attacker abuse to access the Client03 machine as Administrator?  
**Answer:** `http/Client03`  
**SPL:**
```splunk
index=folks host=CLIENT02 "Client03"
| table CommandLine
```
**Analysis:** The attacker requested a service ticket for `http/Client03`, consistent with WinRM/HTTP SPN usage and S4U-style abuse.

---

### Q11
**Question:** The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name?  
**Answer:** `wsmprovhost.exe`  
**SPL:**
```splunk
index=folks host=CLIENT03 "wsmprovhost.exe"
| table _time, NewProcessName
```
**Analysis:** WinRM remote sessions commonly spawn `wsmprovhost.exe` on the target, confirming remote management-based lateral movement.

---

### Q12
**Question:** The attacker compromises the it-support account. What was the logon type?  
**Answer:** `9`  
**SPL:**
```splunk
index=folks EventCode=4624 TargetUserName="it-support"
| table LogonType
```
**Analysis:** Logon Type `9` (NewCredentials) is commonly associated with `runas /netonly` and credential replay techniques (including PTH-like behavior).

---

### Q13
**Question:** What ticket name did the attacker generate to access the parent DC as Administrator?  
**Answer:** `trust-test2.kirbi`  
**SPL:**
```splunk
index=folks host=CLIENT02 "ticket"
| table CommandLine
```
**Analysis:** The command line shows generation of a forged Inter-Realm Trust Ticket (`.kirbi`) to escalate from the child domain into the parent domain.

---


