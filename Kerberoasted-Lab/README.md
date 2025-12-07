# Kerberoasted Lab: Active Directory Kerberoasting Investigation

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Splunk-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

[Kerberoasted Challenge](https://cyberdefenders.org/blueteam-ctf-challenges/kerberoasted/)

---

## 🔍 Project Overview

This repository documents my investigation into the **Kerberoasted Lab** challenge on CyberDefenders, focusing on detecting and analyzing a sophisticated **Kerberoasting attack** against an Active Directory environment.

**Objective:** Analyze Domain Controller security logs and Sysmon telemetry to identify kerberoasting activity, trace lateral movement, and uncover multi-layered persistence mechanisms employed by the attacker.

**MITRE ATT&CK Technique:** [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)

---

## 📋 Scenario

As a diligent cyber threat hunter, your investigation begins with a hypothesis: 'Recent trends suggest an upsurge in Kerberoasting attacks within the industry. Could your organization be a potential target for this attack technique?' 

This hypothesis lays the foundation for your comprehensive investigation, starting with an in-depth analysis of the domain controller logs to detect and mitigate any potential threats to the security landscape.

**Note:** Your Domain Controller is configured to audit Kerberos Service Ticket Operations, which is necessary to investigate kerberoasting attacks. Additionally, Sysmon is installed for enhanced monitoring.

---

## 🎯 Investigation Summary

### Attack Chain Overview

1. **Reconnaissance:** Attacker identified weak RC4-HMAC Kerberos encryption in use
2. **Credential Access:** User `johndoe` performed kerberoasting from compromised workstation (10.0.0.154)
3. **Privilege Escalation:** Successfully cracked `SQLService` account password offline
4. **Lateral Movement:** Authenticated as SQLService via RDP to Domain Controller
5. **Persistence:** Established dual persistence via malicious Windows service and WMI event subscription
6. **Defense Evasion:** Enabled RDP via registry modification for continued remote access

---

## 📊 Questions & Solutions

### Q1: Encryption Type Analysis

**Question:** To mitigate Kerberoasting attacks effectively, we need to strengthen the encryption Kerberos protocol uses. What encryption type is currently in use within the network?

* **Answer:** `RC4-HMAC`
* **SPL:**
    ```
    index="kerberoasted" event.code=4769 "winlog.event_data.TicketEncryptionType"=0x17
    | table _time, winlog.event_data.TicketEncryptionType, winlog.event_data.TargetUserName
    ```
* **Analysis:** 
  - Event ID 4769 logs Kerberos TGS (Ticket Granting Service) requests
  - `TicketEncryptionType` value `0x17` (hexadecimal) = RC4-HMAC
  - RC4-HMAC is legacy encryption vulnerable to offline password cracking
  - Modern environments should enforce AES256 (0x12) or AES128 (0x11)
  - This weak encryption enables the entire kerberoasting attack chain

**Key Insight:** RC4-HMAC allows attackers to request service tickets and crack them offline using tools like Hashcat or John the Ripper without generating additional network traffic.

---

### Q2: Attacker Identification

**Question:** What is the username of the account that sequentially requested Ticket Granting Service (TGS) for two distinct application services within a short timeframe?

* **Answer:** `johndoe`
* **SPL:**
    ```
    index="kerberoasted" event.code=4769
    | rex field=message "Account Name:\s+(?<RequestingAccount>\S+)"
    | search NOT RequestingAccount="DC01$@*" NOT winlog.event_data.TargetUserName="DC01$@*"
    | table _time, RequestingAccount, winlog.event_data.ServiceName
    | sort RequestingAccount, _time
    ```
* **Analysis:**
  - Distinguished between requesting account (attacker) vs. target service account (victim)
  - Filtered out machine account noise (DC01$)
  - User `JohanaMN@CYBERCACTUS.LOCAL` (johndoe) requested tickets for:
    - **SALEPOINT4** service
    - **SQLService** service
  - Sequential requests within seconds indicate automated kerberoasting tool usage (Rubeus/Invoke-Kerberoast)
  - Typical kerberoasting behavior: enumerate all SPNs and request all available tickets

**Detection Pattern:** Multiple TGS requests (Event 4769) for different services from same user account in short timeframe.

---

### Q3: Compromised Service Account

**Question:** We must delve deeper into the logs to pinpoint any compromised service accounts for a comprehensive investigation into potential successful kerberoasting attack attempts. Can you provide the account name of the compromised service account?

* **Answer:** `SQLService`
* **SPL:**
    ```
    index="kerberoasted" event.code=4624 (SALEPOINT OR SQLService)
    | table _time, winlog.event_data.TargetUserName, winlog.event_data.LogonType, winlog.event_data.IpAddress, winlog.event_data.WorkstationName
    ```
* **Analysis:**
  - Johndoe targeted two services: SALEPOINT4 and SQLService
  - Searched for successful logons (Event 4624) using those service accounts
  - **SQLService** showed suspicious authentication activity:
    - LogonType 3 (Network logon) - unusual for service accounts
    - Source: WORKSTATION (not a server) - major red flag
    - Timing: Shortly after kerberoasting activity
  - Service accounts should authenticate from servers, not user workstations
  - This indicates the attacker successfully cracked SQLService's password offline and then used those credentials

**Post-Exploitation Indicator:** Service account logging in from a workstation (not a server) is a critical IOC.

---

### Q4: Initial Foothold

**Question:** To track the attacker's entry point, we need to identify the machine initially compromised by the attacker. What is the machine's IP address?

* **Answer:** `10.0.0.154`
* **SPL:**
    ```
    index="kerberoasted" event.code=4624 johndoe
    | table _time, winlog.event_data.TargetUserName, winlog.event_data.IpAddress, winlog.event_data.WorkstationName
    | sort _time
    ```
* **Analysis:**
  - All johndoe authentication events originated from **10.0.0.154**
  - This IP represents the compromised workstation where johndoe's account was operating
  - The attacker executed kerberoasting tools from this machine
  - This is likely johndoe's legitimate workstation that was compromised via:
    - Phishing
    - Stolen credentials
    - Malware infection
  - Should be isolated and forensically examined for initial access vector

**Attack Pivot Point:** 10.0.0.154 served as the launch point for the entire attack chain.

---

### Q5: Service Installation

**Question:** To understand the attacker's actions following the login with the compromised service account, can you specify the service name installed on the Domain Controller (DC)?

* **Answer:** `iOOEDsXjWeGRAyGl`
* **SPL:**
    ```
    index="kerberoasted" (event.code=7045 OR event.code=4697)
    | table _time, winlog.event_data.ServiceName, winlog.event_data.ImagePath, winlog.event_data.ServiceType
    ```
* **Analysis:**
  - Event ID 7045 (System log) and 4697 (Security log) log service installations
  - Service Name: **iOOEDsXjWeGRAyGl** (random characters - clearly malicious)
  - ImagePath: PowerShell command with encoded payload
  - Timestamp: 2023-10-16 08:17:12 (after SQLService compromise)
  - Purpose: Establish persistence that survives reboots
  - Services run with SYSTEM privileges, providing maximum control

**Red Flags:**
- Random service name (no legitimate naming pattern)
- PowerShell execution in service ImagePath
- Base64 encoded commands (obfuscation)
- Created immediately after lateral movement

---

### Q6: RDP Enablement

**Question:** To grasp the extent of the attacker's intentions, what's the complete registry key path where the attacker modified the value to enable Remote Desktop Protocol (RDP)?

* **Answer:** `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
* **SPL:**
    ```
    index="kerberoasted" event.code=13 "Terminal Server"
    | table _time, winlog.event_data.TargetObject, winlog.event_data.Details
    ```
* **Analysis:**
  - Sysmon Event ID 13 logs registry value set operations
  - Registry path: `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
  - Value changed to: **DWORD (0x00000000)** = RDP **enabled**
  - Timestamp: 2023-10-16 08:19 (after service installation)
  - This is THE critical registry key controlling RDP access
    - Value 0 = RDP enabled
    - Value 1 = RDP disabled

**Purpose:** Enable interactive remote access to the Domain Controller for easier command execution and data exfiltration.

---

### Q7: First RDP Session

**Question:** To create a comprehensive timeline of the attack, what is the UTC timestamp of the first recorded Remote Desktop Protocol (RDP) login event?

* **Answer:** `2023-10-16 07:50`
* **SPL:**
    ```
    index="kerberoasted" event.code=4624 winlog.event_data.LogonType=10
    | table _time, winlog.event_data.TargetUserName, winlog.event_data.IpAddress, winlog.event_data.WorkstationName
    | sort _time
    ```
* **Analysis:**
  - Event ID 4624 with LogonType 10 = RemoteInteractive (RDP/Terminal Services)
  - First RDP login: **2023-10-16 07:50:29** (rounded to 07:50)
  - Account used: **SQLService**
  - Source IP: **10.0.0.154** (attacker's machine)
  - Interesting timeline observation:
    - RDP login at 07:50
    - Registry modification at 08:19
    - RDP was already accessible, attacker modified registry for persistence

**Forensic Note:** SQLService account used for interactive RDP session from workstation IP is a major indicator of compromise.

---

### Q8: WMI Persistence Consumer

**Question:** To unravel the persistence mechanism employed by the attacker, what is the name of the WMI event consumer responsible for maintaining persistence?

* **Answer:** `Updater`
* **SPL:**
    ```
    index="kerberoasted" event.code=20
    | table _time, winlog.event_data.Name, winlog.event_data.Type, winlog.event_data.Destination
    ```
* **Analysis:**
  - Sysmon Event ID 20 logs WMI Event Consumer activity
  - Consumer Name: **"Updater"** (deceptive naming to appear legitimate)
  - Type: CommandLineEventConsumer
  - Destination: Contains encoded PowerShell command (malicious payload)
  - WMI Event Subscriptions provide stealthy persistence:
    - Harder to detect than traditional services
    - Trigger-based execution (event-driven)
    - Built-in Windows functionality (trusted)

**Dual Persistence Strategy:**
1. Windows Service: iOOEDsXjWeGRAyGl
2. WMI Subscription: Updater

Defense-in-depth ensures access even if one method is discovered.

---

### Q9: WMI Filter Target Class

**Question:** Which class does the WMI event subscription filter target in the WMI Event Subscription you've identified?

* **Answer:** `Win32_NTLogEvent`
* **SPL:**
    ```
    index="kerberoasted" event.code=19
    | table _time, winlog.event_data.EventNamespace, winlog.event_data.Query, winlog.event_data.Name
    ```
* **Analysis:**
  - Sysmon Event ID 19 logs WMI Event Filter activity
  - Query: `SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = '4624' and TargetInstance.Message like '%johndoe%'`
  - Target Class: **Win32_NTLogEvent** (Windows Event Log entries)
  - Trigger Condition Breakdown:
    - **Monitors:** Windows Event Logs
    - **Frequency:** Every 60 seconds (`WITHIN 60`)
    - **Event:** Event ID 4624 (successful logon)
    - **Specific Target:** Only when message contains "johndoe"
  - **Translation:** "Every 60 seconds, check if johndoe logged in anywhere in the domain, and if so, execute the 'Updater' consumer payload"

**Sophisticated Persistence:** Event-driven execution triggered by specific domain activity (johndoe logins) provides flexible, targeted backdoor access.

---

## 🔑 Key Findings

### Attack Timeline

| Time (UTC) | Event | Description | Question |
|------------|-------|-------------|----------|
| - | Reconnaissance | Weak RC4-HMAC encryption identified | Q1 ✓ |
| ~07:40 | Initial Attack | Johndoe performs kerberoasting from 10.0.0.154 | Q2, Q4 ✓ |
| ~07:40 | Compromise | SQLService account password cracked offline | Q3 ✓ |
| 07:50 | Lateral Movement | First RDP login as SQLService | Q7 ✓ |
| 08:17 | Persistence #1 | Malicious service "iOOEDsXjWeGRAyGl" installed | Q5 ✓ |
| 08:19 | Remote Access | RDP enabled via registry modification | Q6 ✓ |
| 08:19 | Persistence #2 | WMI subscription "Updater" created | Q8, Q9 ✓ |

### IOCs (Indicators of Compromise)

**Network:**
- Attacker Workstation: `10.0.0.154`
- Target: Domain Controller `DC01.cybercactus.local`
- Domain: `CYBERCACTUS.LOCAL`

**Accounts:**
- Compromised User: `johndoe` / `JohanaMN@CYBERCACTUS.LOCAL`
- Compromised Service: `SQLService`
- Targeted Services: `SALEPOINT4`, `SQLService`

**Host:**
- Malicious Service: `iOOEDsXjWeGRAyGl`
- WMI Consumer: `Updater`
- WMI Filter Class: `Win32_NTLogEvent`
- Registry Modified: `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` = 0

**Behavior:**
- RC4-HMAC Kerberos encryption (0x17)
- Sequential TGS requests for multiple services
- Service account RDP login from workstation
- PowerShell-based service execution
- Event-driven WMI persistence

---

## 🛡️ Detection & Hunting Guidance

### Event IDs to Monitor

| Event ID | Source | Description |
|----------|--------|-------------|
| 4769 | Security | Kerberos Service Ticket (TGS) Request |
| 4768 | Security | Kerberos Ticket Granting Ticket (TGT) Request |
| 4624 | Security | Successful Logon |
| 7045 | System | Service Installed |
| 4697 | Security | Service Installed |
| 13 | Sysmon | Registry Value Set |
| 19 | Sysmon | WMI Event Filter Activity |
| 20 | Sysmon | WMI Event Consumer Activity |
| 21 | Sysmon | WMI Event Consumer-to-Filter Binding |

### SIEM Detection Rules

**Rule 1: Kerberoasting Detection**
