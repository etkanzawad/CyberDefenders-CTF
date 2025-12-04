FalconEye Lab: Active Directory Threat Hunting
FalconEye Challenge

🔍 Project Overview
This repository documents my investigation into the "FalconEye" capture-the-flag challenge hosted by CyberDefenders.

Role: SOC Analyst. Objective: Use Splunk to investigate a security breach in an Active Directory network, uncovering the attacker's steps from initial enumeration to privilege escalation and lateral movement.

Scenario:

Network Enumeration: Identification of compromised accounts and tools.

Privilege Escalation: Exploitation of an Unquoted Service Path vulnerability.

Lateral Movement: Execution of DCsync, Pass-the-Hash, and Golden Ticket attacks.

Phase 1: Initial Compromise & Enumeration
Context: Investigating the initial foothold and tools used for reconnaissance.

Q1
Question: What is the name of the compromised account?

Answer: Abdullah-work\HelpDesk

SPL:

Code snippet

index=folks sourcetype="XmlWinEventLog" EventCode=4688
| regex field=_raw "<Data Name='SubjectUserName'>(?<extracted_user>[^<]+)<"
| search extracted_user!="-" AND extracted_user!="*$"
| stats count by extracted_user
Analysis: By filtering out system accounts (ending in $) and null values in the Process Creation logs, the HelpDesk account was identified executing suspicious enumeration commands.

Q2
Question: What is the name of the compromised machine?

Answer: Client02

SPL:

Code snippet

index=folks sourcetype="XmlWinEventLog" SubjectUserName="HelpDesk"
| stats count by Computer
Analysis: Pivoting on the compromised HelpDesk user revealed that all malicious activity originated from the Client02 host.

Q3
Question: What tool did the attacker use to enumerate the environment?

Answer: bloodhound

SPL:

Code snippet

index=folks host=CLIENT02 source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" (EventCode=4103 OR EventCode=4104)
| search ScriptBlockText=*bloodhound*
Analysis: PowerShell Script Block logs (Event ID 4104) captured the execution of the SharpHound ingestor, a component of BloodHound used to map Active Directory attack paths.

Phase 2: Privilege Escalation
Context: The attacker escalates privileges on the compromised host.

Q4
Question: The attacker used an Unquoted Service Path to escalate privileges. What is the name of the vulnerable service?

Answer: Automate-Basic-Monitoring.exe

SPL:

Code snippet

index=folks host=CLIENT02 "program.exe"
| table CommandLine
Analysis: The system attempted to launch a service at C:\Program Files\Basic Monitoring\Automate-Basic-Monitoring.exe. Due to missing quotes, Windows executed the malicious file C:\program.exe instead. The intended binary name was visible in the command line arguments.

Q5
Question: What is the SHA256 of the executable that escalates the attacker's privileges?

Answer: F951F9FE207C2D9E412240BD0AEFF7233AB78712063EB1723DFAAA3B74BAA2EA

SPL:

Code snippet

index=folks host=CLIENT02 "program.exe" EventCode=1
| table Hashes
Analysis: Sysmon Event ID 1 (Process Creation) logs the file hashes. The SHA256 hash was extracted from the Hashes field for the malicious program.exe.

Phase 3: Credential Dumping & Evasion
Context: The attacker downloads tools and dumps credentials to move further.

Q6
Question: When did the attacker download fun.exe?

Answer: 2023-05-10 05:08

SPL:

Code snippet

index=folks "fun.exe"
| table _time, CommandLine
| sort _time
Analysis: The attacker used certutil.exe to download the tool fun.exe. The timestamp of this specific process execution marks the download time.

Q7
Question: What is the command line used to launch the DCSync attack?

Answer: "C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"

SPL:

Code snippet

index=folks "fun.exe"
| table CommandLine
Analysis: The attacker executed fun.exe with the lsadump::dcsync argument to simulate a Domain Controller and request the Administrator's password hash via replication protocols.

Q8
Question: What is the original name of fun.exe?

Answer: mimikatz.exe

SPL:

Code snippet

index=folks sourcetype="XmlWinEventLog" EventCode=1 Image="*fun.exe"
| table OriginalFileName
Analysis: Sysmon Event ID 1 preserves the OriginalFileName metadata from the file's PE header. This revealed that fun.exe was actually the credential dumping tool mimikatz.exe.

Q9
Question: The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked?

Answer: facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379

SPL:

Code snippet

index=folks "fun.exe" "*aes256*"
| table CommandLine
Analysis: The command line arguments showed the sekurlsa::pth module being used with the explicit AES256 key (hash) for user Mohammed to request a Kerberos TGT.

Phase 4: Lateral Movement & Persistence
Context: Moving laterally to other machines and establishing persistence.

Q10
Question: What service did the attacker abuse to access the Client03 machine as Administrator?

Answer: http/Client03

SPL:

Code snippet

index=folks host=CLIENT02 "Client03"
| table CommandLine
Analysis: The attacker performed an S4U (Service for User) attack using Rubeus/Mimikatz. The argument /msdsspn:http/Client03 confirms they requested a service ticket for the HTTP service (WinRM) on Client03.

Q11
Question: The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name?

Answer: wsmprovhost.exe

SPL:

Code snippet

index="folks" host=CLIENT03 "wsmprovhost.exe"
| table _time, NewProcessName
Analysis: Remote access via WinRM spawns the wsmprovhost.exe (Windows Remote Management Provider Host) process on the target machine, confirming successful lateral movement.

Q12
Question: The attacker compromises the it-support account. What was the logon type?

Answer: 9

SPL:

Code snippet

index=folks EventCode=4624 TargetUserName="it-support"
| table LogonType
Analysis: Logon Type 9 (NewCredentials) is characteristic of "RunAs /netonly" or Pass-The-Hash attacks, allowing local execution while using compromised credentials for network authentication.

Q13
Question: What ticket name did the attacker generate to access the parent DC as Administrator?

Answer: trust-test2.kirbi

SPL:

Code snippet

index=folks host=CLIENT02 "ticket"
| table CommandLine
Analysis: The command line revealed the attacker generated a forged Inter-Realm Trust Ticket named trust-test2.kirbi to escalate privileges from the child domain to the parent domain.
