FalconEye Lab: Active Directory Threat Hunting
🔍 Project Overview
Platform: CyberDefenders Challenge: FalconEye Role: SOC Analyst Objective: Investigate a security breach in an Active Directory network using Splunk. The investigation covers network enumeration, privilege escalation via Unquoted Service Paths, DCSync attacks, evasion techniques, and lateral movement using Pass-The-Hash.

Phase 1: Initial Compromise & Enumeration
Q1
Question: What is the name of the compromised account? Answer: Abdullah-work\HelpDesk SPL:

Code snippet

index=folks sourcetype="XmlWinEventLog" EventCode=4688
| regex field=_raw "<Data Name='SubjectUserName'>(?<extracted_user>[^<]+)<"
| search extracted_user!="-" AND extracted_user!="*$"
| stats count by extracted_user
Analysis: Filtering out system accounts (ending in $) and null values revealed the HelpDesk account executing suspicious commands, indicating it was the initial point of compromise.

Q2
Question: What is the name of the compromised machine? Answer: Client02 SPL:

Code snippet

index=folks sourcetype="XmlWinEventLog" SubjectUserName="HelpDesk"
| stats count by Computer
Analysis: By pivoting on the compromised HelpDesk user, we identified Client02 as the host where the malicious activity originated.

Q3
Question: What tool did the attacker use to enumerate the environment? Answer: bloodhound SPL:

Code snippet

index="folks" host=CLIENT02 source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" (EventCode=4103 OR EventCode=4104)
| search ScriptBlockText=*bloodhound*
Analysis: PowerShell Script Block logs (Event ID 4104) captured the execution of the SharpHound ingestor, a component of BloodHound used to map Active Directory relationships and attack paths.

Phase 2: Privilege Escalation
Q4
Question: The attacker used an Unquoted Service Path to escalate privileges. What is the name of the vulnerable service? Answer: Automate-Basic-Monitoring.exe SPL:

Code snippet

index=folks host=CLIENT02 "program.exe"
| table CommandLine
Analysis: The attacker exploited an Unquoted Service Path vulnerability. The system attempted to run C:\Program Files\Basic Monitoring\Automate-Basic-Monitoring.exe, but because of the unquoted spaces, it executed the malicious file C:\program.exe instead. The intended binary name appears in the command line arguments.

Q5
Question: What is the SHA256 of the executable that escalates the attacker's privileges? Answer: F951F9FE207C2D9E412240BD0AEFF7233AB78712063EB1723DFAAA3B74BAA2EA SPL:

Code snippet

index=folks host=CLIENT02 "program.exe" EventCode=1
| table Hashes
Analysis: Sysmon Event ID 1 (Process Creation) logs the file hashes of executed processes. We located the SHA256 hash in the Hashes field for the malicious program.exe.

Phase 3: Weaponization & Credential Dumping
Q6
Question: When did the attacker download fun.exe? Answer: 2023-05-10 05:08 SPL:

Code snippet

index=folks "fun.exe"
| table _time, CommandLine, Image
| sort _time
Analysis: The attacker used certutil to download the tool fun.exe. The timestamp of this process creation event marks the download time.

Q7
Question: What is the command line used to launch the DCSync attack? Answer: "C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator" SPL:

Code snippet

index=folks "fun.exe"
| table CommandLine
Analysis: The attacker executed fun.exe with the lsadump::dcsync argument. This Mimikatz command simulates a Domain Controller to request password hashes (specifically the Administrator's) via the replication protocol.

Q8
Question: What is the original name of fun.exe? Answer: mimikatz.exe SPL:

Code snippet

index=folks sourcetype="XmlWinEventLog" EventCode=1 Image="*fun.exe"
| table OriginalFileName
Analysis: Although the file was renamed to fun.exe, Sysmon Event ID 1 retains the OriginalFileName metadata from the PE header, identifying the tool as mimikatz.exe.

Phase 4: Lateral Movement & Persistence
Q9
Question: The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked? Answer: facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379 SPL:

Code snippet

index=folks "fun.exe" "*aes256*"
| table CommandLine
Analysis: The command line arguments reveal the attacker used the sekurlsa::pth module (Pass-the-Hash) and explicitly provided the AES256 key (hash) for the user Mohammed to request a Kerberos TGT.

Q10
Question: What service did the attacker abuse to access the Client03 machine as Administrator? Answer: http/Client03 SPL:

Code snippet

index=folks host=CLIENT02 "Client03"
| table CommandLine
Analysis: The attacker used an S4U (Service for User) attack. The argument /msdsspn:http/Client03 indicates they requested a service ticket specifically for the HTTP service (WinRM) on Client03.

Q11
Question: The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name? Answer: wsmprovhost.exe SPL:

Code snippet

index="folks" host=CLIENT03 "wsmprovhost.exe"
| table _time, NewProcessName
Analysis: Accessing a machine via WinRM (Windows Remote Management) spawns the wsmprovhost.exe (Windows Remote Management Provider Host) process on the target machine. This confirms successful lateral movement.

Q12
Question: The attacker compromises the it-support account. What was the logon type? Answer: 9 SPL:

Code snippet

index=folks EventCode=4624 TargetUserName="it-support"
| table LogonType
Analysis: Logon Type 9 (NewCredentials) is characteristic of tools like Mimikatz or runas /netonly. It allows the attacker to execute processes locally while using the compromised credentials for network authentication (Pass-The-Hash).

Q13
Question: What ticket name did the attacker generate to access the parent DC as Administrator? Answer: trust-test2.kirbi SPL:

Code snippet

index=folks host=CLIENT02 "ticket"
| table CommandLine
Analysis: The attacker forged an Inter-Realm Trust Ticket to hop domains. The command line arguments show the generation/loading of a ticket file named trust-test2.kirbi.
