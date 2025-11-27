# Boss of the SOC v1: Threat Hunting with Splunk

![Category](https://img.shields.io/badge/Category-Blue%20Team-blue)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20Suricata-green)
![Status](https://img.shields.io/badge/Status-Completed-success)

## 🔍 Project Overview
This repository documents my investigation into the **"Boss of the SOC" (BOTSv1)** capture-the-flag challenge hosted by CyberDefenders.

**Role:** Alice Bluebird, SOC Analyst at Wayne Enterprises.  
**Objective:** Use **Splunk Enterprise** to reconstruct two distinct attack scenarios:
1.  **APT Po1s0n1vy:** A targeted web defacement of the corporate website.
2.  **Cerber Ransomware:** An endpoint infection that moved laterally to a file server.

---

## Scenario 1: Web Defacement (APT Po1s0n1vy)
**Context:** Investigating a reported defacement of `imreallynotbatman.com`.

### Phase 1: Reconnaissance

#### Q1
**Question:** What is the name of the company that makes the software that you are using for this competition?
* **Answer:** `Splunk`
* **Methodology:** Identification of the SIEM platform interface.

#### Q2
**Question:** Web Defacement: What content management system is imreallynotbatman.com likely using?
* **Answer:** `Joomla`
* **SPL:**
    ```splunk
    index=botsv1 imreallynotbatman.com sourcetype=stream:http
    | top uri limit=20
    ```
* **Analysis:** Frequent access to `/administrator/` and `/media/` directories confirmed the Joomla CMS structure.


#### Q3
**Question:** Web Defacement: What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?
* **Answer:** `40.80.148.42`
* **SPL:**
    ```splunk
    index=botsv1 imreallynotbatman.com sourcetype=stream:http
    | top src_ip
    ```
* **Analysis:** Vulnerability scanners generate high volumes of traffic. Sorting by source IP count revealed `40.80.148.42` as the most aggressive scanner.

#### Q4
**Question:** Web Defacement: What company created the web vulnerability scanner used by Po1s0n1vy?
* **Answer:** `Acunetix`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=40.80.148.42 sourcetype=stream:http
    | stats count by http_user_agent
    ```
* **Analysis:** The scanner left signature strings (e.g., `wvs_security_test`) in the HTTP User-Agent header, identifying the tool as Acunetix.

### Phase 2: Weaponization & Delivery

#### Q5
**Question:** Web Defacement: What IP address is likely attempting a brute force password attack against imreallynotbatman.com?
* **Answer:** `23.22.63.114`
* **SPL:**
    ```splunk
    index=botsv1 imreallynotbatman.com uri_path="/joomla/administrator/index.php" http_method=POST
    | stats count by src_ip
    ```
* **Analysis:** The attacker switched IPs to perform the login brute force. This IP sent hundreds of POST requests to the admin login page.

#### Q6
**Question:** Web Defacement: What was the first brute force password used?
* **Answer:** `12345678`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 http_method=POST
    | table _time form_data
    | sort _time
    ```
* **Analysis:** Sorting the POST events chronologically revealed the first password attempted in the `form_data` field.

#### Q7
**Question:** Web Defacement: What is the name of the executable uploaded by Po1s0n1vy?
* **Answer:** `3791.exe`
* **SPL:**
    ```splunk
    index=botsv1 dest_ip=192.168.250.70 http_method=POST part_filename="*.exe"
    ```
* **Analysis:** The attacker uploaded this file via a POST request after compromising the CMS. The `part_filename` field captured the filename.

#### Q8
**Question:** Web Defacement: What is the MD5 hash of the executable uploaded?
* **Answer:** `AAE3F5A29935E6ABCC2C2754D12A9AF0`
* **SPL:**
    ```splunk
    index=botsv1 "3791.exe" EventCode=1 sourcetype=xmlwineventlog
    | table Hashes
    ```
* **Analysis:** Sysmon EventCode 1 (Process Creation) logs the hash of the file when it is executed on the endpoint.

#### Q9
**Question:** Web Defacement: What was the correct password for admin access to the content management system running "imreallynotbatman.com"?
* **Answer:** `batman`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 http_method=POST uri_path="/joomla/administrator/index.php" http_content_length!=182
    | table form_data
    ```
* **Analysis:** Failed logins returned a page size of 182 bytes. Filtering for events where `http_content_length != 182` revealed the single successful login attempt.

### Phase 3: Exploitation & Installation

#### Q10
**Question:** Web Defacement: What is the name of the file that defaced the imreallynotbatman.com website?
* **Answer:** `poisonivy-is-coming-for-you-batman.jpeg`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 OR dest_ip=23.22.63.114 sourcetype=stream:http uri="*.jpeg"
    ```
* **Analysis:** The compromised server downloaded this image from the attacker's infrastructure to replace the website's homepage.

#### Q11
**Question:** Web Defacement: This attack used dynamic DNS to resolve to the malicious IP. What is the fully qualified domain name (FQDN) associated with this attack?
* **Answer:** `prankglassinebracket.jumpingcrab.com`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 sourcetype=suricata http.hostname!="imreallynotbatman.com"
    ```
* **Analysis:** Suricata logs captured the HTTP Host header pointing to this dynamic DNS domain (jumpingcrab).

#### Q12
**Question:** Web Defacement: What IP address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?
* **Answer:** `23.22.63.114`
* **Analysis:** This is the IP address that resolved to the domain found in Q11.

### Phase 4: Infrastructure & OSINT

#### Q13
**Question:** Web Defacement: Based on the data gathered... what is the email address most likely associated with the Po1s0n1vy APT group?
* **Answer:** `Lillian.Rose@po1s0n1vy.com`
* **Analysis:** Historical OSINT/Whois data for the `po1s0n1vy` domain reveals this registrant email (a reference to the Batman villain).

#### Q14
**Question:** Web Defacement: ... provide the SHA256 hash of this malware.
* **Answer:** `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8`
* **Analysis:** Investigating the attacker IP `23.22.63.114` on VirusTotal revealed a communicating file named `MirandaTateScreensaver.scr.exe`.

#### Q15
**Question:** Web Defacement: What is the special hex code associated with the customized malware discussed in the previous question?
* **Answer:** `53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21`
* **Analysis:** This hex string was found in the "Community Comments" section of the VirusTotal page for the malware hash found in Q14.

#### Q16
**Question:** Web Defacement: One of Po1s0n1vy's staged domains has some disjointed "unique" whois information. Concatenate the two codes together.
* **Answer:** `3173743266696E6467657473667265656265657266726F6D7279616E66696E6468696D746F676574`
* **Analysis:** The typosquatted domain `waynecorinc.com` contained Hex strings in the "Company Name" and "Address" fields of its historical WHOIS record.

#### Q17
**Question:** Web Defacement: One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song... Which is it?
* **Answer:** `yellow`
* **Analysis:** Found by manually reviewing the list of passwords attempted in the brute force dictionary.

#### Q18
**Question:** Web Defacement: What was the average password length used in the password brute-forcing attempt?
* **Answer:** `6`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 http_method=POST
    | rex field=form_data "passwd=(?<password>[^&]+)"
    | eval len=len(password) | stats avg(len)
    ```

#### Q19
**Question:** Web Defacement: How many seconds elapsed between the brute force password scan identified the correct password and the compromised login?
* **Answer:** `92.17`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 http_method=POST form_data="*passwd=batman*"
    | transaction form_data
    | table duration
    ```
* **Analysis:** Calculated the time delta between the automated brute-force success (bot) and the manual login (human).

#### Q20
**Question:** Web Defacement: How many unique passwords were attempted in the brute force attempt?
* **Answer:** `412`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=23.22.63.114 http_method=POST
    | rex field=form_data "passwd=(?<password>[^&]+)"
    | stats dc(password)
    ```

---

## Scenario 2: Ransomware (Cerber)
**Context:** Investigating the infection of Bob Smith's workstation (`we8105desk`).

### Phase 1: Infection Vector

#### Q21
**Question:** Ransomware: What fully qualified domain name (FQDN) makes the Cerber ransomware attempt to direct the user to at the end of its encryption phase?
* **Answer:** `cerberhhyed5frqa.xmfir0.win`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=192.168.250.100 sourcetype=stream:dns query="*.win"
    ```
* **Analysis:** This suspicious domain (ending in .win) was queried immediately after the infection to display the ransom note.

#### Q22
**Question:** Ransomware: What was the most likely IP address of we8105desk in 24AUG2016?
* **Answer:** `192.168.250.100`
* **SPL:**
    ```splunk
    index=botsv1 host=we8105desk | stats count by src_ip
    ```

#### Q23
**Question:** Ransomware: Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times?
* **Answer:** `2816763`
* **SPL:**
    ```splunk
    index=botsv1 sourcetype=suricata alert.signature="*Cerber*"
    | stats count by alert.signature_id | sort count
    ```

#### Q24
**Question:** Ransomware: The VBScript found in question 25 launches 121214.tmp. What is the ParentProcessId of this initial launch?
* **Answer:** `3968`
* **SPL:**
    ```splunk
    index=botsv1 sourcetype="xmlwineventlog" "121214.tmp"
    | table ParentProcessId
    ```
* **Analysis:** The VBScript process (`3968`) launched `cmd.exe`, which launched the temporary file.

#### Q25
**Question:** Ransomware: During the initial Cerber infection a VB script is run... What is the length in characters of the value of this field?
* **Answer:** `4490`
* **SPL:**
    ```splunk
    index=botsv1 host=we8105desk sourcetype="xmlwineventlog"
    | eval cmd_length=len(CommandLine) | sort - cmd_length | head 1
    ```
* **Analysis:** The malware utilized a "fileless" technique, stuffing the entire malicious payload (4,490 characters) into the command line argument.

### Phase 2: Payload & Lateral Movement

#### Q26
**Question:** Ransomware: The malware downloads a file that contains the Cerber ransomware crypto code. What is the name of that file?
* **Answer:** `mhtr.jpg`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=192.168.250.100 sourcetype=stream:http
    | search uri_path="*.jpg"
    ```
* **Analysis:** The malware downloaded this file from the compromised charity site. The suspicious context (downloaded by a script, not a browser) indicated this was not a real image.

#### Q27
**Question:** Ransomware: Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?
* **Answer:** `Steganography`
* **Analysis:** Hiding malicious code inside a JPEG image (`mhtr.jpg`) is the definition of steganography.

#### Q28
**Question:** Ransomware: What is the name of the USB key inserted by Bob Smith?
* **Answer:** `MIRANDA_PRI`
* **SPL:**
    ```splunk
    index=botsv1 host=we8105desk sourcetype=winregistry
    | table friendlyname
    ```
* **Analysis:** Registry logs (`USBSTOR`) revealed a USB device named `MIRANDA_PRI` connected shortly before the infection.

#### Q29
**Question:** Ransomware: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?
* **Answer:** `192.168.250.20`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=192.168.250.100 dest_port=445
    | stats count by dest_ip
    ```
* **Analysis:** High-volume SMB (Port 445) traffic moving laterally from the infected host identified the File Server.

#### Q30
**Question:** Ransomware: How many distinct PDFs did the ransomware encrypt on the remote file server?
* **Answer:** `257`
* **SPL:**
    ```splunk
    index=botsv1 dest_ip=192.168.250.20 Relative_Target_Name="*.pdf"
    | stats dc(Relative_Target_Name)
    ```
* **Analysis:** Using `dc` (Distinct Count) revealed the exact number of unique PDF files accessed/encrypted during the attack window.

#### Q31
**Question:** Ransomware: The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?
* **Answer:** `406`
* **SPL:**
    ```splunk
    index=botsv1 host=we8105desk sourcetype="xmlwineventlog" TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt"
    | stats dc(TargetFilename)
    ```

#### Q32
**Question:** Ransomware: What was the first suspicious domain visited by we8105desk in 24AUG2016?
* **Answer:** `solidaritedeproximite.org`
* **SPL:**
    ```splunk
    index=botsv1 src_ip=192.168.250.100 sourcetype=stream:dns
    | table _time query
    | sort _time
    ```
* **Analysis:** This domain was queried immediately after the USB insertion and before the ransomware domain, indicating it was the source of the dropped payload.
