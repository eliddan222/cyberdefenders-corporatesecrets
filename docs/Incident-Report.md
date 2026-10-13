# Incident Response Report — INC-2026-001

## Executive Summary
This simulated forensics investigation centered around potential exfiltration of company secrets. An AD1 logical evidence image was provided and analyzed. Analysis identified the host as DESKTOP-3A4NLVQ, running Windows build 16299, with six user accounts. 

The user `jim.tomato` was at the center of the findings. The account's browser history revealed searches concerning the legality of leaking company secrets and gaining access to company systems following departure from the company. Another central finding was a shortcut `.lnk` in Jim's desktop that linked to `CompanySecrets.docx`. Upon using the location listed in the shortcut, the document was missing. However, through correlating the documents MFT entry and object identifier, it was possible to identify the same file was `file.xml` inside a recycled directory. Examining `file.xml` revealed that it was the markup portion of a Word document with contents containing company secrets. Despite this being consistent with concealment attempts, there is no proof that this was a purposeful attempt to conceal `CompanySecrets.docx`.

The investigation concluded unable to discover evidence confirming or denying the possible exfiltration. Across the browser history, Chrome cache, Slack data, and Tor artifacts. No external recipient or exfiltration attempts were established.

## Incident Scope

The system targeted for investigation was DESKTOP-3A4NLVQ.

Analysis covered the supplied forensic AD1 image including:
- Registry hives.
- User Documents and files.
- Recycle Bin metadata and contents.
- Master File Table (MFT) records
- Browser history, cache, and local Slack data.


## Evidence Examined
| Evidence | Description and investigative use |
|---|---|
| E002–E003 | Original evidence file and working copy used for examination. |
| E004–E006 | SOFTWARE, SAM, and SYSTEM registry hives used to identify the host and map accounts to profiles. |
| E007 | `secret.odt`, containing simulated CEO plans and concealed text concerning Jim Tomato. |
| E016 | `CompanySecrets.lnk`, referencing a document on Jim’s desktop. |
| E017–E020 | Recycle Bin metadata and document contents examined during the search for the missing document. |
| E021 | Jim’s Chrome History database, containing disclosure-related searches and Slack activity. |
| E022 | LibreOffice Writer Jump List referencing `CompanySecrets.docx` and other documents. |
| E023 | MFT data used to correlate the referenced document with its recovered filename and location. |
| E024–E025 | Recycle Bin metadata and recovered `file.xml` containing purported company secrets. |
| E026–E027 | Jim’s Slack-related local data examined for communications or transfer evidence. |
| E028–E029 | UserAssist and Tor browser history artifacts examined for execution and browsing activity. |
| E030 | Chrome cache examined for message or file-transfer records. |
| E031 | Slack log under the `hansel.apricot` profile, containing workplace discussions. |


## Attack Timeline
| Time | Recorded activity | Evidence |
|---|---|---|
| 2020-04-09 20:12:07 UTC | UserAssist recorded a last-run timestamp for the executable associated with Tor Browser in Jim’s profile. | E028 |
| 2020-04-10 05:32:24; timezone pending verification | Jump List entry associated with `CompanySecrets.docx` displayed a DestList creation timestamp. | E022 |
| 2020-04-11 23:16:21; timezone pending verification | The same entry displayed a DestList last-modification timestamp. | E022 |
| 2020-04-11 17:23:48; timezone pending verification | Recycle Bin metadata recorded deletion of the directory containing the recovered document. | E024 |
| Time not established | Chrome history recorded searches concerning leaking company secrets and computer access after departure. | E021 |
| Present in supplied evidence | Matching file identifiers correlated `CompanySecrets.docx` with `file.xml` in a recycled directory. | E022–E025 |


## Key Findings

### F-001 — Host and User Identification

**Evidence:** E004-E006

The SOFTWARE hive identified the Windows build number 16299. The SYSTEM hive recorded the hostname as DESKTOP-3A4NLVQ. ProfileList included six user profiles and mapped them to their respective directories and SID's. 

**Assessment:** No malicious activity identified at this stage. This established baseline knowledge of the system being examined.

**Supporting Exhibit:**

![Account Names Registry Hive](/screenshots/RegistryAccountNames.png)

### F-002 — Sensitive Information Identified

**Evidence:** E007

The `tim.apple` profile contained `secret.odt`. It contained simulated CEO plans. Although missed upon first examination, a later examination revealed that there was white text intended to blend in with the white background. Changing the color of the text revealed a fourth plan to fire Jim Tomato.

**Assessment:** The document provided some useful context of the workplace. There was no evidence established of Jim having access to the file or transfer of it out of the system.

**Supporting Exhibit:**

![Tim Apple's Secret CEO Plans](/screenshots/JimTomatoFireConcealedLine.png)

### F-003 — Suspicious Browser History

**Evidence:** E021

Jim Tomato's chrome history database contained searches about the legality of leaking company secrets and hacking into a computer following departure from a company.

**Assessment:** The searches were highly concerning and provided a lead making `jim.tomato` the lead suspect. Despite the severity of the searches, they do not establish any successful unauthorized access or completed file transfers.

**Supporting Exhibit:**

![Jim's Chrome History Database](/screenshots/JimHistoryDB.png)

### F-004 — CompanySecrets.docx Interactions

**Evidence:** E002 — Network Capture; E003 — Memory Image

The IIS server initiated a TCP connection from `10.0.2.15:49688` to `10.0.2.4:4443` that involved bidirectional communication. Memory analysis associated the connection with `w3wp.exe` PID 4332.

**Assessment:** This suggested a high probability of a reverse shell connection through the IIS server's compromised worker process.

**Supporting Exhibit:**
![biderectionalCommunications](/screenshots/bidirectionalCommunications.png)
![volatilitynetscan](/screenshots/volatilityFilteredNetscanOutput.png)

### F-005 — Malicious Executable Launched Through IIS

**Evidence:** E003 — Memory Image

Process-tree analysis showed `w3wp.exe` PID 4332 had a child process: `updatenow.exe` PID 900.

**Assessment:** The parent-child relationship connects execution of
`updatenow.exe` directly to the compromised IIS application process and
supports post-exploitation code execution through the web server.

**Supporting Exhibit:**
![PSTree](/screenshots/volatilityWindowsPStree.png)

### F-006 — Startup Folder Persistence

**Evidence:** E003 — Memory Image

Command-line analysis showed `updatenow.exe` executing from:

`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe`

**Assessment:** Putting the executable inside the startup folder indicates an attempt to maintain persistence through future logins.

**Supporting Exhibit:**
![updateNowLaunchLocation](/screenshots/volatilityCommandLineUpdateNowLaunchLocation.png)

### F-007 — Recovered Executable Confirmed Malicious

**Evidence:** E004 — `updatenow.exe`; external threat intelligence

The SHA-256 hash of `updatenow.exe` was identified as malicious by the majority of VirusTotal scanners. Threat-intelligence and sandbox analysis associated the sample with Agent Tesla, UPX packing, credential-access behavior, process injection, and external network communication.

**Assessment:** External threat intelligence found the executable to be malicious. 

**Supporting Exhibit:**
![virusTotalResults](/screenshots/virusTotalResults.png)

## MITRE ATT&CK Mapping

These ATT&CK mappings are based on techniques supported by evidence in the provided artifacts. Other behaviors are excluded, as they have not been independently confirmed through the artifacts and would be supported only by third-party threat intelligence.

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning; Vulnerability Scanning | T1595.002 | Rapid TCP probing and Nmap NSE-based HTTP enumeration. |
| Command and Control | Ingress Tool Transfer | T1105 | `shell.aspx` was transferred by the attacker through SMB. |
| Persistence | Server Software Component; Web Shell | T1505.003 | `shell.aspx` was placed in a web-accessible directory and requested through IIS. |
| Command and Control | Non-Application Layer Protocol | T1095 | A bidirectional TCP session was established from the IIS server to `10.0.2.4:4443` following execution of the web shell. |
| Persistence / Privilege Escalation | Registry Run Keys / Startup Folder | T1547.001 | `updatenow.exe` executed from the system-wide Windows Startup directory. |
| Stealth | Software Packing | T1027.002 | VirusTotal identified `updatenow.exe` as UPX-packed. |


## Containment Recommendations
- Isolate the compromised IIS server, maintaining only necessary forensic examination access.
- Block all communication to the attacker's systems.
- Disable accounts if credential compromise is possible.
- Search other systems and the network telemetry for further potentially compromised systems.

## Eradication
- Remove `shell.aspx` and `updatenow.exe`.
- Remove any additional malicious files and persistence mechanisms uncovered through investigation.
- Patch and harden the services on the IIS that were exposed.
- Reset any accounts and change credentials that were potentially exposed.
- Search the rest of the enterprise for related attacker activity.

## Recovery
- Restore the server from a known good state.
- Validate malicious files are no longer present.
- Confirm there are no unauthorized outbound connections.
- Bring the systems back to production only after controls, patches, and monitoring are verified to be back in working order.
- Increase monitoring of the affected server post-recovery.

## Limitations
- Only three artifacts were provided, limiting the scope.
- No live access to the impacted server was possible.
- There were several other capabilities of the malware according to external threat-intelligence that could not be treated as confirmed or denied based on the provided forensic data.

## Lessons Learned
- The public facing IIS server should have been more hardened to reduce exposure, especially administrative protocols like SMB.
- Outbound connections from the IIS server should be monitored for suspicious activity. The connections made in this attack did not represent typical IIS activity and should have been actively monitored.
- The attacker was able to place the malicious ASPX file in a web-accessible location and attempt to create persistence in the Windows Startup folder. Locations like these should be monitored for for unexpected file creation, modification, and deletion.
- Finding correlation between the memory dump and packet capture increased confidence in the investigation. The packet capture identified the suspicious activity. The memory analysis was able to associate that connection with `w3wp.exe` and linked the IIS process to execution of `updatenow.exe`.
- External threat-intelligence was useful for identifying capabilities of the malware, but the provided findings need to be kept separated from the real incident-confirmed findings unless corroborated by the evidence.