# Incident Response Report — INC-2026-002

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

**Evidence:** E016, E022

`jim.tomato`'s recents folder contained references inside of `.lnk` shortcuts to a `CompanySecrets.docx`. The documents the shortcut linked to no longer existed in the given directory. Additional analysis of LibreOffice Writer Jump List revealed another reference to the same file inside Jim's account.

**Assessment:** The shortcut and jump list indicated interaction of `CompanySecrets.docx` on Jim's profile. This provided an investigative lead into searching for what happened to the now absent document.

**Supporting Exhibit:**
![Jim Tomato's Recents](/screenshots/JimTomatoRecentsCompanySecrets.png)
![Jump List](/screenshots/JumpListExplorer.png)

### F-005 — Identified the Missing Document

**Evidence:** E022,E023,E025

The aforementioned Jump List entry for CompanySecrets.docx had an MFT sequence number, 140007/7 and File Droid identifier a88a8ba5-7aec-11ea-b941-000c29727385. Using these to filter through the MFT record contained in the forensic image showed the file currently associated with those identifiers was `file.xml`. Following its references it was determined to be inside of Jim Tomato's recycle bin directory as its own directory, $RD4SUNL. It also had a metadata file alongside it, $ID4SUNL, showing the original location was Jim's desktop. Opening $RD4SUNL revealed the directory had the same structure as a word document, but it was recycled as a directory instead of a `.docx`. 

**Assessment:** The matching MFT sequence number and file droid identifier strongly indicated file.xml was the document previously titled `CompanySecrets.docx`. The findings are indicative of a filename change, location change, then recycling. There is not a full establishment of who performed those actions or why.

**Supporting Exhibit:**
![MFTEcmd Findings](/screenshots/MFTEcmdFirstQuery.png)
![MFTEcmd Findings Continued](/screenshots/MFTEcmdQuery2.png)

### F-006 — Contents of Recovered Document

**Evidence:** E025

Examining the contents of the recovered `file.xml` confirmed it was previously the contents of a `.docx` file. The file had the heading "Fruit inc. company secrets" followed by claims: "Tim is sleeping with his secretary", "Miriam is copying designs from the iPhone", "Suzy was only hired for her looks", and "Customer data is not stored securely."

**Assessment:** The contents of the document confirm that it contained sensitive information. The way it was recycled as a directory instead of a .docx indicates possible attempt at concealment. However, there is no established deliberate concealment attempts, and the allegations in the document cant be verified.

**Supporting Exhibit:**
![Contents of file.xml](/screenshots/fileXMLContentsCompanySecrets.png)

### F-007 — Exfiltration not Established

**Evidence:** E026,E027,E028,E029,E030,E031

Analysis of Chrome history, Slack related local data, UserAssist and Tor history, Chrome cache, and Slack logs were unable to confirm any transfer of the document. Jim's  search history did contain searches related to exfiltration of company data. Jim's Slack data did not contain any records of uploading or sharing information contained within the document. Tor history only contained default Tor project landing pages. Using readable Slack messages from the `hansel.apricot` profile provided workplace context, but no establishment of disclosure of company secrets.

**Assessment:** No transfer of the document containing company secrets could be established. Despite Jim's search activity being indicative of attempting to exfiltrate the data, there is no evidence suggesting successful transference of the data outside of the company computer. This also does not mean no transfer occurred. 


## Containment Recommendations
- Preserve all evidence, logs, and account information pertaining to the incident.
- Observe all available email, Slack, cloud storage, and endpoint telemetry from the incident's time frame.
- Examine records for transfers associated with the document.



## Limitations
- Analysis was limited to the supplied AD1 evidence image and examined artifacts. The package wasn't a complete sector by sector disk capture.
- Slack related data yielded limited content, and the absence of records doesn't establish absence of uploads.
- Tor history provided limited activity and couldn't provide the full extent of Tor activity.
- Activity associated with a user profile doesn't guarantee the owner of the account is the one responsible.
- Some expected artifacts were missing from where they would be listed in a directory.
- No network records were provided, limiting the possible analysis and confirmation of a transfer occurring.

## Lessons Learned
- Correlating Jump Lists, shortcuts, and MFT records can locate a document after filename and location changes.
- File extensions should be checked against file signatures.
- Initial assessments should avoid reaching conclusions until later evidence can further corroborate it.
- Suspicious searches alone do not establish successful disclosure.
- A defensible investigation can result in unresolved allegations when the evidence doesn't support it.