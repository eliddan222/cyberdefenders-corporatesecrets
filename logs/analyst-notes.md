# INC-2026-002 - Cyberdefender's Corporate Secrets

Case Opened: 2026-10-09 14:35 America/Denver Timezone
Analyst: Elijah D.
Environment: CyberDefender's simulated incident

Initial Reason for Investigation:
Suspected corporate secret exfiltration, based on lab objective.

Known Assets:
- One windows system represented in the supplied evidence. Hostname, Windows Version, and number of users are unknown. No impacted files or accounts have been confirmed.

Initial Severity:
Unknown, pending triage. Provided information does not yet establish severity.

Initial Objectives:
- Identify the system's hostname and Windows build.
- Identify local user accounts and distinguish them from user profile folders.
- Inventory available artifacts relevant to user activity and suspected exfiltration.
- Reconstruct any relevant activity to determine if evidence supports the suspected incident.

Limitations:
Analysis is limited to the provided artifacts.

## 2026-10-09 14:58
**Action performed:** Created a SHA256 hash of the original file to create an integrity baseline in `evidence-log.csv` as E002. Created a working copy (E003) and opened it in FTK Imager to begin initial analysis. 

## 2026-10-09 15:10
**Action Performed:**Exported `\Windows\System32\config\SOFTWARE` registry file (E004) for analysis in FTK Registry Viewer to determine the host's Windows build number/version.

**Observation:** Inside the registry viewer examining E004 at `\Microsoft\Windows NT\CurrentVersion` the CurrentBuild and CurrentBuildNumber are both 16299.

**Assessment:** According to Microsoft's website, build number 16299 corresponds to the Windows 10 Version 1709 from late 2017.
Supporting Screenshot:
![BuildNumberRegistry](/screenshots/RegistryBuildNumber.png)

## 2026-10-09 15:26

**Action Performed:** Exported `\Windows\System32\config\SAM` registry file (E005) for analysis in FTK Registry Viewer to determine the number of users on the host.

**Observation:** There is 10 local accounts on this system, 6 being user accounts: admin, Administrator, DefaultAccount, Guest, hansel.apricot, jim.tomato, miriam.grapes, suzy.strawberry, tim.apple, and WDAGUtilityAccount.

**Next Step:** Identify the hostname

Supporting Screenshot:
![AccountNamesInSAMRegistry](/screenshots/RegistryAccountNames.png)

## 2026-10-09 16:04

**Action Performed:** Exported `\Windows\System32\config\SYSTEM` registry hive (E006) for analysis in FTK registry viewer to determine the hostname.

**Observation:** Hostname is DESKTOP-3A4NLVQ based on the registry key at `Control\ComputerName\Computername`

**Assessment:** The examined key records the computer name as DESKTOP-3A4NLVQ. Confirm this against `Select\Current` before treating this as the true name.

## 2026-10-09 16:10

**Observation:** In E006, `Select\Current` was 1, meaning ControlSet001 was the active control set. At `ControlSet001\Control\ComputerName\ComputerName` the value was DESKTOP-3A4NLVQ.

**Assessment:** This confirms the supplied SYSTEM hive records the hostname as DESKTOP-3A4NLVQ in the active control set.

## 2026-10-09 16:12

**Action Performed:** Reopened E004 for examination of `Microsoft\Windows NT\CurrentVersion\ProfileList\` to begin mapping accounts to profile directories.

**Observation:**

| Profile SID | ProfileImagePath |
|---|---|
| S-1-5-18 | `%systemroot%\system32\config\systemprofile` |
| S-1-5-19 | `C:\Windows\ServiceProfiles\LocalService` |
| S-1-5-20 | `C:\Windows\ServiceProfiles\NetworkService` |
| S-1-5-21-2446097003-76624807-2828106174-1001 | `C:\Users\admin` |
| S-1-5-21-2446097003-76624807-2828106174-1002 | `C:\Users\tim.apple` |
| S-1-5-21-2446097003-76624807-2828106174-1003 | `C:\Users\jim.tomato` |
| S-1-5-21-2446097003-76624807-2828106174-1004 | `C:\Users\suzy.strawberry` |
| S-1-5-21-2446097003-76624807-2828106174-1005 | `C:\Users\hansel.apricot` |
| S-1-5-21-2446097003-76624807-2828106174-1006 | `C:\Users\miriam.grapes` |

**Assessment:** E004's ProfileList contains six profile mappings to user directories and three service profile mappings. The six user directories' names correspond to the account names found in E005's SAM account list. This has found locations that should be inspected for suspicious user activity, but this alone doesn't establish ownership of specific actions, or involvement in suspected exfiltration.

## 2026-10-09 16:32

**Action Performed:** Examined user directories in E003 using FTK Imager.

**Observation:**
| Profile | Directory present | Visible artifacts and folders | Notes |
|---|---|---|---|
| admin | Yes | `AppData`, `NTUSER.DAT`, registry transaction logs | User registry hive available for examination. |
| tim.apple | Yes | `AppData`, `Documents`, `Pictures`, `NTUSER.DAT`, registry transaction logs | Documents and Pictures provide leads for file examination. |
| jim.tomato | Yes | `AppData`, `Desktop`, `NTUSER.DAT`, registry transaction logs | Desktop contents and user registry hive available for examination. |
| suzy.strawberry | Yes | `AppData`, `Pictures` | `NTUSER.DAT` is not visible in the supplied top-level listing. |
| hansel.apricot | Yes | `AppData`, `Pictures` | `NTUSER.DAT` is not visible in the supplied top-level listing. |
| miriam.grapes | Yes | `AppData`, `Downloads`, `Pictures`, `NTUSER.DAT`, registry transaction logs | Downloads, Pictures, and user registry hive available for examination. |

**Assessment:** All directories identified from E004's profile mappings are represented in E003. Four of the listings have `NTUSER.DAT`. `hansel.apricot` and `suzy.strawberry` only have `AppData` and `Pictures` folders. 

## 2026-10-09 16:41

**Action Performed:** Examined the `Documents` folder of account `tim.apple`

**Observation:** The listing contains `secret.odt` (10,120 bytes), `desktop.ini`, an NTFS index allocation entry, and subfolder's `My Music`,`My Pictures`, and `My Videos`.

**Assessment:** Based on filename, `secrets.odt` is of interest, so investigation should be performed on it.

Supporting Screenshot:
![timAppleDocuments](/screenshots/timAppleDocumentsFolder.png)


## 2026-10-09 16:45
**Action Performed:** opened `secrets.odt` using LibreOffice writer and inspected contents.

**Observation:** The file contained the heading "Super secret CEO plans:" followed by three bullet points containing the following text: "Take over the world", "Destroy Google", "Release the new Fruit Phone".

**Assessment:** It would appear this document is meant to represent simulated corporate secret information in the lab. This makes it relevant to the suspected exfiltration investigation because it is considered sensitive corporate data. Its presence under user `tim.apple`'s folder doesn't establish who created, accessed, copied, or transferred it.

**Next Step:** Since this is sensitive company secrets that could have been exfiltrated, looking for any references to this in other artifacts is a good idea.

Supporting screenshot:
![secrets.odt contents in LibreOffice](/screenshots/SecretsODTDocumentContents.png)


## 2026-10-09 17:50
**Observation:** The expected `Microsoft\Windows\Recent` path is missing from `tim.apple`'s `AppData\Roaming` folder. There is however a Mozilla folder inside `tim.apple`'s `AppData\Roaming`. 

**Assessment:** This means windows recent-item artifacts are unavailable at this location in the supplied evidence. It doesn't establish secrets.odt was never accessed, though.

## 2026-10-09 18:06
**Action Performed:** Exported the `places.sqlite` file from one of `tim.apple`'s Firefox profiles (E008) for examination.

**Observation:** There are two firefox profiles, however profile `xn6cy72r.default` only contains times.json. The profile of interest is `d6kc02w6.default-release`.  

**Next Step:** Examine E008 in db browser for sqlite.


## 2026-10-09 18:17

**Observation:** E008’s moz_places table contains entries titled “slack - Google Search,” “slack download - Google Search,” “Windows | Downloads Beta | Slack,” and “SlackSetup.exe.”

**Assessment:** These entries show that the Firefox profile associated with `tim.apple`'s directory has searches and activity related to attempting to install slack onto the system. There is no connection to `secret.odt` or establishment of exfiltration. Further investigation is required before prioritizing Slack as a lead.

**Next Step:** Continue looking through user accounts for any suspicious files or leads.

Supporting Screenshot
![SQlite browser view](/screenshots/SQLiteBrowserSlackDowloadAttempted.png)

## 2026-10-09 19:04
**Observation:** While reviewing user files to find potential leads, a file, `vegetable` was found in `miriam.grapes`' `Pictures` folder. This file is oddly missing an extension in FTK Imager. So, using the hex view and looking at the first six bytes, it was possible to determine it is a 7-zip archive missing its extension. Catalogued `vegetable` as E009.

## 2026-10-09 19:10
**Observation:** Examined E009 using 7-zip. The archive contained a folder `pears` containing 3 .jpg images: `pear1`,`pear2`,`pear3` (E010,E011,E012). All three images depict a pear shaped phone with one image showing a person holding the pear shaped phone up to their camera.

**Assessment:** The archive contains imagery of phones that could potentially be related to the E007 document mentioning a new fruit phone. The archive's missing extension doesn't explicitly prove attempted concealment.

**Next Step:** Continue investigating `miriam.grapes` other files.


## 2026-10-09 19:23
**Observation:** `miriam.grapes`' `Downloads` folder contains two potential files of interest. `Phone_Sample_Photos.zip` and `samplePhone.jpg`. Upon examining E014 contains clip art of a phone. E013 only contained the same imagery. No audience-specific text or design information was identified.

**Assessment:** Examine `miriam.grapes` firefox data to see if the clip art was possibly obtained online.

## 2026-10-09 19:36
**Observation:** In E015's moz_places table, record 8's title is "what kind of phones do vsco girls enjoy - Google Search". Record 9's title is "What is a VSCO girl? Shop the latest teen trend - CNN".

**Assessment:** These records show that there is an interest in uncovering the phone preferences of VSCO girls, consistent with the lab-provided target-audience context. This doesn't establish that Miriam finalized any products for that audience or connect anything to exfiltration.

Supporting Screenshot:
![SQLite Miriam Grapes](/screenshots/VSCOSearchesInDBSQLite.png)

## 2026-10-09 19:44
**Observation:** further examination of E007 (secret.odt) revealed that there is a hidden/concealed line using white font against the white background. Changing the font color revealed that the line states plans to fire Jim Tomato.

**Assessment:** This document contains concealed content relevant to Jim Tomato. This provides additional context, but doesn't support any access of the document by Jim or data exfiltration attempts.

**Examination Method:** Font color changed for viewing.

**Next Step:** Examine `jim.tomato`'s recent files for any potential leads on data exfiltration.
Supporting Screenshot:
![Jim Tomato Firing](/screenshots/JimTomatoFireConcealedLine.png)

## 2026-10-10 12:15 
**Observation:** `jim.tomato`'s `AppData\Roaming\Microsoft\Windows\Recent` folder contained `CompanySecrets.lnk`. Exported and recorded the SHA256 hash of the shortcut in the evidence log as E016.

**Assessment:** The shortcut's name makes it a lead for suspected exfiltration. 

**Next Step:** Examine its target path and metadata to determine the file or folder it references.

## 2026-10-10 12:21
**Observation:** The target path of `CompanySecrets.lnk` (E016) is `C:\Users\jim.tomato\Desktop\CompanySecrets.docx`. However, looking at the referenced folder, there is no CompanySecrets.docx presently in that directory listing.

**Assessment:** The E016 shortcut references a document unavailable at the location it is connected to. Possible explanations could be deletion, renaming, or movement of the file. 

**Next Step:** Document1.docx on is present on Jim's desktop but was previously examined and found to be clean and has no relationship to `CompanySecrets.docx`. Examine his recycle bin and other folders for references to `CompanySecrets.docx`.

## 2026-10-10 12:43
**Observation:** There are four files inside `jim.tomato`'s SID associated recycle bin directory. $IK6JCRY.docx (E017) and $IQ1FSDY.docx (E018) are metadata files and they correspond to the content files $RK6JCRY.docx (E019) and $RQ1FSDY.docx (E020). Niether eximined metadata record contains the name `CompanySecrets.docx`.

**Assessment:** The two files have no established relationship to `CompanySecrets.docx` further investigation of the documents is required.

## 2026-10-10 12:51
**Observation:** `$RK6JCRY.docx` is a document titled `Document1.txt`. It just contains the text "Nothing to see here!". Attempting to open `$RQ1FSDY.docx` in LiberOffice writer results in notification that the document is corrupt. Attempting to repair a copy with LibreOffice Writer failed.

**Next Step:** Attempt to examine the internal file structure using 7-zip.

## 2026-10-10 12:58
**Observation:** Inspecting the internal structure of `$RQ1FSDY.docx` with 7-zip revealed the main body text is "Nothing to see here!".

**Assessment:** There is no link between this document and `CompanySecrets.docx` or suspected exfiltration. The cause of the file corruption remains unknown.


## 2026-10-10 13:20
**Observation:** Found `jim.tomato` uses Google Chrome as a web browser and exported the `History` file from it (E021). Examined the file using DB Browser for SQLite. Found several suspicious searches in the `urls` table: "is it illegal to leak company secrets - Google Search", "how to hack into a computer after you are gone - Google Search", followed by pages explaining company secret disclosure and laws. The table also has Slack sign-in and Fruit Inc workspace URLs, including "https://fruitincworkspace.slack.com/"

**Assessment:** Browser records in Jim's profile provided concerning leads in regards to leaking company secrets. Together with E016's "CompanySecrets.docx", this requires further investigation into `jim.tomato`'s activity.

## 2026-10-10 13:34 America/Denver

**Action performed:** Exported `d38a3ea7ec79fbed.automaticDestinations-ms` from Jim’s `Recent\AutomaticDestinations` directory in E003. Calculated its hash and recorded it as E022.

**Observation:** Text examination showed E022 had refernces to `C:\Users\jim.tomato\Desktop\Document1.docx` and `C:\Users\jim.tomato\Desktop\CompanySecrets.docx`.

**Assessment:** E022 again referenced `CompanySecrets.docx`, consistent with observations of E016.

**Next Step:** Examine E022 in JumpList Explorer to distinguish its entries and inspect their target paths and timestamps.

## 2026-10-10 13:41
**Observation:** Examined E022 using JumpList Explorer. It associated the artifact with LiberOffice Writer and shows three seperate entries referencing `Untitled 1.docx`, `CompanySecrets.docx`, and `Document1.docx` on `jim.tomato`'s desktop. The one referencing `CompanySecret.docx` is entry number 1 and has an interaction count of 1.

**Assessment:** The Jump List supports interaction with the path of E016 in Jim's profile. Company Secrets and Document1 are distinct entries and this doesn't establish any direct relationship between the two.

Supporting Screenshot
![JumpList Explorer](/screenshots/JumpListExplorer.png)



