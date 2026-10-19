# CyberDefenders Corporate Secrets - Digital Forensics Investigation

A simulated digital forensics investigation of a suspected corporate secret exfiltration using a Windows AD1 evidence image.

## Investigation Summary

Analysis examined Windows registry hives, browser history, shortcuts, Jump Lists, MFT records, and Recycle Bin artifacts to uncover activity associated with a document containing company secrets and its potential exfiltration.

Analysis of the provided artifacts revealed which user account was the lead suspect, and resulted in following a trail to find where the document was and what it contained. Following the trail required correlating MFT entry sequence numbers to correlate a shortcut to a recycled `file.xml`. Examination of `file.xml` revealed the structure of a Word document containing company secrets. 

Additional suspicious searches about exfiltration of company data were found in the browser history. However, examination of browsers` cache, Tor, and Slack artifacts did not establish any successful transfer of company secrets. The result was document interaction and recovery being substantiated, but exfiltration remained unconfirmed within the provided evidence.


## Tools
- FTK Imager
- FTK Registry Viewer
- DB Browser for SQLite
- JumpList Explorer
- MFTECmd
- RBCmd
- Hindsight
- ChromeCacheView
- LibreOffice Writer
- 7-Zip
- PowerShell

## Skills Applied
- Evidence preservation and integrity verification
- Windows registry analysis
- Browser artifact examination
- Shortcut and Jump List analysis
- NTFS metadata and file identifier correlation
- Recycle Bin analysis and document recovery
- File signature and internal structure examination
- Evidence-based assessment and incident documentation

## Documentation
- [Incident Response Report](docs/Incident-Report.md)
- [Analyst Case Notes](logs/analyst-notes.md)
- [Evidence Integrity Log](logs/evidence-log.csv)
- [Incident Response SOP](docs/IR-SOP.md)

## Works Cited
- CyberDefenders CorporateSecrets: https://cyberdefenders.org/blueteam-ctf-challenges/corporatesecrets/



## Copyright
© 2026 Elijah D. All rights reserved.

This repository contains original analysis and documentation created for a CyberDefenders simulated lab. CyberDefenders and the Lockdown lab remain property of their respective owners.