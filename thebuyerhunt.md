Shadow copy deletion is a standard ransomware preparation step.

Results Summary

Alert indicates:

cmd.exe attempted to delete volume shadow copies
Flagged Indicators
FLAG-004
Field	Value
Technique	Shadow copy deletion
Device	AS-PC2
Account	David.Mitchell
Timestamp	4:03:49 PM

Description

System recovery protection removal.

Indicators Table
Flag ID	Type	Indicator	System	Notes
FLAG-001	Defense Evasion	Defender disabled	AS-PC2	PowerShell tampering
FLAG-002	Discovery	Advanced IP Scanner	AS-PC2	Network scanning
FLAG-003	Credential Access	LSASS memory read	AS-PC2	Credential theft
FLAG-004	Impact	Shadow copy deletion	AS-PC2	Ransomware preparation
Systems Impacted
System	Type	Owner	Suspicious Activity
AS-PC2	Windows 10	David.Mitchell	Defender tampering, network scanning, credential dumping
Timeline of Activity
Time	Event	System	Account	Notes
1:29 PM	Suspicious svchost activity	AS-PC2	David.Mitchell	Early compromise indicator
3:17 PM	Advanced IP Scanner executed	AS-PC2	David.Mitchell	Network discovery
3:45 PM	LSASS memory access	AS-PC2	David.Mitchell	Credential dumping
4:03 PM	Defender protections disabled	AS-PC2	David.Mitchell	Defense evasion
4:03 PM	Shadow copies deleted	AS-PC2	David.Mitchell	Ransomware staging
Data Gaps
Missing Telemetry	Impact
Network flow logs	Cannot confirm lateral movement
Azure AD sign-in telemetry	Cannot confirm initial access vector
Email telemetry	Possible phishing vector unknown
Final Assessment
Summary

The investigation identified clear indicators of hands-on-keyboard ransomware activity consistent with Akira ransomware operations.

Observed behaviors include:

Defender tampering

Network scanning

Credential dumping

Recovery destruction

These actions align with ransomware pre-deployment activity.

Compromise Likelihood

HIGH

Risk Level

CRITICAL

Recommended Remediation

Immediate actions:

1️⃣ Disable compromised account

David.Mitchell

2️⃣ Isolate affected host

AS-PC2

3️⃣ Re-enable Defender protections

4️⃣ Reset all domain credentials

5️⃣ Hunt for lateral movement

Additional Hunt Queries
Lateral Movement Detection
DeviceLogonEvents
| where AccountName == "David.Mitchell"
| project TimeGenerated, DeviceName, LogonType
| order by TimeGenerated asc
Suspicious PowerShell
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc"
Lessons Learned
Detection Improvements

Add Sentinel analytic rule for:

Set-MpPreference
DisableAntiSpyware
Logging Improvements

Enable:

Defender Advanced Hunting

Azure AD Identity Protection logs

Network flow telemetry

Conclusion

The activity observed represents a human-operated ransomware intrusion, progressing through:

1️⃣ Discovery
2️⃣ Credential theft
3️⃣ Defense evasion
4️⃣ Impact preparation

Immediate containment is required.
