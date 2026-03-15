<p align="center">
  <img src="../assets/the_buyer_banner.svg" alt="SOC Investigation – The Buyer" width="100%" />
</p>

# 🛒 Threat Hunt Report: The Buyer

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2B%20MDE-blue)
![Focus](https://img.shields.io/badge/Focus-Ransomware%20Intrusion%20Reconstruction-purple)

> **What happened?**  
> This hunt identified a high-confidence, hands-on-keyboard ransomware intrusion on `AS-PC2`.  
> The attacker performed discovery, credential theft, defense evasion, and recovery-destruction behavior consistent with pre-encryption staging.

---

## 📌 Quick Answers (CTF Flags / Findings)

### Confirmed Flag
- **FLAG-004 (Impact):** Shadow copy deletion
- **Technique:** Recovery inhibition / ransomware preparation
- **Host:** `AS-PC2`
- **Account:** `David.Mitchell`
- **Timestamp:** `4:03:49 PM`

### Related Indicators from the Same Attack Chain
- **FLAG-001 (Defense Evasion):** Defender disabled (PowerShell tampering)
- **FLAG-002 (Discovery):** Advanced IP Scanner execution
- **FLAG-003 (Credential Access):** LSASS memory access

---

## 🎯 Executive Summary

The investigation confirms a coordinated ransomware kill chain on `AS-PC2` under user context `David.Mitchell`. Activity progressed from host discovery and credential theft to direct impairment of recovery capabilities through shadow copy deletion.

This sequence strongly matches human-operated ransomware playbooks and indicates imminent encryption risk at the time of detection.

- **Compromise Likelihood:** **HIGH**
- **Risk Level:** **CRITICAL**
- **Business Impact:** Loss of recovery options and elevated probability of broader domain compromise

---

## 🧠 Hunt Hypothesis

If an adversary is staging ransomware on an endpoint, telemetry should show a sequence of:

1. Discovery activity
2. Credential theft behavior
3. Security control tampering
4. Recovery inhibition (e.g., shadow copy deletion)

The observed evidence validated this hypothesis.

---

## 🔍 Scope & Data Sources

### Investigated Asset
- `AS-PC2` (Windows 10)

### Primary User Context
- `David.Mitchell`

### Data Sources Referenced
- Endpoint process telemetry
- Defender behavior and tamper indicators
- Credential access alerts
- Hunt timeline reconstruction artifacts

---

## 🕒 Timeline of Confirmed Activity

| Time | Event | Host | Account | Assessment |
|---|---|---|---|---|
| 1:29 PM | Suspicious `svchost` activity | AS-PC2 | David.Mitchell | Early compromise signal |
| 3:17 PM | Advanced IP Scanner executed | AS-PC2 | David.Mitchell | Internal discovery |
| 3:45 PM | LSASS memory access detected | AS-PC2 | David.Mitchell | Credential dumping |
| 4:03 PM | Defender protections disabled | AS-PC2 | David.Mitchell | Defense evasion |
| 4:03 PM | Shadow copies deleted | AS-PC2 | David.Mitchell | Ransomware staging / impact prep |

---

## 🧾 Indicator Matrix

| Flag | Tactic | Indicator | System | Notes |
|---|---|---|---|---|
| FLAG-001 | Defense Evasion | Defender disabled | AS-PC2 | PowerShell tampering |
| FLAG-002 | Discovery | Advanced IP Scanner | AS-PC2 | Network reconnaissance |
| FLAG-003 | Credential Access | LSASS memory read | AS-PC2 | Credential theft |
| FLAG-004 | Impact | Shadow copy deletion | AS-PC2 | Recovery inhibition |

---

## 💥 Systems Impacted

| System | Type | Owner | Suspicious Activity |
|---|---|---|---|
| AS-PC2 | Windows 10 | David.Mitchell | Defender tampering, network scanning, credential dumping, shadow copy deletion |

---

## 🧪 Detection & Hunt Queries

### Lateral Movement Validation
```kusto
DeviceLogonEvents
| where AccountName == "David.Mitchell"
| project TimeGenerated, DeviceName, LogonType
| order by TimeGenerated asc
```

### Suspicious PowerShell (Encoded Command Pattern)
```kusto
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc"
```

---

## ⚠️ Data Gaps

| Missing Telemetry | Investigative Impact |
|---|---|
| Network flow logs | Unable to fully confirm lateral movement path |
| Azure AD sign-in telemetry | Initial access vector remains unconfirmed |
| Email telemetry | Phishing delivery chain cannot be validated |

---

## 🛡 Recommended Remediation

### Immediate Containment
1. Disable compromised account: `David.Mitchell`
2. Isolate endpoint: `AS-PC2`
3. Restore and lock Defender protection settings
4. Reset all potentially exposed domain credentials
5. Run targeted lateral movement hunts across peer systems

### Detection Engineering Improvements
- Create analytic detections for:
  - `Set-MpPreference` abuse
  - `DisableAntiSpyware` behavior
  - Shadow copy deletion commands
- Expand mandatory telemetry collection:
  - Defender Advanced Hunting completeness
  - Azure AD Identity Protection logs
  - East-west network flow visibility

---

## 🧭 Final Assessment

The intrusion on `AS-PC2` is best assessed as a **human-operated ransomware operation in pre-encryption stage**.

Observed phases map to:
1. **Discovery**
2. **Credential Access**
3. **Defense Evasion**
4. **Impact Preparation**

Immediate containment and enterprise-wide scoping are required to reduce probability of follow-on encryption and lateral spread.
