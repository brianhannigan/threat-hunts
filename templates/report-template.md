# Azure Threat Hunt Report

## Hunt ID

TH-YYYY-XXX

## Date

## Hunter

## Environment

Azure / Microsoft Sentinel / Defender XDR

---

# Hunt Objective

Describe the reason for the hunt.

Example:

Investigate possible credential compromise and suspicious Azure AD activity.

---

# Threat Hypothesis

Example:

An attacker may have compromised a user account and is performing abnormal sign-in activity.

---

# MITRE ATT&CK Mapping

| Tactic          | Technique          |
| --------------- | ------------------ |
| Initial Access  | Valid Accounts     |
| Persistence     | Create Account     |
| Defense Evasion | Token Manipulation |

---

# Investigation Steps

---

## Step 1 – Suspicious Sign-ins

### Hypothesis

An attacker logged in from abnormal locations.

### KQL Query

```kql
SigninLogs
| where ResultType == 0
| summarize count() by UserPrincipalName, IPAddress, Location
| order by count_ desc
```

### Findings

No anomalies / suspicious IP detected.

### Flags

None.

---

## Step 2 – Privileged Role Changes

### KQL Query

```kql
AuditLogs
| where OperationName contains "Add member to role"
```

### Findings

FLAG-001

New Global Admin assigned.

---

# Flag Tracker

| Flag ID  | Indicator            | Account                                   | IP  | System   | Description           |
| -------- | -------------------- | ----------------------------------------- | --- | -------- | --------------------- |
| FLAG-001 | Privilege escalation | [user@domain.com](mailto:user@domain.com) | N/A | Azure AD | Added to Global Admin |

---

# KQL Query Library

| ID   | Purpose          | Query |
| ---- | ---------------- | ----- |
| Q001 | Sign-in analysis | ...   |
| Q002 | Privileged roles | ...   |

---

# Systems Investigated

| System   | Type     | Notes           |
| -------- | -------- | --------------- |
| Azure AD | Identity | Role changes    |
| VM-01    | Compute  | Normal activity |

---

# Timeline

| Time  | Event           | Actor                                       | Resource |
| ----- | --------------- | ------------------------------------------- | -------- |
| 10:14 | Login           | [user@domain.com](mailto:user@domain.com)   | Azure AD |
| 10:22 | Role assignment | [admin@domain.com](mailto:admin@domain.com) | Azure AD |

---

# Data Gaps

Example:

* No Defender for Endpoint telemetry
* Limited Azure Storage logs

---

# Findings Summary

Describe whether malicious activity was found.

---

# Risk Assessment

Low / Medium / High

---

# Recommended Remediation

* Reset credentials
* Revoke tokens
* Enable conditional access
* Block malicious IPs

---

# Detection Improvements

New Sentinel rules to deploy.

---

# Lessons Learned

Improvements for logging and detection.
