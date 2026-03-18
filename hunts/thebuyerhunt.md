<p align="center">
  <img src="../assets/the_buyer_banner.svg" alt="SOC Investigation – The Buyer" width="100%" />
</p>

# Threat Hunt Report: The Buyer
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2B%20MDE-blue)
![Focus](https://img.shields.io/badge/Focus-Akira%20Ransomware%20%7C%20Impact%20Reconstruction-purple)

# THE BUYER — Ashford Sterling Recruitment  
## Threat Hunt Analysis & DFIR Report

> Portfolio-grade Microsoft Sentinel / Log Analytics / Defender investigation report documenting a human-operated **Akira ransomware** intrusion following reused access from the prior **“The Broker”** compromise.

---

## Executive Summary

### Executive-Ready Summary

This investigation identified a **human-operated Akira ransomware intrusion** in the Ashford Sterling Recruitment environment. The evidence indicates the attacker **returned using pre-staged access** established during the prior intrusion known as **The Broker**, then progressed through a structured ransomware attack chain: remote access reuse, tool transfer, defense evasion, credential-focused activity, reconnaissance, lateral movement, exfiltration staging, and ransomware deployment.

Confirmed evidence ties the operation to **Akira**, including the ransom portal, victim ID, and encrypted file extension. The attacker leveraged **AnyDesk** for remote access, used **wsync.exe** as a beacon, performed reconnaissance with **scan.exe**, staged exfiltration with **st.exe**, and deployed ransomware via **updater**. The intrusion also included defense impairment through **kill.bat**, anti-spyware registry tampering, LSASS-oriented activity, and recovery inhibition using **`wmic shadowcopy delete`**.

At this stage, the **full host impact scope is not completely confirmed from available evidence**. Based on currently provided evidence, **as-srv** is directly implicated in the intrusion. Additional affected hosts remain **not yet determined from available evidence**.

---

### Technical Analyst Summary

The attacker reused prior access, likely from incomplete remediation after **The Broker**, and operated through **AnyDesk** associated with compromised user **David.Mitchell** and attacker IP **88.97.164.155**. Infrastructure associated with tool delivery and staging included **sync.cloud-endpoint.net** and **cdn.cloud-endpoint.net**, while **relay-0b975d23.net.anydesk.com** supported remote access operations.

The intrusion showed deliberate operator behavior:

- **Defense evasion** via **kill.bat** and registry tampering of **DisableAntiSpyware**
- **Credential-focused activity** involving **`tasklist | findstr lsass`** and **`\Device\NamedPipe\lsass`**
- **Reconnaissance** with **scan.exe**
- **Administrative pivoting** from **David.Mitchell** to **as.srv.administrator**
- **Exfiltration staging** via **st.exe** into **exfil_data.zip**
- **Ransomware deployment** through **powershell.exe** and **updater**
- **Recovery prevention** using **`wmic shadowcopy delete`**
- **Cleanup activity** via **clean.bat**

This sequence is consistent with a mature, hands-on-keyboard ransomware intrusion rather than opportunistic malware execution.

---

## Incident Overview

| Field | Value |
|---|---|
| Incident Title | **THE BUYER — Ashford Sterling Recruitment** |
| Threat Type | Human-operated ransomware |
| Ransomware Family | **Akira** |
| Environment | Microsoft Sentinel / Log Analytics / Microsoft Defender telemetry |
| Related Intrusion | **The Broker** |
| Investigation Type | Threat Hunt / DFIR |

This investigation examined a ransomware event in which the attacker returned to the environment using previously established access. The available evidence supports a deliberate intrusion path culminating in Akira ransomware deployment and ransom note creation.

---

## Scope & Environment

### Technologies Used in the Investigation

- Microsoft Sentinel
- Azure Log Analytics workspace
- Microsoft Defender telemetry
- Process telemetry
- Authentication telemetry
- Network telemetry
- File activity telemetry

### Scope Notes

This report is limited to the confirmed findings provided for the investigation. Where an artifact, host, or step is not directly confirmed, it is labeled accordingly as:

- **Unknown**
- **Not yet determined**
- **Not confirmed from available evidence**

---

## Methodology

The investigation was conducted through cross-correlation of multiple telemetry sources rather than isolated artifact review. The analytical approach included:

1. **Ransom note analysis** to attribute the intrusion to Akira
2. **Infrastructure mapping** to identify staging, delivery, and remote-access support systems
3. **Process telemetry review** to identify tooling used across the attack chain
4. **Registry and evasion analysis** to confirm defense impairment
5. **Credential access review** focused on LSASS-related activity
6. **Authentication sequence analysis** to assess account pivoting and lateral movement
7. **Network correlation using KQL** to validate reconnaissance via SMB activity
8. **Impact reconstruction** covering exfiltration staging, recovery inhibition, encryption, and cleanup

This methodology emphasized evidence discipline. No host, timestamp, domain, hash, or command was added beyond the evidence provided.

---

## Attack Timeline

| Time / Date | Event | Evidence |
|---|---|---|
| Prior to current intrusion | Attacker retained or reused access from earlier intrusion | Known context: follows **The Broker** |
| Not confirmed from available evidence | Remote access reuse via AnyDesk | AnyDesk, `C:\Users\Public\`, `88.97.164.155`, `David.Mitchell` |
| Not confirmed from available evidence | Tool delivery / payload acquisition | `sync.cloud-endpoint.net`, `bitsadmin.exe`, `Invoke-WebRequest` |
| Not confirmed from available evidence | Ransomware staging infrastructure used | `cdn.cloud-endpoint.net` |
| `21:03:42` | Registry tampering of anti-spyware setting | `DisableAntiSpyware` |
| `1/27/2026 8:18:42.600 PM` | Activity on **as-srv** involving `david.mitchell` and `lsass.exe` | Authentication sequence |
| `1/27/2026 8:18:42.601 PM` | Activity on **as-srv** involving `david.mitchell` and `10.1.0.183` | Authentication sequence |
| `1/27/2026 10:07:13.811 PM` | Activity on **as-srv** involving `as.srv.administrator`, `lsass.exe`, and `10.0.8.6` | Authentication sequence |
| `1/27/2026 10:07:15.618 PM` | Follow-on activity on **as-srv** involving `as.srv.administrator`, `lsass.exe`, `svchost.exe`, and `10.0.8.6` | Authentication sequence |
| Between `2026-01-27 20:00:00` and `2026-01-27 23:00:00` | Reconnaissance and SMB network enumeration | Correlated KQL |
| `22:18:33` | Encryption began | Confirmed finding |
| Not confirmed from available evidence | Ransom note dropped by `updater.exe` | Confirmed finding |
| Not confirmed from available evidence | Cleanup via `clean.bat` | Confirmed finding |

---

## Detailed Findings by Section

---

## Section 1 — Ransom Note Analysis

### Confirmed Findings

| Item | Value |
|---|---|
| Threat Actor | **Akira** |
| Negotiation Portal | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Victim ID | `813R-QWJM-XKIJ` |
| Encrypted Extension | `.akira` |

### Analysis

The ransom note provides the strongest attribution evidence in the case. It directly identifies the threat actor as **Akira**, provides the negotiation portal used for extortion, and assigns the unique victim ID **`813R-QWJM-XKIJ`**. The encrypted extension **`.akira`** confirms the impact behavior associated with the family.

### Why It Matters

Ransom note evidence anchors the intrusion in a named ransomware operation and establishes the attacker’s final objective: extortion through encrypted systems and negotiation.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## Section 2 — Infrastructure

### Confirmed Findings

| Item | Value |
|---|---|
| Payload Domain | `sync.cloud-endpoint.net` |
| Ransomware Staging Domain | `cdn.cloud-endpoint.net` |
| C2 IP Address | `172.67.174.46` |
| C2 IP Address | `104.21.30.237` |
| Remote Tool Relay Domain | `relay-0b975d23.net.anydesk.com` |

### Analysis

The infrastructure shows a multi-stage intrusion architecture:

- **`sync.cloud-endpoint.net`** supported payload or tool delivery
- **`cdn.cloud-endpoint.net`** supported ransomware staging
- **`172.67.174.46`** and **`104.21.30.237`** were identified as C2-related IPs
- **`relay-0b975d23.net.anydesk.com`** linked the intrusion to AnyDesk remote-access operations

This separation of functions is consistent with organized ransomware operations in which delivery, staging, beaconing, and operator access may use distinct infrastructure elements.

### Why It Matters

Infrastructure mapping supports:

- containment
- retroactive hunting
- IOC enrichment
- correlation to previous intrusion activity

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## Section 3 — Defense Evasion

### Confirmed Findings

| Item | Value |
|---|---|
| Evasion Script | `kill.bat` |
| Evasion Script Hash | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| Registry Tampering | `DisableAntiSpyware` |
| Registry Timestamp | `21:03:42` |

### Analysis

The use of **`kill.bat`** indicates deliberate defense suppression activity, likely aimed at terminating or interfering with security tools or operational processes. Registry tampering involving **`DisableAntiSpyware`** at **21:03:42** confirms active attempts to weaken host protections.

### Why It Matters

This is a classic pre-impact step in ransomware operations. Attackers frequently impair defenses before escalating activity, staging exfiltration, or launching encryption.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## Section 4 — Credential Access

### Confirmed Findings

| Item | Value |
|---|---|
| Process Hunt | `tasklist | findstr lsass` |
| Credential Pipe | `\Device\NamedPipe\lsass` |

### Analysis

The command **`tasklist | findstr lsass`** shows deliberate interest in the LSASS process, while **`\Device\NamedPipe\lsass`** supports LSASS-related activity consistent with credential-access behavior. Although the exact credential theft mechanism is not confirmed from available evidence, the artifacts strongly indicate intent to obtain or interact with credentials.

### Why It Matters

Credential access often marks the turning point between an initial foothold and enterprise-wide compromise. In this case, it is especially relevant because the intrusion later shows progression from **David.Mitchell** to **as.srv.administrator**.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## Section 5 — Initial Access

### Confirmed Findings

| Item | Value |
|---|---|
| Remote Access Tool | AnyDesk |
| Suspicious Execution Path | `C:\Users\Public\` |
| Attacker IP | `88.97.164.155` |
| Compromised User | `David.Mitchell` |

### Analysis

This intrusion did not appear to begin with a brand-new access vector inside the scope of this report. Instead, the evidence aligns with **reuse of pre-staged access** from the earlier **The Broker** intrusion. The attacker used **AnyDesk**, associated with compromised user **David.Mitchell**, suspicious path **`C:\Users\Public\`**, and attacker IP **`88.97.164.155`**.

### Why It Matters

The key lesson is not just initial compromise prevention, but **post-incident eradication**. Reused remote-access tooling indicates that persistence or residual access from the prior intrusion remained viable.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## Section 6 — Command & Control

### Confirmed Findings

| Item | Value |
|---|---|
| Primary Beacon | `wsync.exe` |
| Beacon Location | `C:\ProgramData\` |
| Original Beacon Hash | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| Replacement Beacon Hash | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |

### Analysis

The file **`wsync.exe`** in **`C:\ProgramData\`** functioned as the primary beacon. The presence of both an original and replacement hash indicates the beacon was updated, replaced, or re-delivered during the intrusion lifecycle.

### Why It Matters

C2 replacement behavior suggests an adaptive operator maintaining access despite possible operational changes, detection pressure, or tooling refresh requirements.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## Section 7 — Reconnaissance

### Confirmed Findings

| Item | Value |
|---|---|
| Scanner Tool | `scan.exe` |
| Scanner Hash | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| Scanner Execution | `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us` |
| Network Enumeration Targets | `10.1.0.154`, `10.1.0.183` |

### Analysis

The attacker used **`scan.exe`** for reconnaissance, executed in portable mode against **`C:/Users/david.mitchell/Downloads/`**. The network enumeration targets **`10.1.0.154`** and **`10.1.0.183`** were not treated as generic SMB connections; they were derived by correlating suspicious discovery-related process activity with SMB traffic on port 445 inside a constrained time window.

This is important because it raises confidence that these were relevant reconnaissance targets rather than incidental background network traffic.

### Evidence / Query Used

```kusto
let suspicious =
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00))
| where ProcessCommandLine has_any ("net view", "net use", "\\\\")
   or InitiatingProcessCommandLine has_any ("net view", "net use", "\\\\")
| project DeviceName, SuspiciousTime=Timestamp, ProcessCommandLine, InitiatingProcessCommandLine;
DeviceNetworkEvents
| where RemotePort == 445
| where RemoteIPType == "Private"
| join kind=inner suspicious on DeviceName
| where Timestamp between (SuspiciousTime - 5m .. SuspiciousTime + 5m)
| project Timestamp, DeviceName, RemoteIP, ProcessCommandLine, InitiatingProcessCommandLine
| distinct RemoteIP
