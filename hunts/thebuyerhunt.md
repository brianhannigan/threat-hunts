<p align="center">
  <img src="../assets/the_buyer_banner.svg" alt="SOC Investigation – The Buyer" width="100%" />
</p>

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2B%20MDE-blue)
![Focus](https://img.shields.io/badge/Focus-Akira%20Ransomware%20%7C%20Impact%20Reconstruction-purple)

# THE BUYER — Ashford Sterling Recruitment
## Threat Hunt Analysis & DFIR Report

> Portfolio-grade Microsoft Sentinel, Log Analytics, and Defender investigation report documenting a human-operated **Akira ransomware** intrusion that followed reused access from the prior **The Broker** compromise.

---

## Executive Summary

### Executive-Ready Summary

This hunt identified a **human-operated Akira ransomware intrusion** in the Ashford Sterling Recruitment environment. The attacker appears to have **returned using access that remained available after the earlier “The Broker” intrusion**, then progressed through a disciplined ransomware workflow: remote access reuse, tool transfer, defense evasion, credential-focused activity, reconnaissance, lateral movement, exfiltration staging, and ransomware deployment.

The strongest attribution evidence comes from the ransom note, which names **Akira**, includes the negotiation portal, assigns victim ID **`813R-QWJM-XKIJ`**, and shows the **`.akira`** encrypted file extension. Across the intrusion, the attacker used **AnyDesk** for remote access, **wsync.exe** as a beacon, **scan.exe** for discovery, **st.exe** for exfiltration staging, and **updater** for ransomware execution. The intrusion also included defense impairment via **kill.bat**, registry tampering of **`DisableAntiSpyware`**, LSASS-focused activity, and recovery inhibition through **`wmic shadowcopy delete`**.

Based on the evidence currently in scope, **`as-srv` is the only host directly confirmed as involved in the intrusion sequence**. Other systems and IP addresses appear in recon, authentication, or access telemetry, but **they cannot be conclusively labeled as compromised from the available evidence alone**.

### Technical Analyst Summary

The investigation supports a sequence in which the operator reused earlier access, likely due to incomplete eradication after **The Broker**, and operated through **AnyDesk** associated with compromised user **`David.Mitchell`** and attacker IP **`88.97.164.155`**. Infrastructure used during the intrusion included **`sync.cloud-endpoint.net`** for tool or payload delivery, **`cdn.cloud-endpoint.net`** for staging, and **`relay-0b975d23.net.anydesk.com`** for remote-access support.

Observed operator behavior included:

- **Defense evasion** via **`kill.bat`** and registry tampering of **`DisableAntiSpyware`**
- **Credential-focused activity** involving **`tasklist | findstr lsass`** and **`\Device\NamedPipe\lsass`**
- **Reconnaissance** using **`scan.exe`** with correlated SMB activity
- **Administrative pivoting** from **`David.Mitchell`** to **`as.srv.administrator`**
- **Exfiltration staging** through **`st.exe`** into **`exfil_data.zip`**
- **Ransomware execution** via **`powershell.exe`** and **`updater`**
- **Recovery prevention** using **`wmic shadowcopy delete`**
- **Cleanup / anti-forensics** via **`clean.bat`**

Taken together, the evidence is consistent with a mature, hands-on-keyboard ransomware intrusion rather than opportunistic malware execution.

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

This investigation examined a ransomware event in which the attacker returned to the environment using previously established access. Available telemetry supports a deliberate intrusion path that culminated in Akira ransomware deployment and ransom note creation.

---

## Scope & Environment

### Telemetry Used

- Microsoft Sentinel
- Azure Log Analytics workspace
- Microsoft Defender telemetry
- Process telemetry
- Authentication telemetry
- Network telemetry
- File activity telemetry

### Scope Notes

This report is intentionally limited to the findings confirmed by the evidence provided for the hunt. Where an artifact, host, timestamp, or attack step is not directly supported, it is labeled as one of the following:

- **Unknown**
- **Not yet determined**
- **Not confirmed from available evidence**

---

## Methodology

The hunt was built through **cross-correlation of multiple telemetry sources**, not through isolated review of individual artifacts. The analytical workflow included:

1. **Ransom note analysis** to attribute the event to Akira.
2. **Infrastructure mapping** to identify delivery, staging, and remote-access support systems.
3. **Process telemetry review** to identify the attacker’s tooling across the intrusion.
4. **Registry and evasion analysis** to confirm attempts to weaken host defenses.
5. **Credential-access review** focused on LSASS-related activity.
6. **Authentication sequence analysis** to assess account pivoting and lateral movement.
7. **Network correlation with KQL** to validate reconnaissance through SMB activity.
8. **Impact reconstruction** covering exfiltration staging, recovery inhibition, encryption, and cleanup.

This methodology prioritized evidence discipline. No host, domain, hash, timestamp, or command is presented here unless it was provided in the source material for the hunt.

---

## Attack Timeline

| Time / Date | Event | Evidence |
|---|---|---|
| Prior to current intrusion | Attacker retained or reused access from earlier intrusion | Hunt context links activity to **The Broker** |
| Not confirmed from available evidence | Remote access reuse via AnyDesk | **AnyDesk**, `C:\Users\Public\`, `88.97.164.155`, `David.Mitchell` |
| Not confirmed from available evidence | Tool delivery / payload acquisition | `sync.cloud-endpoint.net`, `bitsadmin.exe`, `Invoke-WebRequest` |
| Not confirmed from available evidence | Ransomware staging infrastructure used | `cdn.cloud-endpoint.net` |
| `21:03:42` | Registry tampering of anti-spyware setting | `DisableAntiSpyware` |
| `2026-01-27 20:18:42.600` | Authentication-related activity on **as-srv** involving `david.mitchell` and `lsass.exe` | Authentication sequence |
| `2026-01-27 20:18:42.601` | Authentication-related activity on **as-srv** involving `david.mitchell` and `10.1.0.183` | Authentication sequence |
| `2026-01-27 22:07:13.811` | Authentication-related activity on **as-srv** involving `as.srv.administrator`, `lsass.exe`, and `10.0.8.6` | Authentication sequence |
| `2026-01-27 22:07:15.618` | Follow-on activity on **as-srv** involving `as.srv.administrator`, `lsass.exe`, `svchost.exe`, and `10.0.8.6` | Authentication sequence |
| Between `2026-01-27 20:00:00` and `2026-01-27 23:00:00` | Reconnaissance and SMB network enumeration | Correlated KQL |
| `22:18:33` | Encryption began | Confirmed finding |
| Not confirmed from available evidence | Ransom note dropped by `updater.exe` | Confirmed finding |
| Not confirmed from available evidence | Cleanup via `clean.bat` | Confirmed finding |

---

## Detailed Findings

## 1) Ransom Note Analysis

### Confirmed Findings

| Item | Value |
|---|---|
| Threat Actor | **Akira** |
| Negotiation Portal | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Victim ID | `813R-QWJM-XKIJ` |
| Encrypted Extension | `.akira` |

### Analysis

The ransom note provides the strongest attribution evidence in the case. It directly names **Akira**, includes the extortion portal used for negotiation, and assigns a unique victim identifier. The **`.akira`** extension confirms the expected impact behavior associated with the family.

### Why It Matters

This section anchors the intrusion to a named ransomware operation and confirms that the attacker’s final objective was extortion through encryption and negotiation.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 2) Infrastructure

### Confirmed Findings

| Item | Value |
|---|---|
| Payload Domain | `sync.cloud-endpoint.net` |
| Ransomware Staging Domain | `cdn.cloud-endpoint.net` |
| C2 IP Address | `172.67.174.46` |
| C2 IP Address | `104.21.30.237` |
| Remote Tool Relay Domain | `relay-0b975d23.net.anydesk.com` |

### Analysis

The infrastructure reflects a multi-stage intrusion architecture:

- **`sync.cloud-endpoint.net`** supported payload or tool delivery.
- **`cdn.cloud-endpoint.net`** supported ransomware staging.
- **`172.67.174.46`** and **`104.21.30.237`** were identified as C2-related IPs.
- **`relay-0b975d23.net.anydesk.com`** links the intrusion to AnyDesk remote-access activity.

This separation of delivery, staging, and operator-access infrastructure is consistent with organized ransomware tradecraft.

### Why It Matters

Infrastructure mapping supports containment, IOC expansion, retroactive hunting, and correlation with earlier intrusion activity.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 3) Defense Evasion

### Confirmed Findings

| Item | Value |
|---|---|
| Evasion Script | `kill.bat` |
| Evasion Script Hash | `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c` |
| Registry Tampering | `DisableAntiSpyware` |
| Registry Timestamp | `21:03:42` |

### Analysis

The use of **`kill.bat`** indicates deliberate defense suppression, likely aimed at terminating or impairing security tooling or security-relevant processes. Registry tampering involving **`DisableAntiSpyware`** at **21:03:42** confirms active efforts to weaken host protections before later stages of the attack.

### Why It Matters

Defense impairment is a classic pre-impact ransomware step. Attackers often reduce visibility and resistance before they escalate privileges, stage data, or launch encryption.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 4) Credential Access

### Confirmed Findings

| Item | Value |
|---|---|
| Process Hunt | `tasklist | findstr lsass` |
| Credential Pipe | `\Device\NamedPipe\lsass` |

### Analysis

The command **`tasklist | findstr lsass`** shows deliberate interest in the LSASS process, while **`\Device\NamedPipe\lsass`** supports LSASS-related activity that is consistent with credential-access behavior. The exact theft mechanism is not confirmed, but the artifacts strongly indicate intent to obtain, inspect, or interact with credential material.

### Why It Matters

Credential access often marks the point where an initial foothold can expand into privileged control. In this hunt, it is especially important because the intrusion later progresses from **`David.Mitchell`** to **`as.srv.administrator`**.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 5) Initial Access / Access Reuse

### Confirmed Findings

| Item | Value |
|---|---|
| Remote Access Tool | AnyDesk |
| Suspicious Execution Path | `C:\Users\Public\` |
| Attacker IP | `88.97.164.155` |
| Compromised User | `David.Mitchell` |

### Analysis

Within the scope of this report, the intrusion does not appear to begin with a brand-new access vector. Instead, the evidence aligns with **reuse of pre-staged access** from the earlier **The Broker** intrusion. The attacker operated through **AnyDesk**, associated with compromised user **`David.Mitchell`**, suspicious execution path **`C:\Users\Public\`**, and attacker IP **`88.97.164.155`**.

### Why It Matters

The key lesson is not only initial compromise prevention, but also **complete post-incident eradication**. Reused remote-access tooling indicates that persistence or residual access from the prior incident remained viable.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 6) Command and Control

### Confirmed Findings

| Item | Value |
|---|---|
| Primary Beacon | `wsync.exe` |
| Beacon Location | `C:\ProgramData\` |
| Original Beacon Hash | `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b` |
| Replacement Beacon Hash | `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654` |

### Analysis

The file **`wsync.exe`** in **`C:\ProgramData\`** functioned as the primary beacon. The presence of both an original and replacement hash suggests the beacon was updated, replaced, or re-delivered during the intrusion.

### Why It Matters

Beacon replacement suggests an adaptive operator maintaining access despite operational changes, detection pressure, or tooling refresh requirements.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 7) Reconnaissance

### Confirmed Findings

| Item | Value |
|---|---|
| Scanner Tool | `scan.exe` |
| Scanner Hash | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| Scanner Execution | `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us` |
| Network Enumeration Targets | `10.1.0.154`, `10.1.0.183` |

### Analysis

The attacker used **`scan.exe`** for reconnaissance, executed in portable mode against **`C:/Users/david.mitchell/Downloads/`**. The network enumeration targets **`10.1.0.154`** and **`10.1.0.183`** were not treated as generic SMB connections; they were identified by correlating suspicious discovery-related process activity with SMB traffic on port 445 inside a constrained time window.

That correlation materially increases confidence that these systems were relevant discovery targets rather than incidental background network traffic.

### Why It Matters

Reconnaissance identifies reachable systems, administrative opportunities, and likely candidates for later movement or impact.

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
```

---

## 8) Lateral Movement

### Confirmed Findings

| Item | Value |
|---|---|
| Lateral Movement Account | `as.srv.administrator` |

### Authentication Sequence Observed

- `2026-01-27 20:18:42.600 — as-srv — david.mitchell — lsass.exe`
- `2026-01-27 20:18:42.601 — as-srv — david.mitchell — 10.1.0.183`
- `2026-01-27 20:18:42.601 — as-srv — david.mitchell — 10.1.0.183`
- `2026-01-27 22:07:13.811 — as-srv — as.srv.administrator — lsass.exe`
- `2026-01-27 22:07:13.811 — as-srv — as.srv.administrator — 10.0.8.6`
- `2026-01-27 22:07:15.618 — as-srv — as.srv.administrator — lsass.exe`
- `2026-01-27 22:07:15.618 — as-srv — as.srv.administrator — svchost.exe — 10.0.8.6`

### Assessment

#### Confirmed

- **`David.Mitchell`** was the compromised user in the early phase of activity.
- LSASS-oriented activity occurred during the intrusion.
- Later authentication activity on **`as-srv`** involved **`as.srv.administrator`**.
- The sequence shows progression from a user context to an administrative account context.

#### Inferred from Sequence and Timing

- The attacker likely used credential-access activity to support the pivot.
- The LSASS-related artifacts provide a plausible bridge between the two account contexts.
- The appearance of **`as.srv.administrator`** later in the chain is consistent with successful privilege escalation or credentialed lateral movement.

#### Not Confirmed from Available Evidence

- The exact method used to obtain or use **`as.srv.administrator`**.
- Whether credentials were dumped, replayed, reused, or otherwise acquired.

### Host Assessment from Current Evidence

Based on the evidence currently provided:

- **Confirmed involved host:** `as-srv`
- **Likely recon / access-related internal IP targets:** `10.1.0.154`, `10.1.0.183`
- **Related authentication source / system indicator:** `10.0.8.6`

These IPs show relevant interaction, but **they cannot be conclusively labeled as fully compromised hosts from the available evidence alone**.

### Why It Matters

Lateral movement into an administrative account is the moment when a localized compromise can become an enterprise-level incident.

### Evidence / Query Used

Authentication sequence above; no additional KQL was explicitly provided for this section.

---

## 9) Tool Transfer

### Confirmed Findings

| Item | Value |
|---|---|
| Download Method | `bitsadmin.exe` |
| Fallback Method | `Invoke-WebRequest` |

### Analysis

The attacker used native Windows transfer mechanisms to deliver tooling. **`bitsadmin.exe`** is a common living-off-the-land technique, while **`Invoke-WebRequest`** provided a fallback if the primary method was unsuitable or blocked.

### Why It Matters

Native utilities reduce operational friction and can make attacker behavior blend into legitimate administrative activity unless those tools are tightly monitored.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 10) Exfiltration

### Confirmed Findings

| Item | Value |
|---|---|
| Staging Tool | `st.exe` |
| Staging Hash | `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015` |
| Exfil Archive | `exfil_data.zip` |

### Analysis

The use of **`st.exe`** to produce **`exfil_data.zip`** indicates data staging prior to ransomware impact. This aligns with double-extortion behavior, where data theft or theft preparation is used to increase leverage during ransom negotiations.

### Why It Matters

Even when encryption is the most visible effect, exfiltration staging introduces confidentiality risk and should be treated as a potential data-breach element of the incident.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 11) Ransomware Deployment

### Confirmed Findings

| Item | Value |
|---|---|
| Ransomware Filename | `updater` |
| Ransomware Hash | `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b` |
| Ransomware Staging | `powershell.exe` |
| Recovery Prevention | `wmic shadowcopy delete` |
| Ransom Note Origin | `updater.exe` |
| Encryption Start | `22:18:33` |

### Analysis

The final impact stage involved operator-controlled ransomware launch. **`powershell.exe`** staged the ransomware identified as **`updater`**, and **`updater.exe`** was the process that dropped the ransom note. The command **`wmic shadowcopy delete`** shows deliberate removal of shadow copies to reduce recovery options before or during encryption.

Encryption began at **22:18:33**, marking the transition from preparation and access operations to direct business impact.

### Why It Matters

This phase confirms that the attacker reached final objective execution: encrypting systems, impairing recovery, and initiating ransom pressure.

### Evidence / Query Used

Not explicitly provided beyond the confirmed findings.

---

## 12) Anti-Forensics & Scope

### Confirmed Findings

| Item | Value |
|---|---|
| Cleanup Script | `clean.bat` |
| Affected Hosts | Not yet determined from available evidence |

### Analysis

The batch file **`clean.bat`** indicates likely cleanup or anti-forensic activity. Its exact contents are not confirmed from available evidence, but its role in the attack chain suggests post-execution artifact removal or trace suppression.

### Current Host Scope Assessment

#### Confirmed from Available Evidence

- **`as-srv`** is directly involved in the intrusion sequence.

#### Related but Not Fully Confirmed as Compromised

- `10.1.0.154`
- `10.1.0.183`
- `10.0.8.6`

#### Unresolved

- Full list of impacted or encrypted hosts.
- Whether all internal IPs observed in recon or authentication telemetry were ultimately compromised.
- Whether additional servers or workstations were affected.

### Why It Matters

Cleanup activity reduces forensic visibility and can hide the full extent of the intrusion. The unresolved host scope means containment and recovery would require additional validation.

---

## Key Judgments

### High-Confidence Judgments

- The intrusion is attributable to **Akira** based on direct ransom note evidence.
- The attacker reused pre-staged access associated with the earlier **The Broker** intrusion.
- The intrusion followed a coherent ransomware sequence: access, staging, defense evasion, credential-focused activity, reconnaissance, lateral movement, exfiltration staging, ransomware deployment, and cleanup.
- **`as-srv`** is directly confirmed as involved in the intrusion.

### Moderate-Confidence Judgments

- LSASS-related activity likely supported the transition from **`David.Mitchell`** to **`as.srv.administrator`**.
- Beacon replacement suggests tooling refresh or adaptive C2 maintenance during the intrusion.
- Exfiltration staging likely supported double-extortion objectives.

### Not Confirmed from Available Evidence

- The exact method used to obtain **`as.srv.administrator`** access.
- The exact behavior or contents of **`kill.bat`** and **`clean.bat`**.
- The final outbound exfiltration destination.
- Whether **`10.1.0.154`**, **`10.1.0.183`**, or **`10.0.8.6`** were fully compromised.
- The full list of affected hosts.

---

## Portfolio / Interview Talking Points

This hunt demonstrates the ability to:

- perform structured threat hunting across **Microsoft Sentinel**, **Log Analytics**, and **Defender telemetry**
- distinguish **confirmed evidence** from **analytical inference**
- reconstruct a complete ransomware intrusion chain
- correlate process, authentication, and network telemetry to validate attacker progression
- analyze credential-access indicators and administrative pivoting
- document findings in a portfolio-grade, SOC-ready DFIR format
- communicate clearly to both technical and leadership audiences

---

## Conclusion

The available evidence supports a clear assessment: **The Buyer** was a **human-operated Akira ransomware intrusion** enabled by reused access from a prior compromise. The attacker leveraged remote access, staged and refreshed tooling, impaired defenses, targeted credentials, moved laterally into an administrative context, prepared data for theft, and then launched ransomware while inhibiting recovery.

### Best Current Answer on Compromised Hosts

Based strictly on the evidence provided:

#### Confirmed involved / compromised host

- **`as-srv`**

#### Additional systems observed in relevant attack activity, but not fully confirmable as compromised from current evidence

- `10.1.0.154`
- `10.1.0.183`
- `10.0.8.6`

#### Final scope status

- **Affected hosts: Not yet determined from available evidence**

That is the most defensible host assessment from the evidence currently in scope.

---

## Appendix — KQL Query Used

### Reconnaissance / SMB Correlation Query

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
```

### Additional Queries

Additional KQL used in the broader investigation was **not explicitly provided in the available evidence**.
