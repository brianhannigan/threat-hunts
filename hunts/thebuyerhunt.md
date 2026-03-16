<p align="center">
  <img src="../assets/the_buyer_banner.svg" alt="SOC Investigation – The Buyer" width="100%" />
</p>

# Threat Hunt Report: The Buyer
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2B%20MDE-blue)
![Focus](https://img.shields.io/badge/Focus-Akira%20Ransomware%20%7C%20Impact%20Reconstruction-purple)

> **What happened?**  
> Following the initial compromise investigated in **The Broker**, a ransomware affiliate returned to the environment using **pre-staged access** and deployed **Akira ransomware** across the network.  
> This hunt works **backwards from impact**, starting from Defender tampering and recovery-destruction activity on `AS-PC2`, then reconstructs the attack chain across related systems and prior intrusion artifacts.

---

## Hunt Context

**Difficulty:** Advanced

This investigation is a continuation of **The Broker**. The earlier intrusion established access, persistence, and lateral movement pathways. In **The Buyer**, the threat actor returns and transitions from intrusion and staging to **ransomware execution preparation and impact**.

This hunt is harder than The Broker because it requires:

- working backwards from impact
- tracking activity across multiple hosts
- correlating infrastructure and access paths from the first investigation
- using previously identified IOCs and account activity to validate follow-on attacker behavior

---

## Quick Answers (CTF Flags / Findings)

### Confirmed Flag
- **FLAG-004 (Impact):** Shadow copy deletion
- **Technique:** Recovery inhibition / ransomware preparation
- **Host:** `AS-PC2`
- **Account:** `David.Mitchell`
- **Timestamp:** `2026-01-27 16:03:49`

### Related Indicators from the Same Attack Chain
- **FLAG-001 (Defense Evasion):** Defender disabled via PowerShell tampering
- **FLAG-002 (Discovery):** Advanced IP Scanner execution
- **FLAG-003 (Credential Access):** LSASS memory access

---

## Executive Summary

The investigation confirms a **high-confidence, hands-on-keyboard ransomware intrusion** centered on `AS-PC2` under the user context `David.Mitchell`.

Observed activity shows a clear transition from attacker-controlled exploration and credential access to ransomware-enablement actions, including:

- network discovery
- process discovery
- LSASS memory access
- Microsoft Defender tampering
- shadow copy deletion

This sequence is consistent with **Akira ransomware pre-encryption staging** and indicates the actor returned with already established knowledge and access from the earlier **Broker** intrusion.

- **Compromise Likelihood:** **HIGH**
- **Risk Level:** **CRITICAL**
- **Business Impact:** Loss of recovery options, increased likelihood of encryption, and elevated risk of multi-host compromise

---

## Threat Hypothesis

If a ransomware affiliate has returned to the environment using access established during **The Broker**, telemetry should show:

1. re-use of previously compromised accounts or paths
2. discovery activity on already reached hosts
3. credential access or privilege validation
4. security-control tampering
5. recovery inhibition and impact preparation

The observed evidence validated this hypothesis.

---

## Scope & Data Sources

### Investigated Assets
- `AS-PC2` (primary impact host)
- additional peer systems should be reviewed for related activity

### Primary User Context
- `David.Mitchell`

### Data Sources Referenced
- Microsoft Defender for Endpoint alert telemetry
- Endpoint process telemetry
- Defender tamper indicators
- Credential access alerts
- Timeline reconstruction artifacts

### Known Data Gaps
- no confirmed network flow visibility in this report
- no confirmed Entra ID sign-in trail included in this page
- no confirmed mail telemetry included in this page

---

## Timeline of Confirmed Activity

| Time | Event | Host | Account | Assessment |
|---|---|---|---|---|
| 1:29 PM | Suspicious `svchost.exe` / `wsync.exe` behavior | AS-PC2 | David.Mitchell | Early compromise / staging signal |
| 3:17 PM | `powershell.exe` remote execution observed | AS-PC2 | David.Mitchell | Hands-on-keyboard activity |
| 3:17 PM | `scan.exe` created | AS-PC2 | David.Mitchell | Tool staging |
| 3:17 PM | Advanced IP Scanner executed | AS-PC2 | David.Mitchell | Internal discovery |
| 3:22 PM | `wsync.exe` created | AS-PC2 | David.Mitchell | Additional staging / tooling |
| 3:23 PM | PowerShell-based process discovery | AS-PC2 | David.Mitchell | Discovery |
| 3:45 PM | LSASS memory access detected | AS-PC2 | David.Mitchell | Credential dumping |
| 4:03 PM | `kill.bat` executed via `cmd.exe` | AS-PC2 | David.Mitchell | Attack preparation |
| 4:03 PM | Defender protections disabled | AS-PC2 | David.Mitchell | Defense evasion |
| 4:03 PM | `reg.exe` set `DisableAntiSpyware=1` | AS-PC2 | David.Mitchell | Defender tampering |
| 4:03 PM | Volume shadow copies deleted | AS-PC2 | David.Mitchell | Impact preparation / recovery inhibition |

---

## Indicator Matrix

| Flag | Tactic | Indicator | System | Notes |
|---|---|---|---|---|
| FLAG-001 | Defense Evasion | `Set-MpPreference` abuse | AS-PC2 | Real-time, behavior, and IOAV protections disabled |
| FLAG-002 | Discovery | Advanced IP Scanner | AS-PC2 | Network reconnaissance |
| FLAG-003 | Credential Access | LSASS memory read | AS-PC2 | Credential theft |
| FLAG-004 | Impact | Shadow copy deletion | AS-PC2 | Recovery inhibition prior to ransomware |

---

## Systems Impacted

| System | Type | Owner | Suspicious Activity |
|---|---|---|---|
| AS-PC2 | Windows 10 | David.Mitchell | Discovery, credential access, Defender tampering, shadow copy deletion |

---

## Investigation Notes

This hunt should be documented as a **follow-on ransomware phase** rather than a standalone compromise. The earlier attacker activity from **The Broker** established the access and movement patterns that make the later activity in **The Buyer** more understandable.

Key analytic point:

- **The Broker** explains **how the attacker got in and moved around**
- **The Buyer** explains **how the attacker returned and prepared to detonate ransomware**

That linkage should be explicit in the documentation.

---

## Detection & Hunt Queries

### Defender Tampering

```kusto
DeviceProcessEvents
| where DeviceName == "AS-PC2"
| where FileName in~ ("powershell.exe","cmd.exe","reg.exe")
| where ProcessCommandLine contains "Set-MpPreference"
   or ProcessCommandLine contains "DisableAntiSpyware"
   or ProcessCommandLine contains "DisableRealtimeMonitoring"
   or ProcessCommandLine contains "DisableBehaviorMonitoring"
   or ProcessCommandLine contains "DisableIOAVProtection"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### Discovery / Scanner Execution

```kusto
DeviceProcessEvents
| where DeviceName == "AS-PC2"
| where ProcessCommandLine has_any ("AdvancedIpScanner", "scan.exe", "whoami", "net view")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### LSASS Access

```kusto
DeviceEvents
| where DeviceName == "AS-PC2"
| where ActionType has_any ("ReadLsassMemory", "CredentialTheft", "ProcessAccessed")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
```

### Shadow Copy Deletion

```kusto
DeviceProcessEvents
| where DeviceName == "AS-PC2"
| where ProcessCommandLine has_any ("vssadmin", "delete shadows", "wmic shadowcopy delete")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### Account Reuse / Lateral Movement Validation

```kusto
DeviceLogonEvents
| where AccountName =~ "David.Mitchell"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, InitiatingProcessFileName
| order by Timestamp asc
```

## Data Gaps

| Missing Telemetry | Investigative Impact |
|---|---|
| Network flow logs | Unable to fully confirm lateral movement path and east-west spread |
| Entra ID / Azure AD sign-in telemetry | Cannot fully validate cloud-side access reuse or sign-in anomalies |
| Email telemetry | Cannot confirm whether a fresh phishing or lure event occurred |
| Full cross-host timeline | Limits definitive blast-radius reconstruction |

---

## Recommended Remediation

### Immediate Containment

- Disable compromised account: `David.Mitchell`
- Isolate endpoint: `AS-PC2`
- Re-enable and enforce Defender protections
- Reset all potentially exposed credentials
- Hunt for activity on peer systems and servers
- Review whether persistence from **The Broker** remained active
- Validate whether Akira artifacts executed or only staged

### Detection Engineering Improvements

- Create detections for `Set-MpPreference` abuse
- Create detections for `DisableAntiSpyware`
- Create detections for shadow copy deletion
- Create detections for suspicious scanner execution from user workstations


### Logging Improvements

- Ensure complete Defender Advanced Hunting coverage
- Expand Entra ID / Azure AD logging
- Add east-west network visibility
- Preserve case notes and IOC handoff between related hunts

---

## Final Assessment

The intrusion on `AS-PC2` is best assessed as a human-operated ransomware operation in a pre-encryption, impact-preparation stage.

Observed phases map to:

- Re-entry using previously staged access
- Discovery
- Credential access
- Defense evasion
- Impact preparation

This hunt should explicitly be treated as the ransomware continuation of **The Broker**, not as an isolated incident.

Immediate containment and enterprise-wide scoping are required.

---

## Broker Quick Reference (Carry-Forward Notes)

Use this section for fast correlation while working **The Buyer**.

### Initial Access / Payload

- Fake resume payload: `daniel_richardson_cv.pdf.exe`
- Payload SHA256: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`
- Parent process: `explorer.exe`
- Decoy process: `notepad.exe`

### C2 / Staging Infrastructure

- C2 domain: `cdn.cloud-endpoint.net`
- Staging domain: `sync.cloud-endpoint.net`

### Credential Access / Local Staging

- Registry hives targeted: `SAM`, `SYSTEM`
- Local staging path: `C:\Users\Public`
- Execution identity seen earlier: `sophie.turner`

### Persistence / Remote Access

- Remote tool installed: `AnyDesk`
- AnyDesk SHA256: `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`
- AnyDesk unattended password: `intrud3r!`
- Scheduled task: `MicrosoftEdgeUpdateCheck`
- Renamed binary: `RuntimeBroker.exe`
- Backdoor account: `svc_backup`

### Lateral Movement Notes

- Failed remote tools: `wmic.exe`, `PsExec.exe`
- Successful movement tool: `mstsc.exe`
- Movement path: `as-pc1 > as-pc2 > as-srv`
- Compromised account used: `david.mitchell`
- Account activation parameter: `active:yes`

### Data Access / Collection

- Sensitive file: `BACS_Payments_Dec2025.ods`
- Editing artifact: `.~lock.BACS_Payments_Dec2025.ods#`
- Archive created: `Shares.7z`
- Archive SHA256: `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

### Anti-Forensics / Memory

- Logs cleared: `System`, `Application`
- Memory-only action type: `ClrUnbackedModuleLoaded`
- Tool observed: `SharpChrome`
- Injected process: `notepad.exe`

### Why This Matters for The Buyer

These Broker notes explain how the attacker likely retained the access and host familiarity needed to return later and perform ransomware staging on `AS-PC2`.




# Infrastructure Investigation Checklist — *The Buyer*

This section documents the investigation process used to identify attacker infrastructure associated with the **ransomware deployment phase** of the intrusion.

The investigation required correlating information from multiple sources:

- Microsoft Defender incident artifacts
- Infrastructure identified during **The Broker**
- External DNS resolution of attacker domains
- Elimination of incorrect infrastructure hypotheses

---

# Q5 — Payload Download Domain

## Objective

Identify the domain used by the attacker to host or deliver malicious tooling.

## Evidence Sources

- Defender incident artifacts
- **The Broker** investigation notes

## Confirmed Indicator

```
sync.cloud-endpoint.net
```

## What Worked

- Cross-referencing infrastructure reused from **The Broker**
- Identifying the **cloud-endpoint.net infrastructure cluster**
- Validating the domain against the Broker IOC list

## What Did Not Work

- Hunting Defender Advanced Hunting tables (telemetry not populated)
- Searching incident process command lines

## Notes

This domain hosted malicious tooling used during the intrusion.

---

# Q6 — Ransomware Staging / C2 Domain

## Objective

Identify the infrastructure used by the attacker to stage or coordinate the ransomware deployment.

## Confirmed Indicator

```
cdn.cloud-endpoint.net
```

## What Worked

- Recognizing infrastructure reuse from **The Broker**
- Identifying the second domain within the same attacker-controlled cluster

## What Did Not Work

- Searching incident telemetry tables
- Extracting command-line network indicators from process artifacts

## Notes

Attackers commonly separate infrastructure roles.

| Function | Domain |
|--------|--------|
| Payload Hosting | `sync.cloud-endpoint.net` |
| C2 / Staging | `cdn.cloud-endpoint.net` |

---

# Q7 — Command-and-Control IP Addresses

## Objective

Determine the IP infrastructure supporting the C2 domain.

## Method Used

DNS resolution of the attacker domain.

### Command Used

```bash
nslookup -type=A cdn.cloud-endpoint.net 1.1.1.1
```

## Confirmed IP Addresses

```
172.67.174.46
104.21.30.237
```

## What Worked

- External DNS resolution of the attacker domain

## What Did Not Work

- Attempting to extract IP addresses from Defender incident artifacts
- Checking internal IP telemetry (only private addresses were present)

## Notes

The domain is protected by **Cloudflare**, which explains the presence of CDN edge IP addresses.

---

# Q8 — Remote Tool Relay Domain

## Objective

Identify the relay infrastructure used by the attacker’s remote access tooling.

## Evidence From The Broker

Remote tool installed during the earlier intrusion phase:

```
AnyDesk
```

However, the specific relay hostname used by the attacker session was **not exposed directly in the Defender incident artifacts**.

---

## Investigation Attempts

The following domains were tested but rejected.

| Attempted Domain | Result |
|-----------------|--------|
| relay.anydesk.com | ❌ Incorrect |
| net.anydesk.com | ❌ Incorrect |
| *.net.anydesk.com | ❌ Incorrect |
| boot.net.anydesk.com | ❌ Incorrect |
| boot-relays.net.anydesk.com | ❌ Incorrect |

---

## Observations

- **AnyDesk was confirmed on the compromised host**
- Incident artifacts did not expose the exact relay hostname
- Defender telemetry tables were not populated for this hunt

---

## Current Status

⚠️ **Unresolved**

Further confirmation will likely require:

- Additional infrastructure notes from **The Broker**
- Additional IOC documentation
- Network telemetry not available in this investigation environment

---

# Telemetry Limitations Observed

Several Defender Advanced Hunting tables returned **no relevant data** during the investigation.

| Table | Result |
|------|--------|
| DeviceNetworkEvents | Empty |
| DeviceProcessEvents | Empty |
| AlertInfo | Empty |
| AlertEvidence | Empty |
| CloudAppEvents | Empty |

---

# Investigation Impact

This limitation prevented direct extraction of:

- Network connections
- Remote domains
- Attacker infrastructure indicators from telemetry

The investigation therefore relied on:

- Artifact correlation
- Previously identified IOCs
- Infrastructure clustering

---

# Infrastructure Cluster Identified

The attacker reused a small infrastructure cluster.

| Purpose | Indicator |
|-------|-----------|
| Payload Hosting | `sync.cloud-endpoint.net` |
| C2 / Staging | `cdn.cloud-endpoint.net` |
| C2 IPs | `172.67.174.46`, `104.21.30.237` |

---

# Key Investigation Lesson

**The Buyer investigation demonstrates an important threat hunting principle:**

> When telemetry is limited, infrastructure correlation across related incidents  
> (**The Broker → The Buyer**) can reveal attacker patterns and reused infrastructure.

This linkage allowed the **ransomware phase** to be reconstructed despite missing network logs.

---

*Investigation Status: In Progress*



# SOC Investigation Case Study – The Buyer

## 1. Investigation Summary

**Investigation Name:** The Buyer  
**Platform:** Microsoft Defender for Endpoint  
**Related Hunt:** The Broker  
**Threat Type:** Human-operated ransomware  
**Ransomware Family:** Akira  
**Primary Impact Host:** `AS-PC2`  
**Compromised Account:** `David.Mitchell`

### Executive Summary
The Buyer investigation focused on reconstructing a human-operated ransomware intrusion culminating in Akira ransomware deployment activity on `AS-PC2`. This hunt built on infrastructure, access patterns, and attacker tradecraft previously identified in **The Broker**, and worked backward from impact indicators to identify the attacker’s staging domains, tooling, discovery activity, credential access behavior, and defense evasion actions.

The investigation confirmed that the threat actor used remote access and administrative tooling, performed internal reconnaissance, accessed LSASS memory, tampered with Microsoft Defender protections, and executed destructive actions consistent with ransomware pre-encryption preparation, including shadow copy deletion. Confirmed attacker-controlled infrastructure included `sync.cloud-endpoint.net` for payload delivery and `cdn.cloud-endpoint.net` for staging/C2-related activity, resolving to `172.67.174.46` and `104.21.30.237`.

Although the investigation successfully reconstructed major portions of the attack chain, several telemetry gaps limited full end-to-end validation, particularly the absence of complete network flow visibility, incomplete Advanced Hunting telemetry, lack of Entra ID sign-in correlation, and no mail telemetry to assess earlier delivery or access vectors.

---

## 2. What We Did

The following steps summarize the investigation process used during The Buyer hunt.

### Step 1 – Established Hunt Scope
We defined the objective as reconstructing the ransomware deployment phase associated with Akira activity, with emphasis on:
- attacker infrastructure
- confirmed tooling
- affected systems
- account usage
- pre-impact and impact behaviors
- relationship to artifacts previously identified in **The Broker**

### Step 2 – Started from Impact on AS-PC2
We pivoted first from the impact host `AS-PC2`, focusing on behaviors commonly associated with ransomware execution:
- Defender tampering
- destructive recovery inhibition
- suspicious batch/script execution
- payload execution artifacts
- evidence of process and system discovery

This backward-from-impact approach was necessary because ransomware telemetry often becomes clearest near execution and defense evasion stages.

### Step 3 – Correlated Activity with Known User Context
We associated suspicious activity with the compromised account `David.Mitchell` and used that account context to determine whether the attacker actions were interactive, staged, or likely operator-driven rather than commodity malware alone.

### Step 4 – Identified and Validated Attacker Tooling
We confirmed attacker use of the following tools and binaries:
- `AnyDesk`
- `Advanced IP Scanner`
- `scan.exe`
- `PowerShell`
- `wsync.exe`
- `kill.bat`

These tools were reviewed in the context of likely ransomware operator objectives:
- remote access
- host and network enumeration
- credential access
- security control impairment
- payload staging and execution

### Step 5 – Investigated Infrastructure Reuse
We cross-referenced infrastructure from **The Broker** and validated reuse of the `cloud-endpoint.net` cluster:
- `sync.cloud-endpoint.net`
- `cdn.cloud-endpoint.net`

This was a key pivot because direct hunting inside some Defender tables was incomplete or unavailable.

### Step 6 – Reconstructed Host-Level Behaviors
We documented the following confirmed attacker behaviors:
- network discovery
- process discovery
- LSASS memory access
- Defender tampering
- shadow copy deletion

These actions strongly aligned with late-stage ransomware operations and helped distinguish this intrusion from lower-fidelity suspicious activity.

### Step 7 – Distinguished Confirmed Findings from Gaps
We separated:
- what was directly observed
- what was inferred from related evidence
- what could not be confirmed because of telemetry limitations

This was important to keep the report publishable, defensible, and professional.

---

## 3. What Worked

The following investigative methods produced useful results.

### Successful Investigation Techniques

| Technique | Result | Why It Worked |
|---|---|---|
| Starting from the impact host (`AS-PC2`) | Helped anchor the investigation in confirmed ransomware-related activity | Impact-stage behaviors were the highest-confidence evidence available |
| Working backward from Defender tampering and shadow copy deletion | Helped identify pre-encryption preparation activity | These are strong, high-signal ransomware behaviors |
| Correlating with prior hunt findings from **The Broker** | Confirmed infrastructure reuse and improved confidence | The actor reused related infrastructure, enabling cross-hunt validation |
| Tool-based analysis of binaries and utilities | Helped reconstruct attacker objectives | The toolset clearly aligned to discovery, access, and execution phases |
| Domain-based infrastructure pivoting | Confirmed staging and payload delivery infrastructure | Direct telemetry gaps were partially overcome by IOC reuse and domain analysis |
| Behavior clustering rather than relying on a single alert | Produced a stronger narrative of intrusion activity | Multiple lower-level actions combined into a coherent ransomware sequence |

### Why These Techniques Were Effective
The most successful parts of the investigation came from combining:
1. high-confidence impact behaviors,
2. cross-host/cross-hunt IOC correlation,
3. attacker tradecraft analysis,
4. and host-level evidence reconstruction.

This allowed the investigation to move forward even when some telemetry sources were incomplete.

---

## 4. What Did Not Work

Several investigative paths produced limited or no value.

### Failed or Limited Pivots

| Pivot / Technique | Outcome | Limitation |
|---|---|---|
| Direct hunting across incomplete Advanced Hunting tables | Inconclusive | Relevant records were missing or incomplete |
| Network-flow-based validation of external communications | Could not be completed | Network flow logs were missing |
| Entra ID sign-in correlation | Could not validate identity activity end-to-end | No sign-in correlation available |
| Email-based initial access review | Could not assess email delivery or phishing vector | No mail telemetry present |
| Some command-line process reconstruction | Partial only | Process telemetry did not fully preserve all investigative context |
| Pure IOC searching without behavioral context | Low standalone value | Many findings required correlation with attack sequence to be meaningful |

### Key Takeaway
What did not work was not necessarily incorrect methodology; in most cases, the failure was due to **data absence**, not bad investigative logic.

---

## 5. Evidence That Confirmed Findings

The following evidence supports the confirmed findings in this investigation.

### Confirmed Evidence Table

| Finding | Evidence Type | Confidence | Notes |
|---|---|---|---|
| Akira-related payload execution | Presence/use of `wsync.exe` | High | Consistent with known payload naming/activity in this case |
| Defense evasion | Defender tampering activity | High | Strong ransomware precursor behavior |
| Recovery inhibition | Shadow copy deletion | High | Common pre-encryption ransomware behavior |
| Credential access attempt or capability | LSASS memory access | High | Strong indicator of credential theft or privilege preparation |
| Internal reconnaissance | Advanced IP Scanner / `scan.exe` / discovery activity | High | Supports operator-driven intrusion |
| Remote access capability | AnyDesk presence/use | High | Indicates potential remote interactive access |
| Scripted attacker actions | `PowerShell` and `kill.bat` | High | Likely used for staging, control impairment, or execution support |
| Payload infrastructure | `sync.cloud-endpoint.net` | High | Confirmed as malicious infrastructure in this investigation |
| Staging/C2 infrastructure | `cdn.cloud-endpoint.net` | High | Confirmed as malicious staging/C2 infrastructure |
| Related infrastructure resolution | `172.67.174.46`, `104.21.30.237` | High | Resolved IPs tied to confirmed malicious domain |

### Confirmed vs Hypothesized
**Confirmed findings** are those directly supported by infrastructure validation, observed tool usage, or clearly documented attacker actions.

**Hypotheses** remain around:
- exact initial access mechanism in this phase
- full identity-provider correlation path
- complete email involvement
- full cross-host propagation scope beyond observed evidence

---

## 6. Infrastructure Identified

### Confirmed Malicious Infrastructure

| Type | Indicator | Status | Notes |
|---|---|---|---|
| Payload Domain | `sync.cloud-endpoint.net` | Confirmed | Used to host or deliver attacker tooling/payloads |
| Staging / C2 Domain | `cdn.cloud-endpoint.net` | Confirmed | Used for staging or command-and-control-related activity |
| Resolved IP | `172.67.174.46` | Confirmed | Associated with confirmed C2 infrastructure |
| Resolved IP | `104.21.30.237` | Confirmed | Associated with confirmed C2 infrastructure |

### Infrastructure Assessment
The `cloud-endpoint.net` domain cluster appears central to this intrusion phase and should be treated as confirmed malicious infrastructure for:
- blocking
- retrospective searching
- detection content
- IOC enrichment
- threat intel watchlisting

---

## 7. Attack Chain Reconstruction

## Confirmed Attack Progression

| Phase | Confirmed Activity | Evidence |
|---|---|---|
| Access / Session Establishment | Attacker had usable access under `David.Mitchell` context | Compromised account context |
| Remote Operations | AnyDesk present/used | Confirmed attacker tool |
| Internal Reconnaissance | Network and process discovery performed | Advanced IP Scanner, `scan.exe`, process discovery |
| Credential Access | LSASS memory access observed | Confirmed credential access behavior |
| Payload / Tool Staging | Malicious infrastructure used for staging/delivery | `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net` |
| Defense Evasion | Defender tampering | Confirmed on impact path |
| Destructive Preparation | Shadow copy deletion | Confirmed ransomware precursor behavior |
| Payload Execution | `wsync.exe` associated with Akira activity | Confirmed payload indicator |
| Final Impact | Ransomware activity centered on `AS-PC2` | Impact host confirmation |

### Narrative Reconstruction
The attacker appears to have returned to the environment after access and staging established during **The Broker**. In The Buyer phase, activity shifted decisively into ransomware preparation and execution. The actor used remote access tooling, performed internal discovery, accessed LSASS memory to facilitate credential or privilege expansion, staged tooling via attacker-controlled `cloud-endpoint.net` infrastructure, tampered with Defender protections, deleted shadow copies, and executed the ransomware payload on `AS-PC2`.

### Hypotheses Still Under Review
The following remain plausible but not fully confirmed:
- whether AnyDesk was the primary interactive access path during the final phase
- whether additional hosts were staged before `AS-PC2`
- whether email or identity telemetry would have revealed an earlier supporting intrusion chain
- whether additional living-off-the-land commands were used but not retained in telemetry

---

## 8. Telemetry Gaps Observed

### Confirmed Telemetry Gaps

| Gap | Impact on Investigation |
|---|---|
| Missing network flow logs | Prevented full validation of outbound/inbound communications and infrastructure contact patterns |
| Incomplete Advanced Hunting telemetry | Limited host and process pivoting across the full attack chain |
| No Entra ID sign-in correlation | Prevented identity-layer confirmation of account misuse and session flow |
| No mail telemetry | Prevented validation of phishing, malicious attachments, or email-based intrusion support |

### Operational Impact of These Gaps
These gaps reduced the ability to:
- prove exact ingress path
- validate timing between user/account activity and infrastructure contact
- confirm whether additional attacker-controlled mail artifacts existed
- build a complete multi-host communication map
- distinguish fully between hands-on-keyboard sessions and staged automation at every step

---

## 9. Lessons Learned

### Investigation Lessons
1. **Backward-from-impact investigations can be highly effective** when ransomware telemetry is strongest at the end of the attack chain.
2. **Prior hunt context matters.** The relationship to **The Broker** materially improved confidence and reduced false pivots.
3. **Behavioral clustering outperforms isolated IOC searching** in incomplete telemetry conditions.
4. **Defense evasion and recovery-destruction behaviors remain high-value ransomware signals** and should trigger immediate escalation.
5. **LSASS access in combination with discovery plus defense tampering should be treated as near-critical** in enterprise environments.
6. **Lack of network, identity, and email telemetry significantly slows root-cause validation** even when endpoint evidence is strong.
7. **Remote access tools in context matter.** Tools like AnyDesk may be legitimate in some environments, but in this case their usage must be evaluated against the larger attack sequence.

---

## 10. Detection Engineering Improvements

### Recommended Detection Content

| Detection Area | Recommendation | Priority |
|---|---|---|
| Defender tampering | Alert on service modification, disabling, policy tampering, or security control impairment attempts | High |
| Shadow copy deletion | Alert on `vssadmin`, `wmic shadowcopy`, PowerShell, or scripted deletion activity | High |
| LSASS access | Detect suspicious memory access to LSASS by non-standard tools/processes | High |
| Discovery tooling | Detect use of Advanced IP Scanner, `scan.exe`, and unusual discovery commands in user context | High |
| Suspicious remote access tools | Detect AnyDesk installation/execution in sensitive environments or unusual user/device combinations | High |
| Malicious infrastructure contact | Block and alert on `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, and related indicators | High |
| Batch/script-based security impairment | Detect suspicious execution of files such as `kill.bat` and PowerShell used for control impairment | High |
| Ransomware staging sequences | Correlate discovery + LSASS access + Defender tampering + shadow deletion into a multi-stage analytic | Critical |

### Detection Strategy Improvements
The best improvement is not just more single alerts, but **correlated analytics** that identify ransomware progression. For example:

- discovery tooling  
+ suspicious admin/remote access  
+ LSASS access  
+ Defender tampering  
+ shadow copy deletion  

should produce a **critical incident chain**, not separate low-confidence detections.

---

## 11. Remaining Investigation Tasks

### Open Investigation Items

| Task | Status | Purpose |
|---|---|---|
| Validate full scope of affected hosts | Pending | Determine whether `AS-PC2` was the only impact host |
| Review for additional use of compromised account | Pending | Determine breadth of `David.Mitchell` account misuse |
| Search for additional infrastructure in the same cluster | Pending | Identify related attacker domains/IPs |
| Reconstruct broader timeline from Broker to Buyer | Pending | Improve continuity between initial intrusion and ransomware phase |
| Identify exact sequence of `kill.bat` activity | Pending | Determine whether it targeted protections, processes, or services |
| Determine whether AnyDesk was persistent or temporary | Pending | Clarify attacker access method |
| Validate whether shadow copy deletion occurred on other hosts | Pending | Assess pre-impact staging scope |
| Expand hunt for `wsync.exe` across environment | Pending | Determine whether payload staging occurred elsewhere |

### Hypotheses Requiring More Data
The following questions remain open because of telemetry gaps:
- Was the ransomware deployment limited to one host or broader in scope?
- Did the actor leverage identity infrastructure outside endpoint visibility?
- Was mail involved in the original or follow-on compromise chain?
- Were there additional staging nodes or operator workstations not yet identified?

---

## 12. Recommended SOC Playbook Updates

### Playbook Improvement Recommendations

#### A. Ransomware Pre-Impact Triage Playbook
Update the ransomware playbook to explicitly prioritize the following sequence:
1. isolate impacted host
2. check for Defender tampering
3. check for shadow copy deletion
4. search for LSASS access
5. identify remote access tooling
6. search for discovery tooling
7. pivot on compromised account
8. pivot on infrastructure/domain indicators

#### B. Cross-Hunt Correlation Procedure
Create a standard step requiring analysts to compare new hunts against:
- prior domains
- prior IPs
- prior compromised accounts
- prior remote access tools
- prior batch/script names
- prior payload naming patterns

This was especially valuable in connecting The Buyer to The Broker.

#### C. Telemetry Gap Escalation Procedure
Add a formal escalation path when analysts discover missing:
- network flow logs
- identity sign-in telemetry
- mail telemetry
- incomplete endpoint records

This ensures gaps are documented early and not discovered late in reporting.

#### D. Ransomware Behavior Matrix
Maintain an internal matrix of high-signal ransomware behaviors, including:
- discovery
- credential access
- security control tampering
- recovery destruction
- payload staging
- encryption/execution artifacts

Analysts should map observed behaviors against this matrix during triage.

#### E. IOC-to-Behavior Workflow
Revise playbooks so analysts do not stop at IOC identification. Require them to answer:
- what objective the tool supported
- where in the attack chain it appeared
- whether the behavior was preventative, preparatory, or impact-related
- what other expected behaviors should also be searched

---

## Final Assessment

### Confirmed Findings
The Buyer investigation confirmed a ransomware deployment phase involving:
- compromised use of `David.Mitchell`
- malicious infrastructure at `sync.cloud-endpoint.net` and `cdn.cloud-endpoint.net`
- attacker tooling including AnyDesk, Advanced IP Scanner, `scan.exe`, PowerShell, `wsync.exe`, and `kill.bat`
- operator behaviors including discovery, LSASS access, Defender tampering, and shadow copy deletion
- Akira ransomware-related activity centered on `AS-PC2`

### Key Analytical Conclusion
This was not an isolated malware event. The evidence supports a **human-operated ransomware intrusion** in which the attacker used staged access, performed internal reconnaissance, prepared the environment for impact, impaired defenses, and executed ransomware activity consistent with Akira operations.

### Confidence Statement
Confidence is **high** for the confirmed infrastructure, tooling, and late-stage attacker behaviors.  
Confidence is **moderate** for parts of the broader timeline where supporting identity, mail, or network telemetry was unavailable.
