# Incident Report 1: Multiple Failed Logon Attempts (Simulated Brute Force)

**Date:** 1 Oct 2026 | **Analyst:** Kaviya | **Status:** Closed (lab simulation)
**Severity:** Medium (Wazuh rule level 10)

## 1. Summary
Wazuh detected a burst of about 20 failed login attempts against the Windows 10 endpoint within seconds. I generated this activity deliberately to test detection of a brute-force pattern. Wazuh raised a level-10 alert, "Multiple Windows Logon Failures" (rule 60204).

## 2. Affected asset
- Host: SOC-Windows10 (192.168.56.101), agent SOC-Windows10-Agent
- Targeted account: fakeadmin (does not exist on the system)

## 3. Detection
- Source: Windows Security log, Event ID 4625 (failed logon), collected by the Wazuh agent
- Rule 60122, level 5: "Logon Failure - Unknown user or bad password" (one alert per failed attempt)
- Rule 60204, level 10: "Multiple Windows Logon Failures" (fires after 8 failures; fired at 13:24:12)
- MITRE ATT&CK: T1110 (Brute Force), tactic Credential Access
- Key event fields: logon type 3 (network), source IP 127.0.0.1, logon process NtLmSsp, sub-status 0xc0000064 (user name does not exist)

## 4. Timeline (times as shown in Wazuh)
- 13:24:10 failed logons being recorded (rule 60122)
- 13:24:12 escalation to rule 60204 (level 10)
- 13:24:26 last failed logon in the burst
- Note: Wazuh logged a "System time changed" alert (rule 60132) during the lab, so VM and Wazuh times can differ slightly.

## 5. Analysis
- Many failures within seconds, against a username that does not exist, with network logon type 3, is consistent with automated password guessing.
- The source was 127.0.0.1, which is the machine itself, so this was local lab activity and not an outside attacker.
- A few older failed logons (about 6) appeared near midnight, before the test. They are not part of this simulation, so I did not include them in this report.
- fakeadmin does not exist, so a successful logon for it was not possible. Verdict: True positive (simulated), expected behaviour in this lab.

## 6. Recommended response (if this were real)
1. Identify the source IP and block it at the firewall.
2. Check for any successful logon from the same source after the failures.
3. Enable an account lockout policy and consider MFA.
4. Monitor the targeted accounts for further attempts.

## 7. Evidence
screenshots/failed-login-events.png, failed-login-rule-mitre.png, failed-login-event-details.png
