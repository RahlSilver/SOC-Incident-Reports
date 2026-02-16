# Case Information
- **Case ID:** SOC-2026-00302
- **Analyst:** Emre Utku
- **Date:** 14 Feb 2026
- **Status:** Open – Investigation Ongoing
- **Priority:** High

# Incident Title
Suspicious PowerShell Execution with Encoded Command

## Affected Asset
- **Hostname:** WIN-WS01
- **Operating System:** Windows 10
- **User:** j.doe
- **Event ID:** 4688 (Process Creation)

## Timeline
- 14:22:11 – Event ID 4688 logged for `powershell.exe`
- 14:22:11 – Command line included `-EncodedCommand`
- 14:22:15 – Outbound connection observed to external IP `185.199.110.153`
- 14:22:16 – Connection established over TCP port 443

# Event Description
A Windows Security Event (ID 4688) recorded the execution of `powershell.exe` with an encoded command parameter. Shortly after execution, the host initiated an outbound network connection to an external IP address over port 443.

The use of encoded PowerShell commands is commonly associated with obfuscation techniques used in malicious activity.

# Evidence

## Windows Event Log (4688 – Process Creation)
- **New Process Name:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- **Command Line:** powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...
- **Parent Process:** winword.exe
- **User:** j.doe

## Network Observation
- **Source IP:** 192.168.1.25
- **Destination IP:** 185.199.110.153
- **Destination Port:** 443
- **Protocol:** TCP

## Initial Analysis
- Event ID 4688 confirms process creation.
- Use of `-EncodedCommand` suggests command obfuscation.
- Parent process `winword.exe` may indicate possible phishing or malicious document execution.
- Outbound connection to an external IP shortly after execution increases suspicion.
- Port 443 (HTTPS) may be used to disguise command-and-control (C2) traffic.

## Risk Assessment

**Potential Risk:**
- Possible command-and-control (C2) communication.
- Execution of malicious PowerShell payload.
- Initial access via phishing attachment.

**Impact:**
- Potential system compromise.
- Risk of lateral movement or data exfiltration.
- Credential theft possibility.

Risk level assessed as High due to encoded command execution combined with external communication.

## Indicators of Compromise (IOCs)
- **External IP:** `185.199.110.153`
- **Process:** `powershell.exe`
- **ommand Parameter:** `-EncodedCommand`
- **Parent Process:** `winword.exe`
- **Event ID:** 4688

# Actions Taken
1. Reviewed process tree for additional suspicious child processes.
2. Checked EDR alerts for malicious behavior on the host.
3. Investigated outbound network traffic patterns.
4. Escalated case to Incident Response team for deeper investigation.
5. Recommended temporary host isolation pending validation.

## Recommended Actions
- Decode and analyze the encoded PowerShell command.
- Perform full EDR scan on affected endpoint.
- Validate whether user interaction triggered execution.
- Block external IP at firewall if confirmed malicious.
- Reset user credentials as precautionary measure.

# Conclusion
The activity is consistent with potentially malicious PowerShell execution using obfuscated commands and external network communication.
Given the presence of encoded command execution and possible phishing-related parent process, the incident is categorized as High severity and requires immediate escalation.

The case remains open pending further forensic validation.

