# Case Information
- **Case ID:** SOC-2026-00307  
- **Analyst:** Emre Utku  
- **Date:** 11 Jan 2026  
- **Status:** Open – Investigation Ongoing  
- **Priority:** Medium  

# Incident Title
Phishing Email Containing Suspicious ISO Attachment

## Affected Asset
- **Recipient User:** a.smith  
- **Department:** Finance  
- **Workstation:** WIN-FIN-02  
- **Email Client:** Outlook  

## Timeline
- 10:14:22 – Suspicious email received
- 10:15:03 – User opened the email
- 10:15:35 – User downloaded attached file `invoice_2026.iso`
- No confirmed execution observed at the time of initial review

## Event Description
A phishing email was received by a Finance department user. The email contained an ISO attachment named `invoice_2026.iso` and originated from a suspicious sender domain that closely resembles a legitimate vendor.

The sender domain was identified as: billing-support@micros0ft-secure.com

The attachment hash was not recognized in internal or known reputation databases during the initial review.

# Evidence

## Email Header Indicators
- Sender Domain: micros0ft-secure.com
- SPF: Failed
- DKIM: Failed
- Reply-To domain mismatch observed

## Attachment Information
- File Name: invoice_2026.iso
- File Type: ISO Disk Image
- SHA256 Hash: Unknown (no match in threat intelligence lookup)
- File Size: 1.8 MB

## Initial Analysis (SOC Perspective)
- ISO attachments are commonly used to bypass email filtering mechanisms.
- The sender domain uses typosquatting techniques (e.g., “micros0ft” instead of “microsoft”).
- SPF and DKIM validation failures increase suspicion.
- The file hash did not match known malicious or known safe files.
- No confirmed execution was observed at the time of investigation.

# Risk Assessment

**Potential Risk:**
- Initial access via phishing.
- Malware execution through mounted ISO file.
- Potential credential theft or remote access tool (RAT) deployment.

**Impact:**
- If executed, the attachment may allow attacker-controlled access.
- Risk of lateral movement within the network.
- Potential financial data exposure due to Finance department targeting.

Risk level assessed as Medium, pending confirmation of file execution.

## Indicators of Compromise (IOCs)
- Suspicious sender domain: `micros0ft-secure.com`
- Attachment type: `.iso`
- Unknown SHA256 hash
- User interaction with attachment

## Actions Taken
1. Email quarantined from user mailbox.
2. Attachment hash checked against threat intelligence sources.
3. Verified no process execution linked to the attachment at initial review.
4. Notified user and provided phishing awareness reminder.
5. Recommended further analysis via sandbox environment.

## Recommended Actions
- Submit the attachment to a secure sandbox for behavioral analysis.
- Monitor the user endpoint for suspicious process creation.
- Reset user credentials as precaution if execution is confirmed.
- Block the sender domain at the email gateway.
- Continue monitoring for similar phishing attempts.

## Conclusion
The email exhibits characteristics consistent with phishing activity, including typosquatting domain usage and suspicious attachment format. Although no confirmed execution was observed at the time of review, further sandbox analysis is recommended to determine the malicious nature of the attachment.

The case remains open pending additional validation.

