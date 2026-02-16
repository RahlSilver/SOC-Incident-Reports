# Case Information
- **Case ID:** SOC-2026-00309  
- **Analyst:** Emre Utku  
- **Date:** 25 Jan 2026  
- **Status:** Escalated to Incident Response  
- **Priority:** High  

# Incident Title
Unusual Outbound Traffic with Repeated Beaconing Pattern

## Affected Asset
- **Hostname:** WIN-SALES-03  
- **Operating System:** Windows 10  
- **Internal IP:** 192.168.1.45  
- **User:** m.jones  

## Timeline
- 09:12:03 – Outbound connection to external IP 185.243.115.72 (Port 4444)
- 09:12:33 – Repeated connection attempt (30-second interval)
- 09:13:03 – Repeated connection attempt
- Pattern observed every 30 seconds for 45 minutes

# Event Description
Network monitoring detected repeated outbound connections from internal host `192.168.1.45` to a previously unseen external IP address (`185.243.115.72`) over TCP port 4444.

The communication pattern occurred at consistent 30-second intervals, which is indicative of automated beaconing behavior.

Port 4444 is commonly associated with reverse shell or command-and-control (C2) activity.

## Detection Method
Flow-based network monitoring (NetFlow / Firewall logs) triggered an alert due to:

- Communication with rare external IP
- Use of uncommon port (4444)
- Consistent interval-based outbound connections

# Evidence

## Flow Data Summary
Source IP: 192.168.1.45
Destination IP: 185.243.115.72
Destination Port: 4444
Protocol: TCP
Connection Frequency: Every 30 seconds
Total Duration: 45 minutes

## Initial Analysis
- The external IP has no prior communication history within the organization.
- Port 4444 is not used by approved business applications.
- The consistent interval pattern suggests beaconing behavior.
- No known scheduled tasks or legitimate services were identified using this port.
- The behavior is consistent with possible command-and-control (C2) activity.

# Risk Assessment

**Potential Risk:**
- Compromised endpoint communicating with attacker-controlled infrastructure.
- Remote command execution.
- Data exfiltration.
- Lateral movement preparation.

**Impact:**
- Possible system compromise.
- Risk to internal network if lateral movement occurs.

Risk level assessed as High due to sustained external beaconing behavior.

## Indicators of Compromise (IOCs)
- External IP: `185.243.115.72`
- Port: `4444`
- Internal Host: `192.168.1.45`
- Beacon Interval: 30 seconds

## Actions Taken
1. Verified communication pattern using flow-based monitoring.
2. Checked host EDR console for suspicious processes.
3. Searched SIEM for related alerts tied to the same endpoint.
4. Escalated the incident to the Incident Response team.
5. Recommended temporary host isolation pending investigation.

## Recommended Actions
- Isolate affected host from the network.
- Perform full EDR forensic scan.
- Identify process responsible for outbound connection.
- Block external IP at firewall.
- Review user activity and credential usage.
- Monitor for similar traffic from other endpoints.

## Conclusion
The outbound traffic pattern is highly consistent with potential command-and-control communication. Due to the repeated beaconing behavior over a non-standard port, the incident has been escalated to the Incident Response team for immediate containment and deeper investigation.

The case remains under active investigation.

