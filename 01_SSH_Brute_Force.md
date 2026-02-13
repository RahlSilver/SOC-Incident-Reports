# Case Information #
- **Case ID:** SOC-2024-00321
- **Analyst:** Emre Utku
- **Date:** 30 Mar 2024
- **Status:** Open - Monitoring
- **Priority:** Low / Medium

# Incident Title #
SSH Failed Login Attempts – Invalid Users

# Affected Asset #
- Hostname: server
- Operating System: Linux
- Service: SSH (sshd)
- Port: 22

# Timeline #
- 12:45:01 - Failed login attempt for invalid user admin
- 12:45:05 - Failed login attempt for invalid user root

# Event Description #
The SSH service recorded multiple failed authentication attempts targeting privileged-style usernames within a short time window. The activity originated from internal IP addresses.

# Evidence #
- 30 Mar 12:45:01 server sshd[41458]: Failed password for invalid user admin from 192.168.1.3 port 37362 ssh2
- 30 Mar 12:45:05 server sshd[41458]: Failed password for invalid user root from 192.168.1.6 port 37362 ssh2

# Initial Analysis (SOC Perspective) #
- “Invalid user” indicates username guessing.
- "admin" and "root" are commonly targeted accounts in brute-force attacks.
- Source IP addresses are internal, which could indicate:
  - Misconfigured internal script or service,
  - Authorized internal scan or penetration test,
  - Or a potentially compromised internal host.
- No successful SSH login events were observed for these IPs during the initial review.

# Risk Assessment #
- Brute force attempt against SSH. If successful, the attacker could gain unauthorized access and potentially move laterally within the environment.
- Based on the current findings, the severity is assessed as Low to Medium due to the absence of successful authentication.
- Currently limited (authentication failures only).

# Indicators of Interest (IOCs) #
- **Source IPs:** 192.168.1.3, 192.168.1.6
- **Usernames:** admin, root
- **Service:** SSH
- **Event Type:** Failed authentication

# Actions Taken #
- The activity was reviewed in the context of normal internal behavior. No prior pattern of administrative access attempts from these IPs was observed.
- Searched for additional failed login attempts before and after the reported timestamps.
- Marked source IPs for continued monitoring.
- Notified system owner / IT operations team for validation of internal IP activity.

# Conclusion #
- At this time, the activity appears suspicious but limited to failed login attempts only.
- No evidence of successful compromise has been identified.
-The incident remains open for monitoring pending confirmation from system owners.

