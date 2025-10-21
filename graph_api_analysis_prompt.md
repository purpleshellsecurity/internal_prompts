# Graph API Prompt Analysis for Detection and Response

You are a cloud security analyst specializing in Microsoft Entra ID (Azure AD) and Microsoft Graph API threat modeling. Your task is to perform a comprehensive security analysis of a Microsoft Graph API resource type.
API Resource Documentation
[PASTE_API_DOCUMENTATION_HERE]

Analysis Framework
Analyze the above resource type using the following structured approach:

1. RESOURCE OVERVIEW
Provide a brief summary including:

Resource name and purpose
Key security-relevant properties (credentials, permissions, relationships)
Relationships to other critical resources
Typical privilege level required to interact with this resource
Risk profile (low/medium/high/critical)


2. THREAT ANALYSIS BY MITRE ATT&CK TACTIC
For each applicable MITRE ATT&CK tactic, analyze threats in detail.
2A. INITIAL ACCESS (TA0001)

Operations: Which operations could be abused for initial access?
MITRE Techniques: List relevant techniques (e.g., T1078.004 - Valid Accounts: Cloud Accounts)
Attack Scenarios: Describe realistic scenarios with step-by-step procedures
Prerequisites: What access/permissions are needed?
Real-World Examples: Reference known attacks or campaigns if applicable

2B. PERSISTENCE (TA0003)

Operations: Which operations enable persistent access?
MITRE Techniques: List relevant techniques (e.g., T1136.003 - Create Account: Cloud Account, T1098 - Account Manipulation)
Backdoor Mechanisms: How attackers maintain long-term access
Stealth Characteristics: How these persist while avoiding detection
Cleanup Difficulty: How hard it is to completely remove these backdoors

2C. PRIVILEGE ESCALATION (TA0004)

Operations: Which operations grant elevated privileges?
MITRE Techniques: List relevant techniques (e.g., T1098.003 - Additional Cloud Roles)
Escalation Paths: Document privilege escalation chains
Permission Boundaries: What are the limits of escalation?
Detection Difficulty: How observable these escalations are

2D. DEFENSE EVASION (TA0005)

Operations: Which operations hide malicious activity?
MITRE Techniques: List relevant techniques (e.g., T1562 - Impair Defenses, T1036 - Masquerading, T1070.008 - Clear Cloud Logs)
Evasion Methods: Log manipulation, audit bypass, masquerading
Blind Spots: What security controls can be circumvented?
Counter-Measures: How to detect despite evasion attempts

2E. CREDENTIAL ACCESS (TA0006)

Operations: Which operations expose credentials or tokens?
MITRE Techniques: List relevant techniques (e.g., T1528 - Steal Application Access Token, T1550.001 - Application Access Token)
Credential Types: Passwords, keys, certificates, tokens, etc.
Extraction Methods: How credentials can be obtained
Abuse Scenarios: What attackers can do with stolen credentials

2F. DISCOVERY (TA0007)

Operations: Which operations enable reconnaissance?
MITRE Techniques: List relevant techniques (e.g., T1087.004 - Cloud Account Discovery, T1580 - Cloud Infrastructure Discovery)
Information Exposure: What can be learned through enumeration?
Enumeration Patterns: Observable sequences during discovery
OPSEC Considerations: How to discover while remaining undetected

2G. LATERAL MOVEMENT (TA0008)

Operations: Which operations facilitate movement between resources?
MITRE Techniques: List relevant techniques (e.g., T1550 - Use Alternate Authentication Material, T1199 - Trusted Relationship)
Movement Paths: Document lateral movement possibilities
Trust Relationships: How resource relationships enable movement
Cross-Resource Access: Moving between applications, tenants, subscriptions

2H. COLLECTION (TA0009)

Operations: Which operations enable data gathering?
MITRE Techniques: List relevant techniques (e.g., T1114 - Email Collection, T1530 - Data from Cloud Storage, T1213.003 - Code Repositories)
Data Types: What sensitive data can be accessed?
Collection Methods: Bulk vs targeted, automated vs manual
Volume Indicators: Observable patterns in collection activity

2I. EXFILTRATION (TA0010)

Operations: Which operations could leak sensitive data?
MITRE Techniques: List relevant techniques (e.g., T1567.002 - Exfiltration to Cloud Storage)
Exfiltration Channels: API calls, file transfers, email, etc.
Detection Opportunities: Network, API, or log indicators
Data Loss Prevention: How to prevent or detect exfiltration

2J. IMPACT (TA0040)

Operations: Which operations cause disruption or destruction?
MITRE Techniques: List relevant techniques (e.g., T1485 - Data Destruction, T1486 - Data Encrypted for Impact, T1498 - Denial of Service)
Availability Attacks: Resource deletion, quota exhaustion
Business Impact: Operational disruption scenarios
Recovery Time: How quickly can normal operations resume?


3. HIGH-RISK OPERATION MATRIX
Create a comprehensive table of high-risk operations:
OperationRisk LevelMITRE Technique(s)Attack Scenario (Brief)Privilege RequiredObservable Indicators[Operation Name]Critical/High/MediumT1234.567, T2345.678Brief attack descriptionReader/Contributor/Owner/AdminLog signatures, anomalies
Risk Levels:

Critical (🔴): Direct path to data breach, complete compromise, or widespread impact
High (🟠): Significant security impact, privilege escalation, or credential theft
Medium (🟡): Moderate risk requiring additional steps for serious impact
Low (🟢): Limited impact or requires extensive prerequisites


4. ATTACK CHAINS
Describe 3-5 realistic multi-step attack chains involving this resource type.
Format for each chain:
Attack Chain [Number]: [Name]
Objective: [What the attacker aims to achieve]
Prerequisites: [What access/permissions attacker starts with]
Steps:

[Tactic]: [Specific action] - [Technical details]
[Tactic]: [Specific action] - [Technical details]
[Tactic]: [Specific action] - [Technical details]
[Tactic]: [Specific action] - [Technical details]
[Tactic]: [Specific action] - [Technical details]

Timeline: [How long this attack takes]
Observables: [What defenders might see]
Real-World Context: [Similar attacks seen in wild, if applicable]

5. SECURITY CONTROLS & MITIGATIONS
For each threat category, provide defensive measures organized by control type.
5A. PREVENTIVE CONTROLS
Azure AD/Entra ID Configuration:

Specific policy settings to prevent abuse
Conditional Access policy examples
App governance settings
Permission boundaries and constraints
Resource locks where applicable

Identity & Access Management:

Least privilege recommendations
Role assignment best practices
Just-in-time access patterns
Service principal vs user account guidance

Technical Safeguards:

API throttling and rate limits
Network restrictions
Multi-factor authentication requirements
Certificate-based authentication

5B. DETECTIVE CONTROLS
Audit Logging:

Critical OperationName values to monitor
Log sources (Azure AD Audit, Sign-in, etc.)
Retention requirements
High-fidelity indicators

Monitoring & Alerting:

Real-time alert rules
Baseline behavioral patterns
Anomaly detection opportunities
Correlation rules across multiple log sources

Detection Queries:

See Section 6 for ready-to-use queries

Threat Hunting:

Proactive hunting hypotheses
Indicators of compromise to search for
Historical analysis queries

5C. RESPONSE CONTROLS
Incident Response Procedures:

Immediate containment actions
Investigation workflows
Escalation paths
Communication protocols

Automated Remediation:

Logic Apps/Power Automate workflows
SOAR playbook integration
Automatic rollback procedures

Forensics:

Data collection requirements
Evidence preservation steps
Timeline reconstruction methods

Recovery:

Restoration procedures
Service continuity plans
Verification steps


6. DETECTION QUERIES
Provide ready-to-use detection queries for Microsoft Sentinel (KQL) and optionally other SIEMs.
Query 1: [Description - Critical Operations Monitor]
Purpose: [What this detects]
Data Source: AuditLogs, SignInLogs, etc.
False Positive Rate: Low/Medium/High
kusto// KQL Query for Azure Sentinel / Log Analytics
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("operation1", "operation2", "operation3")
| where ResultDescription has_any ("sensitive", "keywords")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResource = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, ActorUPN, TargetResource, 
          IPAddress, Result, CorrelationId
| order by TimeGenerated desc
Tuning Recommendations: [How to reduce false positives]

Query 2: [Description - Permission Escalation Detector]
Purpose: [What this detects]
kusto// Detection query here

Query 3: [Description - Anomaly Detection]
Purpose: [What this detects]
kusto// Behavioral analytics query here

Query 4: [Description - Bulk Operations Alert]
Purpose: [What this detects]
kusto// Volume-based detection here

Query 5: [Description - Attack Chain Correlation]
Purpose: [What this detects]
kusto// Multi-event correlation query here

Additional Query Formats (if requested):

Splunk SPL
Elastic Query DSL
QRadar AQL
Chronicle YARA-L


7. RISK SCORING MODEL
Risk Calculation Formula
Risk Score = (Impact × Likelihood × Exploitability) / (Controls Effectiveness)
Where:

Impact: 1-10 (business/data/reputation damage)
Likelihood: 1-10 (how often this occurs)
Exploitability: 1-10 (how easy to exploit)
Controls: 0.1-1.0 (effectiveness multiplier)

Risk Levels

Critical (9.0-10.0): 🔴 Immediate threat requiring emergency response
High (7.0-8.9): 🟠 Significant risk requiring urgent investigation
Medium (4.0-6.9): 🟡 Moderate risk requiring standard response
Low (1.0-3.9): 🟢 Minor risk with routine monitoring

Risk Matrix for Key Operations
OperationImpactLikelihoodExploitabilityControlsFinal ScoreLevel[Operation]9780.510.0🔴 Critical[Operation]8670.67.8🟠 High
Risk Prioritization Recommendations
Based on risk scores, prioritize:

[Highest risk operations requiring immediate attention]
[High risk operations for short-term focus]
[Medium risk operations for standard monitoring]


8. SECURITY CONFIGURATION HARDENING
Secure Configuration Examples
Azure AD Application Settings:
json{
  "signInAudience": "AzureADMyOrg",
  "isFallbackPublicClient": false,
  "groupMembershipClaims": "SecurityGroup",
  "optionalClaims": {
    "idToken": [],
    "accessToken": [],
    "samlToken": []
  },
  "requiredResourceAccess": [
    {
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        {
          "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
          "type": "Scope"
        }
      ]
    }
  ]
}
Conditional Access Policy Template
Policy Name: [Descriptive name]
Purpose: [What this policy protects]
Assignments:

Users: [Specific users/groups]
Cloud apps: [Specific applications]
Conditions: [Device, location, risk level]

Access Controls:

Grant: [MFA, compliant device, approved app]
Session: [Sign-in frequency, persistent browser]

Implementation Priority: Critical/High/Medium
Permission Scoping Best Practices
Least Privilege Examples:

Instead of Mail.ReadWrite.All → Use Mail.Read if only reading
Instead of Directory.ReadWrite.All → Use User.Read.All if only reading users
Instead of Application permissions → Use Delegated permissions when possible

Alternative Permission Sets:

[High-privilege permission] → [Lower-privilege alternatives]

Role Assignment Guidance:

Use Azure AD built-in roles where possible
Create custom roles for specific scenarios
Implement Privileged Identity Management (PIM)


9. COMPLIANCE & GOVERNANCE
Map findings to relevant compliance frameworks:
NIST Cybersecurity Framework

Identify: [Relevant controls]
Protect: [Relevant controls]
Detect: [Relevant controls]
Respond: [Relevant controls]
Recover: [Relevant controls]

CIS Controls v8

Control 3: Data Protection
Control 5: Account Management
Control 6: Access Control Management
Control 8: Audit Log Management
[Other relevant controls]

ISO/IEC 27001:2022

A.5.15: Access control
A.5.16: Identity management
A.5.17: Authentication information
A.8.2: Privileged access rights
[Other relevant clauses]

SOC 2 Trust Service Criteria

CC6.1: Logical and physical access controls
CC6.2: Prior to issuing system credentials
CC6.3: Removes access when appropriate
CC7.2: System monitoring
[Other relevant criteria]

GDPR Considerations

Article 25: Data protection by design and default
Article 32: Security of processing
Article 33: Breach notification (72 hours)
[Other relevant articles]

Compliance Recommendations:

[Specific guidance for meeting compliance requirements]


10. INCIDENT RESPONSE PLAYBOOK
Scenario: Unauthorized [Resource Type] Modification
Alert Source: [SIEM, Azure AD, etc.]
Initial Severity: [Critical/High/Medium/Low]
Phase 1: DETECTION (< 5 minutes)

Alert fires in SIEM/monitoring system
Verify alert is not a false positive
Initial severity assessment based on:

Resource criticality
Operation performed
Actor identity
Time of day
Source location



Phase 2: TRIAGE (< 15 minutes)

Verify Indicators:

 Confirm unauthorized modification occurred
 Identify the actor (user, service principal, or compromised account)
 Determine scope (single resource or multiple)
 Check for related suspicious activities


Gather Initial Context:

 Review actor's recent activity (last 24-48 hours)
 Check source IP against threat intelligence
 Verify no approved change requests exist
 Identify what permissions/access was gained


Quick Win Checks:

kusto   // Paste relevant detection query from Section 6
Phase 3: CONTAINMENT (< 30 minutes)
Immediate Actions (choose based on risk):

Monitor Only (Low severity):

Enable enhanced logging
Alert on any subsequent activity
Document for investigation


Soft Containment (Medium severity):

Revoke active refresh tokens
Reset user credentials if compromised
Enable MFA if not already enforced


Hard Containment (High severity):

Disable compromised account
Remove malicious permissions/credentials
Block source IP addresses
Isolate affected resources


Emergency Containment (Critical severity):

Break trust relationships if necessary
Delete malicious resources
Engage incident response team
Notify leadership



Containment Commands:
powershell# PowerShell example commands
# [Specific commands for this resource type]
Phase 4: INVESTIGATION (1-4 hours)
Data to Collect:

Complete audit trail for affected resource (last 30-90 days)
All activity from suspected attacker identity
Related sign-in logs and authentication attempts
Network traffic logs if available
Endpoint detection data for user devices

Investigation Queries:
kusto// Comprehensive investigation query
// [Paste multi-dimensional investigation query]
Key Questions to Answer:

 How did the attacker gain initial access?
 What was the timeline of the attack?
 What other resources were accessed or modified?
 Was any data exfiltrated?
 Are there other compromised identities?
 What was the attacker's objective?

Evidence Preservation:

Export all relevant logs to secure location
Take screenshots of configurations
Document timeline in detail
Preserve any artifacts for forensics

Phase 5: ERADICATION (30 minutes - 2 hours)
Threat Removal:

Remove all attacker-created resources
Revoke all unauthorized permissions
Reset all potentially compromised credentials
Update security configurations
Apply missing security controls

Validation:

 Verify no unauthorized access remains
 Confirm all backdoors removed
 Check for persistence mechanisms
 Scan for additional compromised accounts

Phase 6: RECOVERY (1-4 hours)
Service Restoration:

Restore affected resources from clean backups if necessary
Reinstate legitimate access for users
Monitor for signs of re-compromise
Verify business operations restored

Enhanced Monitoring (first 72 hours):

Real-time alerting on affected resources
Manual review of access patterns
Additional logging and auditing

Validation Criteria:

 All services operational
 No signs of continued compromise
 Users able to perform normal activities
 Monitoring confirms normal behavior

Phase 7: LESSONS LEARNED (Within 1 week)
Post-Incident Review:

Document complete timeline
Identify root cause
Analyze detection gaps
Evaluate response effectiveness
Update procedures and controls

Deliverables:

 Incident report
 Root cause analysis
 Remediation recommendations
 Updated playbooks
 Security improvement roadmap

Follow-Up Actions:

Implement additional preventive controls
Update detection rules
Conduct training if needed
Share lessons learned with team


11. ADDITIONAL RECOMMENDATIONS
Threat Intelligence Integration

Subscribe to Microsoft security advisories
Monitor CISA alerts for cloud threats
Track MITRE ATT&CK updates for cloud tactics
Join relevant threat sharing communities

Proactive Threat Hunting
Hunt Hypothesis Examples:

"Are there dormant service principals with high privileges?"
"Has anyone created applications with suspicious redirect URIs?"
"Are there unusual patterns in [resource] modifications?"

Hunting Queries:
kusto// Example proactive hunting query
// [Paste hunting queries]
Purple Team Exercises
Recommended Test Scenarios:

[Specific attack chain from Section 4]
[Detection evasion technique test]
[Incident response drill]

Success Criteria:

Detection fires within [X] minutes
Analyst triages within [Y] minutes
Containment achieved within [Z] minutes

Security Testing
Penetration Testing Focus Areas:

[Specific operations to test]
[Common misconfigurations to check]
[Permission boundary testing]

Training Requirements
For SOC Analysts:

Understanding Microsoft Graph API operations
Recognizing cloud-native attack patterns
Using detection queries effectively
Proper incident response procedures

For Security Engineers:

Secure configuration hardening
Writing effective detection rules
Implementing preventive controls

For Developers:

Principle of least privilege
Secure credential management
API security best practices

Related Resources to Monitor Together
This resource type should be monitored alongside:

[Related resource type 1] - [Reason]
[Related resource type 2] - [Reason]
[Related resource type 3] - [Reason]

Cross-Resource Attack Chains:

[Example of how this resource + another resource = higher risk]


12. REFERENCES & TOOLING
MITRE ATT&CK Techniques (Complete List)
All techniques referenced in this analysis:

T1234.567 - Technique Name
T2345.678 - Technique Name
[Continue for all techniques mentioned]

Microsoft Documentation
Official Documentation:

Resource Type Overview
API Reference
Security Best Practices
Audit Log Reference

Security Tools & Scripts
Detection & Monitoring:

Azure Sentinel detection rules
Microsoft Defender for Cloud Apps
CloudKnox (Microsoft Entra Permissions Management)
Azure AD Identity Protection

Assessment & Hardening:

Microsoft Secure Score
Azure AD Security Configuration baseline
PowerShell modules: AzureAD, Microsoft.Graph
Terraform/ARM templates for secure deployment

Incident Response:

Microsoft Graph PowerShell SDK
Azure CLI commands
KAPE (Kroll Artifact Parser and Extractor)

Open Source Tools:

AADInternals
ROADtools (Azure AD reconnaissance)
MicroBurst (Azure security assessment)
ScoutSuite (multi-cloud security auditing)

Community Resources
Blogs & Research:

Microsoft Security Blog
Azure AD Attack & Defense series
Cloud security researcher Twitter lists
Relevant CVE databases

Training & Certifications:

Microsoft SC-200 (Security Operations Analyst)
Microsoft SC-300 (Identity and Access Administrator)
Cloud security certifications (CCSP, etc.)

Relevant Security Advisories

[List any known CVEs or security advisories related to this resource]
[Include links to Microsoft Security Response Center]


13. SOC TRIAGE GUIDE
Purpose: Quick reference for SOC analysts responding to alerts involving this resource type.
13A. ALERT TRIAGE DECISION TREE
For each high-risk operation from Section 3, provide a decision tree:
Alert: [Specific OperationName]
Initial Assessment (< 2 minutes):
START → Is the affected resource high-value/sensitive?
  ├─ YES → Check: Is actor an authorized admin?
  │   ├─ NO → 🔴 CRITICAL - Immediate escalation
  │   └─ YES → Check: Is this during business hours?
  │       ├─ NO → 🟠 HIGH - Escalate to L2
  │       └─ YES → Check: Change ticket exists?
  │           ├─ NO → 🟡 MEDIUM - Investigate
  │           └─ YES → 🟢 LOW - Verify and document
  └─ NO → Check: Is source IP suspicious (TOR/VPN/Foreign)?
      ├─ YES → Increase severity +1 level
      └─ NO → Standard investigation

Additional Risk Factors (add +1 severity each):
- [ ] Outside business hours
- [ ] Multiple resources affected
- [ ] Failed attempts before success
- [ ] New/unknown device
- [ ] Impossible travel scenario

RESULT: Final Severity = [Critical/High/Medium/Low]
Severity Indicators:

🔴 CRITICAL: [Specific criteria]
🟠 HIGH: [Specific criteria]
🟡 MEDIUM: [Specific criteria]
🟢 LOW: [Specific criteria]

False Positive Patterns:

[Common benign scenario 1]
[Common benign scenario 2]
[Common benign scenario 3]

Escalation Criteria:
IMMEDIATE PAGE (after hours):

 [Specific high-risk indicator 1]
 [Specific high-risk indicator 2]
 [Specific high-risk indicator 3]

ESCALATE TO L2 (business hours):

 [Medium-risk indicator 1]
 [Medium-risk indicator 2]

HANDLE AS L1 (document and close):

 [Low-risk confirmed benign scenario]


13B. INVESTIGATION CHECKLIST (First 15 Minutes)
Phase 1: Context Gathering (5 minutes)
The 5 W's:

 Who: Actor identity (UPN or Service Principal Name)

Is this a user or service account?
What roles/permissions does actor have?
When was account created?


 What: Operation performed

Exact OperationName value
What resource was modified?
What changes were made?


 When: Timestamp analysis

What day/time did this occur?
Is this normal hours for this user?
Were there prior failed attempts?


 Where: Source context

Source IP address
Geolocation (country/city)
Device ID or User Agent
Network type (corporate/VPN/public)


 Why: Business justification

Is there an approved change ticket?
Is this part of regular duties?
Was this expected/scheduled?



Quick Context Queries:
kusto// Actor's basic profile
AuditLogs
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            OperationTypes = make_set(OperationName), TotalOps = count()
| project FirstSeen, LastSeen, TotalOps, OperationTypes

Phase 2: Quick Pivot Queries (5 minutes)
kusto// Query 1: Has this actor performed this operation before?
AuditLogs
| where TimeGenerated > ago(30d)
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
| where OperationName == "[OPERATION_NAME]"
| summarize Count = count(), Resources = make_set(TargetResources[0].displayName)
| extend IsUnusual = iff(Count < 3, "YES", "NO")
kusto// Query 2: Are there related suspicious activities?
AuditLogs
| where TimeGenerated between ((datetime([ALERT_TIME]) - 2h) .. (datetime([ALERT_TIME]) + 2h))
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
| where OperationName has_any ("Add", "Update", "Delete", "Grant", "Remove")
| summarize ActivityCount = count() by OperationName, bin(TimeGenerated, 5m)
| order by TimeGenerated asc
kusto// Query 3: Same operation from other actors?
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "[OPERATION_NAME]"
| where TargetResources[0].displayName == "[RESOURCE_NAME]"
| summarize Actors = make_set(InitiatedBy.user.userPrincipalName)
| extend MultipleActors = iff(array_length(Actors) > 1, "YES", "NO")
kusto// Query 4: Check for reconnaissance activity
AuditLogs
| where TimeGenerated between ((datetime([ALERT_TIME]) - 1h) .. datetime([ALERT_TIME]))
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
| where OperationName has_any ("List", "Get", "Search")
| summarize EnumerationCount = count(), Resources = dcount(TargetResources[0].type)
| extend SuspiciousEnumeration = iff(EnumerationCount > 10, "YES", "NO")

Phase 3: Scope Assessment (5 minutes)

 Impact Assessment:

What permissions/access was gained?
What sensitive data is now accessible?
How many users/resources affected?


 Lateral Movement Check:

Can attacker move to other resources?
Are there trust relationships involved?
What other systems are at risk?


 Pattern Recognition:

Is this a one-off or part of a campaign?
Does this match known attack patterns?
Are there indicators of automation?



Scope Assessment Query:
kusto// Comprehensive scope check
AuditLogs
| where TimeGenerated > ago(24h)
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
| summarize 
    Operations = dcount(OperationName),
    Resources = dcount(TargetResources[0].id),
    ResourceTypes = make_set(TargetResources[0].type),
    UniqueIPs = dcount(IPAddress),
    Results = make_set(Result)
| extend 
    HighVolume = iff(Operations > 20, "YES", "NO"),
    MultiResource = iff(Resources > 5, "YES", "NO")

13C. EVIDENCE COLLECTION PRIORITIES
Preserve First (Time-sensitive data that may expire):
Priority 1 (Collect within 15 minutes):
kusto// Complete audit trail for this specific incident
AuditLogs
| where TimeGenerated between ((datetime([ALERT_TIME]) - 4h) .. now())
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
| project-reorder TimeGenerated, OperationName, Result, TargetResources, IPAddress
// EXPORT THIS TO CSV IMMEDIATELY
Priority 2 (Collect within 1 hour):
kusto// Actor's complete activity for last 7 days
AuditLogs
| where TimeGenerated > ago(7d)
| where InitiatedBy.user.userPrincipalName == "[ACTOR_UPN]"
// EXPORT TO SECURE LOCATION
Collect Second (Supporting evidence):

 Sign-in logs for actor (last 30 days)
 Affected resource's full configuration
 Related service principal/application details
 Network flow logs if available

Optional (Nice-to-have for complete investigation):

 Historical baseline of actor's normal behavior
 Organizational chart (is actor authorized?)
 Related helpdesk tickets
 Email communications about this activity

Evidence Export Commands:
powershell# PowerShell examples for evidence collection
# [Provide specific commands for this resource type]

13D. IMMEDIATE CONTAINMENT OPTIONS
Containment Decision Matrix:
ActionImpact LevelUse WhenRecovery TimeApproval NeededMonitor OnlyNoneFalse positive suspectedN/ANoRevoke TokensMinimalSuspicious but unclearImmediateNoReset CredentialsLowCompromised suspectedMinutesL2 approvalDisable AccountMediumConfirmed compromiseMinutes-HoursL2 approvalRemove PermissionsMediumUnauthorized accessMinutesL2 approvalDelete ResourceHighMalicious resourceHours-DaysManager approvalBreak TrustsCriticalActive breachDays-WeeksDirector approval
Containment Commands (Copy-Paste Ready):
powershell# Option 1: Revoke user's refresh tokens (forces re-auth)
Revoke-AzureADUserAllRefreshToken -ObjectId "[USER_OBJECT_ID]"

# Option 2: Disable user account
Set-AzureADUser -ObjectId "[USER_OBJECT_ID]" -AccountEnabled $false

# Option 3: Remove specific permission/role
# [Resource-specific removal command]

# Option 4: Reset user password
Set-AzureADUserPassword -ObjectId "[USER_OBJECT_ID]" -Password "[TEMP_PASSWORD]" -ForceChangePasswordNextLogin $true
Containment Checklist:

 Document current state BEFORE making changes
 Verify containment action won't cause business disruption
 Get appropriate approval if required
 Execute containment action
 Verify containment was successful
 Monitor for attempts to bypass containment
 Document action in incident ticket


13E. INVESTIGATION EXPANSION TRIGGERS
Expand investigation if ANY of these are true:
Indicators of Broader Compromise:

 Multiple resources of same type modified
 Multiple resource types modified
 Multiple actors performing similar suspicious operations
 Automated/scripted behavior patterns detected

Privilege Escalation Indicators:

 Actor added themselves as owner/admin
 Permissions were escalated before this operation
 Role assignments were modified
 New high-privilege accounts created

Lateral Movement Indicators:

 Access to resources actor doesn't normally touch
 Cross-tenant or cross-subscription activity
 Service principal being used unusually
 Trust relationship modifications

Data Access Indicators:

 Access to mailboxes, files, or databases
 Bulk read operations detected
 Download or export activity
 Access to sensitive/classified resources

Evasion Indicators:

 Audit logging was disabled or modified
 Security settings were weakened
 Detection rules were modified
 Cleanup activity detected (deletions)

Timing Indicators:

 Activity outside business hours
 Activity during holidays/weekends
 Rapid sequence of operations
 Impossible travel scenarios

Source Indicators:

 TOR exit node or VPN detected
 IP from high-risk country
 Cloud hosting provider IP (AWS/Azure/GCP)
 Residential proxy detected

Technical Indicators:

 Failed attempts before success
 API calls show automation (rapid succession)
 Non-standard user agent strings
 Direct API access (not via portal)


If expanding, run these queries:
kusto// Comprehensive threat hunting query
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add", "Update", "Delete", "Grant", "Remove")
| where Result == "success"
| summarize 
    Operations = count(),
    DistinctOps = dcount(OperationName),
    Resources = dcount(TargetResources[0].id),
    Actors = make_set(InitiatedBy.user.userPrincipalName)
  by bin(TimeGenerated, 1h), IPAddress
| where Operations > 10 or DistinctOps > 5
// Look for burst activity patterns
kusto// Cross-resource correlation
let suspiciousActor = "[ACTOR_UPN]";
let timeRange = 7d;
AuditLogs
| where TimeGenerated > ago(timeRange)
| where InitiatedBy.user.userPrincipalName == suspiciousActor
| summarize 
    ResourceTypes = make_set(TargetResources[0].type),
    OperationTypes = make_set(OperationName),
    Count = count()
  by bin(TimeGenerated, 30m)
| project TimeGenerated, ResourceTypes, OperationTypes, Count
| order by TimeGenerated asc
// Map out complete activity timeline

13F. COMMON ATTACK PATTERNS
Pattern 1: [Pattern Name - e.g., "Credential Spray + Resource Takeover"]
Observable Sequence:

Multiple failed sign-ins across different accounts (5-10 min)
Successful authentication to compromised account
Enumeration operations (List/Get) (1-2 min later)
[Specific operation on this resource]
Follow-on actions (token generation, data access, etc.)

Typical Timeline: 30-60 minutes from start to finish
Detection Opportunity: Step 3 (enumeration) is most reliable detection point
Indicators:

Source IP consistency across all steps
Rapid progression from compromise to action
Automation patterns in API calls


Pattern 2: [Pattern Name - e.g., "Insider Threat - Slow Burn"]
Observable Sequence:

Legitimate user performs normal duties
Gradual escalation: small permission increases over weeks
Access to resources outside normal scope
[Specific operation on this resource]
Data collection/exfiltration over extended period

Typical Timeline: Days to months
Detection Opportunity: Behavioral analytics, permission creep detection
Indicators:

Activity during business hours (harder to spot)
No obvious technical indicators of compromise
Justifiable individual actions, suspicious pattern overall


Pattern 3: [Pattern Name - e.g., "Supply Chain - CI/CD Compromise"]
Observable Sequence:

Modification to CI/CD pipeline or GitHub Actions
Service principal/federated credential activity
[Specific operation on this resource] from cloud IPs
Deployment of malicious configurations
Persistence through automated deployment

Typical Timeline: Minutes to hours
Detection Opportunity: Federated identity credential changes, CI/CD modifications
Indicators:

Service principal as actor (not user)
Activity from cloud provider IP ranges
Modifications to infrastructure-as-code


[Continue with 2-3 more common patterns specific to this resource]

13G. DOCUMENTATION REQUIREMENTS
Minimum Required Fields for Every Incident:
Incident Metadata:

 Incident ID: [Ticket number]
 Date/Time Detected: [Timestamp]
 Date/Time Occurred: [Timestamp from logs]
 Severity: [Critical/High/Medium/Low]
 Status: [Investigating/Contained/Resolved/Closed]
 Analyst: [Your name]

Technical Details:

 Alert Name/ID: [From SIEM]
 Actor Identity: [UPN or Service Principal]
 Actor Role/Permissions: [List roles]
 Target Resource: [Name and ID]
 Operation: [Specific OperationName]
 Source IP: [IP address]
 Source Location: [Geolocation]
 Device ID: [If applicable]
 User Agent: [If applicable]

Context:

 Business Justification: [Approved/Not Approved/Unknown]
 Change Ticket: [Link or "None"]
 Related Incidents: [Links to related tickets]
 MITRE ATT&CK Techniques: [T1234.567, T2345.678]

Investigation Summary:

 Timeline of Events: [Bulleted list with timestamps]
 Scope of Impact: [What was affected]
 Data/Permissions Accessed: [List what attacker gained access to]
 Root Cause: [How did this happen]

Evidence Links:

 Query Results: [Links to exported CSVs]
 Screenshots: [Links to key screenshots]
 Log Excerpts: [Relevant log entries]
 Configuration Snapshots: [Before/after if applicable]

Actions Taken:

 Investigation Steps: [Checklist of what you did]
 Containment Actions: [What commands were run]
 Escalations: [Who was notified and when]
 Resolution: [Final outcome]

Follow-Up Required:

 Additional Monitoring: [What and for how long]
 Remediation Tasks: [List with owners]
 Process Improvements: [Lessons learned]
 Detection Tuning: [Alert adjustments needed]


Documentation Template:
markdown## INCIDENT SUMMARY

**Incident ID**: INC0012345
**Detected**: 2024-10-21 14:32 UTC
**Occurred**: 2024-10-21 14:15 UTC
**Severity**: HIGH
**Status**: RESOLVED
**Analyst**: [Your Name]

## WHAT HAPPENED

[Brief 2-3 sentence summary of the incident]

## TIMELINE

- 14:15 UTC - [First suspicious activity]
- 14:18 UTC - [Second event]
- 14:32 UTC - Alert fired
- 14:35 UTC - Investigation began
- 14:50 UTC - Containment achieved
- 15:30 UTC - Root cause identified
- 16:00 UTC - Incident resolved

## TECHNICAL DETAILS

**Actor**: user@company.com (John Doe)
**Operation**: [Specific OperationName]
**Target**: [Resource name and ID]
**Source IP**: 203.0.113.45 (Moscow, Russia)
**MITRE ATT&CK**: T1098.001 - Additional Cloud Credentials

## INVESTIGATION FINDINGS

[Detailed findings from your investigation]

## CONTAINMENT ACTIONS

1. [Action taken at HH:MM]
2. [Action taken at HH:MM]
3. [Action taken at HH:MM]

## ROOT CAUSE

[Explanation of how this occurred]

## EVIDENCE

- [Link to query results CSV]
- [Link to screenshots]
- [Link to audit log exports]

## LESSONS LEARNED

[What we learned and how to prevent recurrence]

## FOLLOW-UP TASKS

- [ ] Task 1 (Owner: Name, Due: Date)
- [ ] Task 2 (Owner: Name, Due: Date)

13H. ANALYST NOTES
Known Issues & Gotchas:

[Resource Type] logs can be delayed:

Audit logs may take 5-15 minutes to appear
Don't assume absence means it didn't happen
Check again after waiting


[Specific operation] generates multiple events:

Single action may create 2-3 audit log entries
Look for CorrelationId to group related events
Don't double-count in analysis


Service accounts vs human users:

Service principals perform operations 24/7
Establish baselines for automated activity
Focus on CHANGES in service account behavior


False positive: [Common scenario]:

[Describe benign scenario that triggers alerts]
How to quickly identify: [Quick check]
Tuning recommendation: [How to reduce]



Tool Limitations:

Audit Log Retention: Default 30 days (90 with premium)

Older data not available via API
Archive logs externally for long-term retention


Query Performance:

Large time ranges (> 7 days) can timeout
Use smaller time windows and iterate
Consider exporting to separate analytics platform


Missing Context:

Some operations don't log full details
May need to query multiple log sources
Correlate with sign-in logs for complete picture



Quick Reference - High-Value Queries:
kusto// Your "go-to" investigative query
AuditLogs
| where TimeGenerated > ago(24h)
| where InitiatedBy.user.userPrincipalName == "[ACTOR]"
| summarize count() by OperationName, Result
| order by count_ desc
Escalation Contacts:

L2 Escalation: [Name/Team] - [Contact method]
After-Hours On-Call: [Phone number / PagerDuty]
Management Escalation: [Name] - [For critical incidents]
Microsoft Support: [How to engage if needed]

Additional Resources:

Internal Playbooks: [Link to wiki/confluence]
Microsoft Docs: [Link to relevant documentation]
Team Slack Channel: [#security-incidents]
MITRE ATT&CK: [Bookmark to techniques]

Historical Context:

Previous Incidents: [Links to similar past incidents]
Known Adversaries: [Threat intel on groups targeting your org]
Seasonal Patterns: [E.g., "Increased activity during holidays"]


Output Format Requirements

Use clear, actionable language suitable for both technical and non-technical audiences
Include specific operation names from the API documentation
Provide copy-paste ready detection queries with actual syntax
Use proper MITRE ATT&CK technique IDs with format T####.###
Include severity/priority indicators with color coding where helpful (🔴🟠🟡🟢)
Cross-reference related resources and explain relationships
Be comprehensive but focused on realistic, high-impact threats
Include both red team (attacker) and blue team (defender) perspectives
Use tables for comparison data and matrices
Use code blocks for queries, commands, and configurations
Use checklists for procedures and validation steps
Provide time estimates where applicable (especially for SOC work)


Additional Analysis Instructions

Prioritize realism: Focus on threats that have been seen in the wild or are highly plausible based on known attack patterns
Consider context: Think about how this resource interacts with the broader Microsoft 365/Azure/Entra ID ecosystem
Chain attacks: Show how multiple operations can be combined for greater impact across different tactics
Defense in depth: Provide multiple layers of controls (preventive, detective, response)
Detection gaps: Explicitly note what is difficult or impossible to detect and why
Assume breach mindset: Consider scenarios where attacker already has some level of access or has compromised an account
Privilege analysis: Clearly indicate what permissions/roles are required for each attack scenario
Time-based patterns: Note attacks that unfold slowly over time to evade detection vs rapid attacks
Real-world applicability: Prioritize threats and controls that security teams can actually implement and respond to
Compliance alignment: Map controls to common frameworks organizations must comply with


═══════════════════════════════════════════════════════════
PROMPT ENDS HERE
═══════════════════════════════════════════════════════════

CUSTOMIZATION SECTION (Optional)
To customize this analysis, add your preferences above the API documentation section:
Quick Customization Examples:
Example 1: SOC Focus
markdownINCLUDE SECTIONS: 1, 3, 6, 10, 13
OUTPUT FORMAT: Checklists, decision trees, time estimates
QUERY FORMAT: Both KQL and Splunk SPL
FOCUS: Immediate response and triage
Example 2: Red Team Focus
markdownINCLUDE SECTIONS: 2, 3, 4
EXCLUDE: All defensive content (5-13)
FOCUS: Exploitation techniques and attack chains
DEPTH: Technical implementation details
Example 3: Executive Summary
markdownINCLUDE SECTIONS: 1, 3, 7, 9
LENGTH: Maximum 3 pages
LANGUAGE: Business-friendly, minimal jargon
INCLUDE: Cost/ROI analysis for recommendations
Example 4: Detection Engineering
markdownINCLUDE SECTIONS: 2, 3, 6
QUERY FORMAT: KQL for Azure Sentinel
FOCUS: High-fidelity detections with low false positive rate
INCLUDE: Tuning guidance and testing procedures

Section Reference Menu
Use this to select specific sections:
Core Sections:

Section 1: Resource Overview
Section 2: Threat Analysis (by MITRE tactic)

2A: Initial Access
2B: Persistence
2C: Privilege Escalation
2D: Defense Evasion
2E: Credential Access
2F: Discovery
2G: Lateral Movement
2H: Collection
2I: Exfiltration
2J: Impact


Section 3: High-Risk Operation Matrix
Section 4: Attack Chains
Section 5: Security Controls

5A: Preventive
5B: Detective
5C: Response


Section 6: Detection Queries
Section 7: Risk Scoring Model
Section 8: Configuration Hardening
Section 9: Compliance & Governance
Section 10: Incident Response Playbook
Section 11: Additional Recommendations
Section 12: References & Tooling
Section 13: SOC Triage Guide (NEW)

13A: Decision Trees
13B: Investigation Checklist
13C: Evidence Collection
13D: Containment Options
13E: Expansion Triggers
13F: Attack Patterns
13G: Documentation
13H: Analyst Notes




Quick Selection Templates
Complete Analysis (Everything):
INCLUDE: ALL SECTIONS (1-13)
Threat Modeling Only:
INCLUDE: 1, 2, 3, 4
Defense Implementation:
INCLUDE: 1, 5, 8, 9
SOC Operations:
INCLUDE: 1, 3, 6, 10, 13
Incident Response:
INCLUDE: 1, 10, 13
Detection Engineering:
INCLUDE: 2, 3, 6
