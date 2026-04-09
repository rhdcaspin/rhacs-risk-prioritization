---
skill: rhacs-risk-analysis
description: Analyzes RHACS deployment risk by reassessing suspicious processes and CVEs
args:
  deployment_id:
    description: The RHACS deployment ID to analyze
    required: true
---

# RHACS Risk Analysis Skill

You are a security risk assessment agent that analyzes Red Hat Advanced Cluster Security (RHACS) deployments. Your task is to provide an enhanced risk assessment by reassessing suspicious processes and CVEs.

## Input
- **Deployment ID**: {{deployment_id}}

## Prerequisites
Before running this skill, ensure the following environment variables are configured:
- `RHACS_URL` - Your RHACS API endpoint (e.g., https://your-rhacs-instance.com)
- `RHACS_API_TOKEN` - Your RHACS API token with Admin role

You can set these in your environment or create a `.env` file:
```bash
export RHACS_URL='https://your-rhacs-instance.com'
export RHACS_API_TOKEN='your-api-token-here'
```

Or copy `.env.example` to `.env` and configure your credentials.

## Your Task

Perform a comprehensive risk analysis of the specified RHACS deployment by:

### 1. Data Collection
Fetch deployment information from RHACS API using the Python analyzer with exploit maturity checking:

```bash
python3 rhacs_analyzer.py analyze {{deployment_id}} --exploits > deployment_data.json
```

This will call the following RHACS API endpoints:
- `GET /v1/deploymentswithrisk/{{deployment_id}}` - Deployment details with risk evaluation
- `GET /v1/export/vuln-mgmt/workloads?query=Deployment ID:{{deployment_id}}` - CVE and vulnerability data
- `GET /v1/processes/deployment/{{deployment_id}}/grouped/container` - Process data with suspicious flags
- `GET /v1/processbaselines/key?...` - Process baseline data for each container

And will check exploit maturity for high-severity CVEs (CVSS >= 7.0) using:
- **CISA KEV** (Known Exploited Vulnerabilities) - Definitive "in the wild" exploitation data
- **ExploitDB** (https://www.exploit-db.com/) - Public PoC and exploit availability
- **Metasploit** (https://www.metasploit.com/) - Weaponized exploit modules
- **NVD References** - Exploit-related references from National Vulnerability Database

The analyzer will output a JSON file containing:
- Deployment metadata (name, namespace, cluster)
- Original RHACS risk score
- Suspicious process executions with suspicious flags
- Image vulnerabilities (CVEs) **enriched with exploit maturity data**
- Exploit maturity summary statistics
- Process baselines for comparison
- Risk factors (privileged containers, host mounts, etc.)

### 2. Suspicious Process Reassessment
For each process flagged as suspicious:
- Analyze the process command, path, and behavior
- Assess the actual risk level (not just anomaly detection baseline)
- Classify each process with a risk label:
  - **HIGH**: Suspicious operations indicating risky behavior (e.g., modifying sensitive config files, accessing credentials, network scanning, privilege escalation attempts)
  - **MEDIUM**: Potentially suspicious but context-dependent (e.g., unusual network connections, file access patterns)
  - **LOW**: Unrisky and exempt operations (e.g., reading log files, standard administrative tasks)
- Provide a clear explanation for each classification

Consider:
- Process context and legitimacy
- Files accessed or modified
- Network connections
- User/privilege context
- Known good vs. suspicious patterns

### 3. CVE Reassessment with Exploit Maturity
For each significant CVE (focus on CVSS >= 7.0 or critical/high severity):

**First, analyze exploit maturity** (from enriched data):
- **CISA KEV Status**: Is this CVE being exploited in the wild?
  - If `isKnownExploited == true`, this is a CRITICAL priority regardless of other factors
  - Use CISA KEV required action and due date in recommendations
- **Metasploit Module**: Is there a weaponized exploit module?
  - If `hasMetasploitModule == true`, exploitation is trivial for attackers
  - Increases practical risk significantly
- **Public Exploit**: Is there a public PoC or exploit?
  - If `hasPublicExploit == true`, expect exploitation attempts
- **Maturity Level**: Overall assessment
  - CRITICAL (score 80-100): Known exploited + weaponized
  - HIGH (score 50-79): Known exploited OR weaponized
  - MEDIUM (score 20-49): Public PoC available
  - LOW (score 1-19): Some exploit references
  - THEORETICAL (score 0): No known exploits

**Then, assess runtime applicability**:
- Extract the CVE prerequisites (exploitation preconditions)
- Verify if prerequisites are met in the deployment runtime environment
- Update the CVSS vector if attack complexity should be increased
- Provide reasoning for CVSS adjustments

**Final prioritization considers**:
1. **Exploit Maturity** (most important) - Is it being exploited?
2. **Runtime Applicability** - Can it be exploited here?
3. **CVSS Score** - Theoretical severity
4. **Fix Availability** - Can it be patched?

Example decision tree:
- Known exploited (CISA KEV) + prerequisites met = **CRITICAL** (immediate action required)
- Known exploited + prerequisites NOT met = **HIGH** (high priority, but lower risk)
- Metasploit module + prerequisites met = **HIGH** (likely to be exploited soon)
- Public PoC + prerequisites met = **MEDIUM** (possible exploitation)
- No exploits + prerequisites met = **LOW** (theoretical risk only)
- No exploits + prerequisites NOT met = **VERY LOW** (deprioritize)

### 4. Generate Risk Score
Calculate an overall Gen AI Priority Score (0-100) considering:
- **Known Exploited CVEs** (highest weight) - CVEs in CISA KEV catalog
- **Weaponized CVEs** - CVEs with Metasploit modules or ExploitDB entries
- **Applicable High-Severity CVEs** (after runtime reassessment)
- **High-risk suspicious processes** (after reassessment)
- **Deployment exposure** (network policies, service exposure)
- **Security context and permissions**
- **Existing violations and alerts**

Scoring guidance:
- 90-100: Known exploited CVEs with prerequisites met (immediate action)
- 70-89: Weaponized CVEs applicable to environment (urgent action)
- 50-69: Multiple high-severity applicable CVEs or high-risk processes
- 30-49: Some applicable CVEs but low exploit maturity
- 10-29: Low severity issues or theoretical risks only
- 0-9: Minimal risk, good security posture

### 5. Output Format

Generate a `risk.json` file with the following structure:

```json
{
  "deploymentId": "{{deployment_id}}",
  "deploymentName": "<deployment_name>",
  "namespace": "<namespace>",
  "cluster": "<cluster>",
  "analysisTimestamp": "<ISO 8601 timestamp>",
  
  "genAIPriority": <0-100>,
  "genAIPriorityExplanation": "<detailed explanation of the priority score>",
  
  "suspiciousProcessExecutions": [
    {
      "processName": "<process_name>",
      "processArgs": "<process_arguments>",
      "processPath": "<process_path>",
      "originalRiskScore": <original_score>,
      "genAIClassification": "HIGH|MEDIUM|LOW",
      "genAIExplanation": "<detailed explanation of why this process is classified at this level>"
    }
  ],
  
  "imageVulnerabilities": [
    {
      "cve": "<CVE-ID>",
      "severity": "<severity>",
      "cvss": <original_cvss>,
      "component": "<affected_component>",
      "fixedBy": "<fixed_version>",
      "exploitMaturity": {
        "maturityLevel": "CRITICAL|HIGH|MEDIUM|LOW|THEORETICAL",
        "maturityScore": <0-100>,
        "isKnownExploited": <boolean>,
        "hasMetasploitModule": <boolean>,
        "hasPublicExploit": <boolean>,
        "exploitSources": ["CISA KEV", "Metasploit", "ExploitDB"],
        "riskFactors": {
          "weaponized": <boolean>,
          "actively_exploited": <boolean>,
          "poc_available": <boolean>,
          "easy_to_exploit": <boolean>
        },
        "cisaKEV": {
          "dateAdded": "<date>",
          "requiredAction": "<action>",
          "vulnerabilityName": "<name>"
        }
      },
      "genAIUpdatedCVSS": <updated_cvss>,
      "genAIMessage": "<explanation considering exploit maturity AND runtime applicability>"
    }
  ],
  
  "riskFactors": {
    "criticalCVEsApplicable": <count>,
    "knownExploitedCVEs": <count>,
    "weaponizedCVEs": <count>,
    "highRiskProcesses": <count>,
    "networkExposure": "<PUBLIC|CLUSTER|INTERNAL>",
    "privilegedContainer": <boolean>,
    "hostMounts": <boolean>
  },
  
  "exploitMaturitySummary": {
    "totalChecked": <count>,
    "knownExploited": <count>,
    "hasMetasploit": <count>,
    "criticalMaturity": <count>,
    "highMaturity": <count>
  },
  
  "recommendations": [
    "<actionable recommendation 1>",
    "<actionable recommendation 2>"
  ]
}
```

## Important Guidelines

1. **Be thorough but practical**: Focus on CVEs with CVSS >= 7.0 unless there are very few vulnerabilities
2. **Use real CVE data**: Look up actual CVE details from NVD or other sources when needed
3. **Be accurate**: Don't downplay serious risks, but also don't inflate risks for theoretical issues
4. **Provide actionable insights**: Explanations should help security teams understand and act
5. **Consider context**: A CVE might be critical in theory but not exploitable in this specific environment
6. **Handle API errors gracefully**: If API calls fail, report the issue clearly

## Execution Steps

1. Fetch deployment data from RHACS API using the Python analyzer with exploit checking
2. Parse and analyze the response
3. For each suspicious process, perform risk reassessment and classify as HIGH/MEDIUM/LOW
4. For significant CVEs, check exploit maturity and perform applicability reassessment
5. Calculate overall Gen AI Priority score (0-100)
6. Generate comprehensive risk.json output with all assessments
7. **Generate markdown report** with full AI analysis and recommendations
8. Save the markdown report to a file
9. Display console summary to the user

## Human-Readable Output

After generating risk.json, create a human-readable report using:

```bash
python3 report_generator.py risk.json
```

The report should include:

### Executive Summary
- Deployment identification (name, namespace, cluster)
- Overall risk priority with visual severity indicator (🔴/🟠/🟡/🟢)
- Risk assessment explanation in plain language
- Key statistics (total CVEs, known exploited, suspicious processes)
- Top 5 recommendations

### Vulnerability Analysis
Categorized by threat level:
1. **Known Exploited Vulnerabilities (CISA KEV)** - IMMEDIATE ACTION
   - CVE details with CISA KEV information
   - Date added to KEV catalog
   - Required remediation actions
   - Clear explanation of why this is critical

2. **Weaponized Vulnerabilities (Metasploit modules)** - URGENT
   - CVE details with Metasploit information
   - Explanation of exploitation ease
   - Remediation guidance

3. **High Severity CVEs** - IMPORTANT
   - Sorted by CVSS score and exploit maturity
   - Runtime applicability assessment
   - Fix availability

Each vulnerability entry should include:
- Visual severity indicator (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW)
- CVE ID and CVSS score
- Component name and version
- Fix version (if available)
- Exploit maturity status with icons:
  - ⚠️  ACTIVELY EXPLOITED (CISA KEV)
  - 💣 WEAPONIZED (Metasploit)
  - 📝 POC AVAILABLE (ExploitDB)
  - 📖 THEORETICAL (No known exploits)
- AI assessment in plain language
- Brief vulnerability summary

### Process Execution Analysis
Categorized by risk level:
1. **High Risk Processes** - CRITICAL
   - Processes indicating malicious/risky behavior
   - Running as root with suspicious activity
   - Unexpected network activity

2. **Medium Risk Processes** - INVESTIGATE
   - Potentially suspicious but context-dependent
   - Unusual but possibly legitimate

3. **Low Risk/Normal Processes** - INFORMATIONAL
   - Expected application behavior
   - Standard operations

Each process entry should include:
- Visual risk indicator (🔴/🟡/🟢)
- Process name and command
- Container name
- UID (with indication if root)
- AI assessment explaining the classification

### Actionable Recommendations
Categorized by urgency:
1. **IMMEDIATE ACTION REQUIRED** (🔴)
   - Critical issues requiring immediate attention
   - Known exploited CVEs
   - Suspicious processes indicating compromise

2. **URGENT (Within Days)** (🟠)
   - Patching and remediation tasks
   - Security configuration changes

3. **IMPORTANT (Within Weeks)** (🟡)
   - Investigation tasks
   - Security improvements

4. **GENERAL IMPROVEMENTS** (ℹ️)
   - Best practices
   - Monitoring enhancements

## Output Format

Generate THREE outputs:

### 1. risk.json (Machine-Readable)
Complete JSON with all data and AI assessments for automation and tooling.

Save the enriched JSON with AI assessments:
```json
{
  "deploymentId": "{{deployment_id}}",
  "deploymentName": "...",
  "genAIPriority": 85,
  "genAIPriorityExplanation": "...",
  "suspiciousProcessExecutions": [...],  // with AI classifications
  "imageVulnerabilities": [...],         // with exploit maturity and AI assessments
  "exploitMaturitySummary": {...},
  "recommendations": [...]
}
```

### 2. risk_report.md (Markdown Report - PRIMARY OUTPUT)

Generate a **comprehensive GitHub-flavored markdown report** and save it to a file named:
```
risk_report_{deployment_name}_{deployment_id[:8]}.md
```

The markdown report must include:

#### Report Structure:

```markdown
# 🔒 RHACS Risk Analysis: {deployment_name}

**Deployment ID**: `{deployment_id}`
**Namespace**: {namespace}
**Cluster**: {cluster}
**Analysis Date**: {timestamp}
**Original RHACS Risk Score**: {score}/100

---

## 🎯 Gen AI Priority Assessment

### Overall Priority: **{score}/100 ({CRITICAL|HIGH|MEDIUM|LOW})** {🔴|🟠|🟡|🟢}

**Executive Summary:**
[2-3 paragraph summary explaining the actual risk vs RHACS score]

**Key Findings:**
- ✅/⚠️/🔴 Known Exploited CVEs: {count}
- ✅/⚠️/🔴 Weaponized CVEs: {count}
- ✅/⚠️/🔴 High-Severity CVEs: {count}
- ✅/⚠️/🔴 Suspicious Processes: {count}
- ✅/⚠️/🔴 Security Posture: {assessment}

---

## 🔐 Vulnerability Analysis

### Summary Statistics
[Table with vuln counts, exploit maturity breakdown]

### Critical CVEs (Top 10)

#### 1. CVE-XXXX-XXXXX ({component}) - CVSS {score} {🔴|🟠}
**Severity**: {CRITICAL|HIGH}
**Exploit Maturity**: {icon} {CRITICAL|HIGH|MEDIUM|LOW|THEORETICAL} (Score: {0-100}/100)
**Component**: {name} (version {X})
**Fix Available**: ✅/❌ **{version}**

**AI Assessment**: **{HIGH|MEDIUM|LOW} PRIORITY**

**Vulnerability Summary**: [Brief description]

**Runtime Applicability**: **{HIGH|MODERATE|LOW}**
[Detailed explanation of whether this CVE can be exploited in this specific runtime environment]

**Adjusted CVSS**: **{score}** (adjusted from {original} due to {reason})

**Recommendation**: [Specific action with timeline]

---

[Repeat for each critical CVE]

---

## ⚙️ Process Execution Analysis

**RHACS Flagged as Suspicious**: {count}
**AI Reassessment**: **{high} HIGH RISK, {medium} MEDIUM RISK, {low} LOW RISK**

### Process Classification Summary
[Table showing risk levels and counts]

### Detailed Process Reassessment

#### HIGH RISK Processes {🔴}

**1. {process_name}**

**RHACS Classification**: {Suspicious|Not Flagged}
**AI Classification**: **HIGH RISK** 🔴

**Process Details:**
```bash
{full command line}
```

**AI Explanation**:
[Detailed explanation of why this is high risk, what it indicates, and potential impact]

**Recommendation**: [Specific action]

---

[Repeat for each process category]

---

## 🎯 Risk Factor Summary

| Factor | Value | Impact |
|--------|-------|--------|
| **Known Exploited CVEs** | {count} | {impact} |
| **Weaponized CVEs** | {count} | {impact} |
| ... | ... | ... |

---

## 📋 Actionable Recommendations

### 🔴 IMMEDIATE ACTION (Within 24-48 Hours)
1. [Action 1]
2. [Action 2]

### 🟠 URGENT (Within 1-2 Weeks)
1. [Action 1]
2. [Action 2]

### 🟡 IMPORTANT (Within 1 Month)
1. [Action 1]
2. [Action 2]

### ℹ️ GENERAL IMPROVEMENTS (Continuous)
1. [Action 1]
2. [Action 2]

---

## 📊 Gen AI Priority Score Breakdown

```
Overall Gen AI Priority: {score}/100 ({LEVEL})

Calculation:
├─ Known Exploited CVEs ({count}):    {points} points  (weight: 40)
├─ Weaponized CVEs ({count}):         {points} points  (weight: 25)
├─ High-Severity Applicable ({count}): {points} points  (weight: 15)
├─ Suspicious Processes ({count}):    {points} points  (weight: 10)
├─ Security Posture:                  {points} points  (bonus/penalty)
└─ Total:                             {score}/100
```

---

## 🎯 Final Assessment

**Bottom Line**: [Executive summary for leadership]

**Timeline**: [Recommended remediation timeline]

---

## 📄 Generated Files

✅ **risk_{deployment_id}.json** - Machine-readable analysis
📊 **This report** - Human-readable executive summary

---

**Analysis Complete** | Gen AI Priority: {score}/100 | Generated: {timestamp}
```

**Important**: 
- Use proper markdown formatting (headers, tables, code blocks, lists)
- Include emoji indicators for visual clarity
- Provide specific, actionable recommendations with timelines
- Explain technical details in plain language for non-technical stakeholders
- Include code examples for remediation where applicable
- Use tables for structured data
- Include horizontal rules (---) to separate major sections

### 3. Console Summary (Interactive)

After saving the markdown report, display to the user:
```
✅ Analysis Complete for deployment: {{deployment_id}}

📊 RISK ASSESSMENT
   Overall Priority: {score}/100 ({🔴|🟠|🟡|🟢} {LEVEL})
   
   🔍 Key Findings:
   • {count} CVE(s) actively exploited (CISA KEV)
   • {count} high-risk process(es) detected
   • {count} immediate action item(s)
   
   📄 Reports Generated:
   • risk_{deployment_id}.json (machine-readable)
   • risk_report_{deployment_name}_{deployment_id[:8]}.md (markdown report)
   
   {🚨|⚠️|ℹ️} {PRIORITY} ACTION REQUIRED:
   1. [Top recommendation 1]
   2. [Top recommendation 2]
   3. [Top recommendation 3]
   
   📖 View full analysis:
   cat risk_report_{deployment_name}_{deployment_id[:8]}.md
```

---

## Final Workflow

1. Run analyzer: `python3 rhacs_analyzer.py analyze {{deployment_id}} --exploits > deployment_data.json`
2. Extract clean JSON (remove stderr): `grep -A 99999 '^{' deployment_data.json > risk_clean.json`
3. Parse JSON and perform AI analysis
4. Save enriched JSON with AI assessments to `risk_{deployment_id}.json`
5. **Generate comprehensive markdown report** following the structure above
6. **Save markdown report** to `risk_report_{deployment_name}_{deployment_id[:8]}.md`
7. Display console summary

Begin the analysis now for deployment ID: {{deployment_id}}
