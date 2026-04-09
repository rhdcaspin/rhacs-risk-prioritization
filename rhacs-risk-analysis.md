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
7. **Generate human-readable report** using report_generator.py
8. Display both JSON and human-readable summary to the user

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

### 2. risk_report.txt (Human-Readable)
Formatted text report with visual indicators, clear explanations, and actionable recommendations for security teams.

### 3. Console Summary (Interactive)
Display to the user:
```
✅ Analysis Complete for deployment: {{deployment_id}}

📊 RISK ASSESSMENT
   Overall Priority: 85/100 (🟠 HIGH)
   
   🔍 Key Findings:
   • 1 CVE actively exploited (CISA KEV)
   • 1 high-risk process detected
   • 3 immediate action items
   
   📄 Full reports generated:
   • risk.json (machine-readable)
   • risk_report.txt (human-readable)
   
   🚨 IMMEDIATE ACTION REQUIRED:
   1. Update log4j-core to 2.17.1+ (CVE-2021-44228)
   2. Investigate wget process execution
   
   Run: cat risk_report.txt
   For full details and all recommendations.
```

Begin the analysis now for deployment ID: {{deployment_id}}
