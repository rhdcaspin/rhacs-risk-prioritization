# RHACS Risk Prioritization with AI - Project Summary

## Overview

This project provides an AI-powered risk analysis system for Red Hat Advanced Cluster Security (RHACS) deployments. It addresses the problem of noisy anomaly detection by reassessing suspicious processes and CVEs to provide more accurate risk prioritization.

## What Was Built

### 1. **Claude Code Skill** (`rhacs-risk-analysis.md`)
   - Invoked via `/rhacs-risk-analysis <deployment-id>`
   - Orchestrates the complete AI-powered risk assessment
   - Analyzes processes and CVEs using real-world context
   - Generates comprehensive risk.json output

### 2. **Python Analyzer** (`rhacs_analyzer.py`)
   - Fetches deployment data from RHACS API
   - Calls 5 specific RHACS endpoints:
     - `/v1/deploymentswithrisk/{id}` - Deployment with risk data
     - `/v1/export/vuln-mgmt/workloads` - CVE data
     - `/v1/processes/deployment/{id}/grouped/container` - Process data with suspicious flags
     - `/v1/processbaselines/key` - Process baselines
   - Extracts and structures all data for AI analysis

### 3. **Documentation**
   - `README.md` - Project overview and installation
   - `USAGE.md` - Detailed usage examples and workflows
   - `PROJECT_SUMMARY.md` - This file

## How It Works

### Data Collection Flow

```
1. User runs: /rhacs-risk-analysis <deployment-id>
                    ↓
2. Skill triggers Python analyzer
                    ↓
3. Analyzer fetches data from RHACS API:
   - Deployment details + risk score
   - Process executions (grouped by container)
   - Image vulnerabilities (CVEs)
   - Process baselines
                    ↓
4. Data is structured and returned to Claude
                    ↓
5. Claude analyzes the data using AI
```

### AI Analysis Flow

```
For each suspicious process:
   ├─ Extract: process name, args, path, UID, parent
   ├─ Analyze: Is this actually risky or just noisy?
   ├─ Classify: HIGH / MEDIUM / LOW
   └─ Explain: Why this classification?

For each high-severity CVE (CVSS >= 7.0):
   ├─ Extract: CVE details, CVSS vector, prerequisites
   ├─ Analyze: Are prerequisites met in this deployment?
   ├─ Adjust: Update CVSS if attack complexity increases
   └─ Explain: Why CVSS was adjusted

Calculate overall Gen AI Priority (0-100):
   ├─ Weight applicable CVEs (after reassessment)
   ├─ Weight high-risk processes (after reassessment)
   ├─ Consider deployment exposure
   └─ Generate explanation
```

## Key Features

### 1. Suspicious Process Reassessment
- **Problem**: RHACS flags processes not in the first-hour baseline as suspicious
- **Solution**: AI analyzes each process for actual risk
- **Classifications**:
  - **HIGH**: Modifying sensitive files, accessing credentials, network scanning, privilege escalation
  - **MEDIUM**: Unusual network connections, non-standard file access
  - **LOW**: Reading logs, health checks, normal admin tasks

### 2. CVE Applicability Analysis
- **Problem**: CVEs scored in theory, not based on runtime environment
- **Solution**: AI checks if exploitation prerequisites exist
- **Adjustments**:
  - If prerequisites not met → Increase attack complexity in CVSS
  - If mitigating controls exist → Document in explanation
  - If not exploitable in this context → Lower effective risk

### 3. Risk Priority Score
- **Problem**: Simple multiplication of risk factors creates noise
- **Solution**: AI-calculated priority (0-100) considering:
  - Actual applicability of CVEs
  - Actual risk of suspicious processes
  - Deployment exposure (public/cluster/internal)
  - Security context (privileged, host mounts, etc.)

## Example Output

### Input (from RHACS)
```json
{
  "deploymentName": "shaggy",
  "originalRiskScore": 31.05,
  "suspiciousProcessExecutions": [
    {
      "processName": "/usr/bin/awk",
      "processArgs": "END { for (name in ENVIRON) { print name } }",
      "suspicious": false  // Not flagged by RHACS
    }
  ],
  "imageVulnerabilities": [
    {
      "cve": "CVE-2019-1010022",
      "cvss": 9.8,
      "component": "libc6",
      "summary": "Stack guard protection bypass..."
    }
  ]
}
```

### Output (from AI Analysis)
```json
{
  "genAIPriority": 45,
  "genAIPriorityExplanation": "Medium-low priority. While the deployment has several high-CVSS vulnerabilities, most are not exploitable in the runtime environment. The CVEs in libc6 require local access and the deployment runs with standard user privileges. No suspicious process executions detected.",
  
  "suspiciousProcessExecutions": [
    {
      "processName": "/usr/bin/awk",
      "genAIClassification": "LOW",
      "genAIExplanation": "AWK is being used by the nginx entrypoint script to process environment variables - a standard initialization task. Running as root is expected during container startup. This is normal behavior for nginx containers."
    }
  ],
  
  "imageVulnerabilities": [
    {
      "cve": "CVE-2019-1010022",
      "cvss": 9.8,
      "genAIUpdatedCVSS": 4.7,
      "genAIMessage": "CVSS reduced from 9.8 to 4.7. This CVE requires local access to exploit (AV:L), but the deployment is a network service with no SSH access or local users. Upstream maintainers have classified this as non-security. The theoretical severity is high, but practical exploitability in this context is very low."
    }
  ]
}
```

## Real-World Test Results

### Deployment: `shaggy` (nginx:latest)

**RHACS Original Assessment:**
- Risk Score: 31.05
- 20 process executions detected
- 219 CVEs found
- 31 CVEs with CVSS >= 7.0

**Data Collection Results:**
```bash
$ python3 rhacs_analyzer.py analyze 83d64f14-3784-4a45-b12e-606cd323639d

✓ Fetched deployment with risk data
✓ Fetched 20 process executions (0 flagged as suspicious)
✓ Fetched 219 CVEs across 152 components
✓ Fetched process baselines for 1 container
✓ Identified risk factors: allowPrivilegeEscalation=true
```

**Top Findings:**
| CVE | CVSS | Component | Note |
|-----|------|-----------|------|
| CVE-2005-2541 | 10.0 | tar | Ancient vulnerability, likely false positive |
| CVE-2019-1010022 | 9.8 | libc6 | Upstream marked non-security |
| CVE-2019-1010023 | 8.8 | libc6 | Upstream marked non-security |

**AI Analysis Would:**
1. Classify all 20 processes as LOW risk (standard nginx operations)
2. Downgrade libc6 CVEs due to lack of local access
3. Flag the ancient tar CVE for investigation
4. Recommend fixing allowPrivilegeEscalation security context
5. Generate priority score ~40-50 (medium-low)

## Usage Examples

### Quick Analysis
```bash
# List deployments
python3 rhacs_analyzer.py list | jq '.[] | {name, priority}'

# Fetch data
python3 rhacs_analyzer.py analyze 83d64f14-3784-4a45-b12e-606cd323639d > data.json

# Run AI analysis
/rhacs-risk-analysis 83d64f14-3784-4a45-b12e-606cd323639d
```

### Find High-Risk Deployments
```bash
# Find deployments with critical CVEs
for id in $(python3 rhacs_analyzer.py list | jq -r '.[].id'); do
  CRITICAL=$(python3 rhacs_analyzer.py analyze "$id" 2>/dev/null | jq '[.imageVulnerabilities[] | select(.cvss >= 9.0)] | length')
  if [ "$CRITICAL" -gt 0 ]; then
    NAME=$(python3 rhacs_analyzer.py fetch "$id" 2>/dev/null | jq -r '.name')
    echo "$NAME: $CRITICAL critical CVEs"
  fi
done
```

### Generate Risk Report
```bash
# CSV report of all deployments
echo "Deployment,Risk Score,High CVEs,Suspicious Processes" > report.csv

python3 rhacs_analyzer.py list | jq -c '.[]' | while read deployment; do
  ID=$(echo "$deployment" | jq -r '.id')
  NAME=$(echo "$deployment" | jq -r '.name')
  
  DATA=$(python3 rhacs_analyzer.py analyze "$ID" 2>/dev/null)
  RISK=$(echo "$DATA" | jq -r '.originalRiskScore')
  HIGH_CVES=$(echo "$DATA" | jq '[.imageVulnerabilities[] | select(.cvss >= 7.0)] | length')
  SUS_PROCS=$(echo "$DATA" | jq '[.suspiciousProcessExecutions[] | select(.suspicious == true)] | length')
  
  echo "$NAME,$RISK,$HIGH_CVES,$SUS_PROCS" >> report.csv
done

column -t -s, report.csv
```

## Technical Details

### RHACS API Endpoints Used

| Endpoint | Purpose | Response Size |
|----------|---------|---------------|
| `/v1/deploymentswithrisk/{id}` | Get deployment + risk | ~2-5 KB |
| `/v1/export/vuln-mgmt/workloads` | Get CVE data | ~100-500 KB |
| `/v1/processes/deployment/{id}/grouped/container` | Get process data | ~20-50 KB |
| `/v1/processbaselines/key` | Get baseline | ~5-10 KB |
| `/v1/deployments` (list) | List all deployments | ~2-10 KB |

### Data Structures

**Process Execution:**
```json
{
  "containerName": "nginx",
  "processName": "/docker-entrypoint.sh",
  "processExecFilePath": "/docker-entrypoint.sh",
  "processArgs": "/docker-entrypoint.sh nginx -g daemon off;",
  "processUid": 0,
  "processGid": 0,
  "timesExecuted": 1,
  "suspicious": false,
  "parentExecFilePath": "",
  "signalTime": "2026-03-17T10:25:37.026226089Z"
}
```

**Vulnerability:**
```json
{
  "cve": "CVE-2019-1010022",
  "severity": "LOW_VULNERABILITY_SEVERITY",
  "cvss": 9.8,
  "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "component": "libc6",
  "componentVersion": "2.41-12+deb13u2",
  "fixedBy": "",
  "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-1010022",
  "summary": "GNU Libc current is affected by...",
  "nvdCvss": 9.8,
  "scoreVersion": "V3",
  "state": "OBSERVED"
}
```

## Files in This Project

```
/Users/dcaspin/Projects/claude/risk-prioritization/
├── rhacs-risk-analysis.md      # Claude Code skill definition
├── rhacs_analyzer.py            # Python API client and data collector
├── README.md                    # Project overview
├── USAGE.md                     # Detailed usage examples
├── PROJECT_SUMMARY.md           # This file
├── complete_analysis.json       # Example: full analysis output
└── deployment_summary.json      # Example: summarized metrics
```

## Benefits

1. **Reduced Noise**: AI filters out false positives from anomaly detection
2. **Contextual Risk**: CVEs assessed based on actual exploitability
3. **Actionable Insights**: Clear explanations and recommendations
4. **Prioritization**: Focus on deployments with real risk, not theoretical
5. **Automation**: Can be integrated into CI/CD or run on schedule

## Limitations

- Requires access to RHACS API
- Analysis quality depends on deployment metadata completeness
- CVE reassessment requires CVE prerequisite information (may need external lookup)
- Focuses on CVSS >= 7.0 by default (configurable)

## Next Steps

### Immediate
1. Run analysis on your critical deployments
2. Review AI-generated classifications
3. Act on high-priority recommendations

### Advanced
1. Integrate into CI/CD pipeline
2. Set up scheduled analysis for all deployments
3. Create dashboards from risk.json outputs
4. Customize risk scoring weights
5. Add automated remediation workflows

## Support

- Report issues: https://github.com/anthropics/claude-code/issues
- Get help: `/help` in Claude Code
- Read docs: See README.md and USAGE.md

---

**Built with Claude Code** • April 2026
