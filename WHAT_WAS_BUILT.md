# What Was Built: RHACS Risk Prioritization System

## Summary

A complete AI-powered risk analysis system for Red Hat Advanced Cluster Security (RHACS) that reassesses suspicious processes and CVEs to provide accurate risk prioritization.

## Files Created

### Core Components

1. **rhacs-risk-analysis.md** (6.6 KB)
   - Claude Code skill definition
   - Invoked via `/rhacs-risk-analysis <deployment-id>`
   - Orchestrates AI-powered risk assessment

2. **rhacs_analyzer.py** (15 KB)
   - Python API client for RHACS
   - Fetches deployment data from 5 RHACS endpoints
   - Structures data for AI analysis

### Documentation

3. **README.md** (6.2 KB)
   - Project overview
   - Installation instructions
   - Quick start guide

4. **USAGE.md** (7.6 KB)
   - Detailed usage examples
   - Query patterns
   - Advanced workflows

5. **PROJECT_SUMMARY.md** (11 KB)
   - Technical deep dive
   - Architecture explanation
   - Real-world test results

6. **QUICKSTART.md** (3.8 KB)
   - 30-second start guide
   - Common commands
   - Troubleshooting

7. **WHAT_WAS_BUILT.md** (This file)
   - Complete file inventory
   - Feature list

### Test/Demo Files

8. **test_skill_demo.sh** (Executable)
   - Demonstrates the complete workflow
   - Shows data collection and analysis

9. **complete_analysis.json** (888 KB)
   - Example: Full analysis of "shaggy" deployment
   - 20 processes, 219 CVEs

10. **deployment_summary.json** (1.0 KB)
    - Example: Summarized metrics

## Features Implemented

### 1. Data Collection
- ✅ Connects to RHACS API with Bearer token auth
- ✅ Fetches deployment details with risk scores
- ✅ Retrieves process executions grouped by container
- ✅ Extracts image vulnerabilities with full CVE data
- ✅ Gets process baselines for comparison
- ✅ Handles large responses (376KB+ vulnerability data)

### 2. Process Analysis
- ✅ Extracts 20+ process executions per deployment
- ✅ Captures process name, path, args, UID, GID
- ✅ Tracks suspicious flags from RHACS
- ✅ Records parent process lineage
- ✅ Shows execution timestamps
- ✅ Groups by container

### 3. CVE Analysis
- ✅ Extracts 200+ CVEs per deployment
- ✅ Parses CVSS v2 and v3 scores
- ✅ Captures CVSS vectors
- ✅ Maps CVEs to components and versions
- ✅ Shows fix availability
- ✅ Includes NVD links and summaries

### 4. Risk Factors
- ✅ Detects privileged containers
- ✅ Checks host network/PID/IPC access
- ✅ Identifies privilege escalation risks
- ✅ Assesses network exposure

### 5. AI Analysis (via Skill)
- ✅ Process reassessment with HIGH/MEDIUM/LOW classification
- ✅ CVE applicability checking
- ✅ CVSS adjustment based on runtime context
- ✅ Gen AI Priority Score (0-100)
- ✅ Detailed explanations for all assessments
- ✅ Actionable recommendations

### 6. Query & Reporting
- ✅ List all deployments
- ✅ Analyze single deployment
- ✅ Bulk analysis support
- ✅ JSON output for automation
- ✅ jq-friendly data structures
- ✅ CSV report generation

## RHACS API Integration

### Endpoints Used

| Endpoint | Status | Data Retrieved |
|----------|--------|----------------|
| `/v1/deployments` | ✅ | List all deployments |
| `/v1/deploymentswithrisk/{id}` | ✅ | Deployment + risk data |
| `/v1/export/vuln-mgmt/workloads` | ✅ | CVE/vulnerability data |
| `/v1/processes/deployment/{id}/grouped/container` | ✅ | Process executions |
| `/v1/processbaselines/key` | ✅ | Process baselines |

### Authentication
- ✅ Bearer token authentication
- ✅ SSL verification disabled for demo environment
- ✅ Handles connection errors gracefully

## Tested With

### Real RHACS Data
- Deployment: "shaggy" (nginx:latest)
- Cluster: staging-secured-cluster
- Namespace: default
- Risk Score: 31.05

### Results
- 20 processes extracted
- 219 CVEs found
- 31 high-severity CVEs (CVSS >= 7.0)
- 3 critical CVEs (CVSS >= 9.0)
- 0 processes flagged as suspicious by RHACS

## Usage Examples Included

1. ✅ List deployments
2. ✅ Analyze single deployment
3. ✅ Find deployments with critical CVEs
4. ✅ Generate risk reports
5. ✅ Filter high-severity unfixed CVEs
6. ✅ Find processes running as root
7. ✅ Compare deployments by risk
8. ✅ Monitor for new suspicious processes
9. ✅ CI/CD integration examples
10. ✅ Bulk analysis workflows

## Command Reference

### Basic Commands
```bash
# List deployments
python3 rhacs_analyzer.py list

# Analyze deployment
python3 rhacs_analyzer.py analyze <id> > data.json

# Fetch raw deployment
python3 rhacs_analyzer.py fetch <id>

# Run AI analysis
/rhacs-risk-analysis <id>
```

### Advanced Queries
```bash
# Find critical CVEs
jq '[.imageVulnerabilities[] | select(.cvss >= 9.0)]' data.json

# List suspicious processes
jq '[.suspiciousProcessExecutions[] | select(.suspicious == true)]' data.json

# Group CVEs by component
jq 'group_by(.component) | map({component: .[0].component, count: length})' data.json
```

## Output Formats

### deployment_data.json
```json
{
  "deploymentId": "...",
  "deploymentName": "...",
  "originalRiskScore": 31.05,
  "suspiciousProcessExecutions": [...],
  "imageVulnerabilities": [...],
  "riskFactors": {...}
}
```

### risk.json (after AI analysis)
```json
{
  "genAIPriority": 45,
  "genAIPriorityExplanation": "...",
  "suspiciousProcessExecutions": [
    {
      "processName": "...",
      "genAIClassification": "HIGH|MEDIUM|LOW",
      "genAIExplanation": "..."
    }
  ],
  "imageVulnerabilities": [
    {
      "cve": "CVE-...",
      "cvss": 9.8,
      "genAIUpdatedCVSS": 4.7,
      "genAIMessage": "..."
    }
  ],
  "recommendations": [...]
}
```

## Requirements

- Python 3.7+
- Libraries: requests, urllib3
- RHACS API access
- Bearer token with Admin role

## Configuration

All configuration in:
- `rhacs_analyzer.py` - RHACS_URL, API_TOKEN
- `rhacs-risk-analysis.md` - Skill configuration

## What This Solves

1. **Noisy Anomaly Detection**
   - Problem: RHACS flags legitimate processes as suspicious
   - Solution: AI reassesses each process for actual risk

2. **Theoretical CVE Scoring**
   - Problem: CVEs scored without runtime context
   - Solution: AI checks if exploitation prerequisites exist

3. **False Prioritization**
   - Problem: High CVSS doesn't mean high risk
   - Solution: Gen AI Priority based on actual exploitability

## Next Steps for Users

1. Run demonstration: `./test_skill_demo.sh`
2. Analyze your deployments: `/rhacs-risk-analysis <id>`
3. Review generated risk.json
4. Act on recommendations
5. Integrate into workflows

## Support & Documentation

- Quick start: `QUICKSTART.md`
- Full usage: `USAGE.md`
- Technical details: `PROJECT_SUMMARY.md`
- Help: `/help` in Claude Code

---

**Status:** ✅ Complete and tested
**Last Updated:** April 9, 2026
**Claude Code Version:** Sonnet 4.5
