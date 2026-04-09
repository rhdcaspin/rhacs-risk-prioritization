# RHACS Risk Analysis - Quick Start Guide

## What This Does

Analyzes RHACS deployments using AI to:
- Reassess "suspicious" processes for actual risk
- Evaluate CVE applicability in runtime environment
- Calculate accurate risk priority scores

## 30-Second Start

```bash
# 1. Install dependencies
pip install requests urllib3

# 2. List deployments
python3 rhacs_analyzer.py list | jq -r '.[] | "\(.id) - \(.name)"'

# 3. Analyze one deployment
python3 rhacs_analyzer.py analyze <deployment-id> > data.json

# 4. View summary
jq '{name: .deploymentName, risk: .originalRiskScore, processes: (.suspiciousProcessExecutions|length), cves: (.imageVulnerabilities|length)}' data.json
```

## Using the Claude Code Skill

```bash
/rhacs-risk-analysis <deployment-id>
```

This runs full AI analysis and generates `risk.json` with:
- `genAIPriority` (0-100 risk score)
- `genAIPriorityExplanation` (why this score)
- Process classifications (HIGH/MEDIUM/LOW)
- CVE reassessments (adjusted CVSS scores)
- Actionable recommendations

## Example

```bash
$ python3 rhacs_analyzer.py list | head -5
[
  {
    "id": "83d64f14-3784-4a45-b12e-606cd323639d",
    "name": "shaggy",
    "cluster": "staging-secured-cluster",
    "priority": "130"
  }
]

$ python3 rhacs_analyzer.py analyze 83d64f14-3784-4a45-b12e-606cd323639d > data.json

$ jq '.suspiciousProcessExecutions[0]' data.json
{
  "containerName": "nginx",
  "processName": "/docker-entrypoint.sh",
  "processExecFilePath": "/docker-entrypoint.sh",
  "processArgs": "/docker-entrypoint.sh nginx -g daemon off;",
  "processUid": 0,
  "timesExecuted": 1,
  "suspicious": false
}

$ jq '[.imageVulnerabilities[] | select(.cvss >= 7.0)] | length' data.json
31

$ /rhacs-risk-analysis 83d64f14-3784-4a45-b12e-606cd323639d
# Claude analyzes and generates risk.json with AI assessments
```

## Output Files

- **deployment_data.json** - Raw data from RHACS API
- **risk.json** - AI-enhanced risk assessment
- **report.csv** - Bulk analysis results (if generated)

## Common Queries

### Find deployments with critical CVEs
```bash
for id in $(python3 rhacs_analyzer.py list | jq -r '.[].id | select(. != null)'); do
  CRITICAL=$(python3 rhacs_analyzer.py analyze "$id" 2>/dev/null | jq '[.imageVulnerabilities[]|select(.cvss>=9)]|length')
  [ "$CRITICAL" -gt 0 ] && echo "$id has $CRITICAL critical CVEs"
done
```

### List high-severity unfixed CVEs
```bash
jq '[.imageVulnerabilities[] | select(.cvss >= 7.0 and .fixedBy == "")] | group_by(.component) | map({component: .[0].component, count: length, max_cvss: map(.cvss)|max})' data.json
```

### Find processes running as root
```bash
jq '[.suspiciousProcessExecutions[] | select(.processUid == 0)] | map(.processName) | unique' data.json
```

## Project Files

- `rhacs-risk-analysis.md` - Claude Code skill
- `rhacs_analyzer.py` - Python API client
- `README.md` - Full documentation
- `USAGE.md` - Detailed examples
- `PROJECT_SUMMARY.md` - Technical overview
- `QUICKSTART.md` - This file

## Next Steps

1. Read `PROJECT_SUMMARY.md` for technical details
2. Read `USAGE.md` for advanced workflows
3. Run AI analysis: `/rhacs-risk-analysis <id>`
4. Review generated `risk.json`
5. Act on recommendations

## Key Concepts

**Process Reassessment:**
- RHACS flags processes not in baseline (first hour) as suspicious
- AI reassesses each process for actual risk
- Reduces false positives from legitimate admin tasks

**CVE Reassessment:**
- RHACS scores CVEs theoretically (from NVD)
- AI checks if exploitation prerequisites exist
- Adjusts CVSS for runtime context

**Gen AI Priority:**
- 0-100 score based on real risk, not theoretical
- Considers applicable CVEs + risky processes + exposure
- Helps prioritize which deployments need attention

## Troubleshooting

**No CVEs found?**
- Deployment may have no vulnerabilities (rare)
- Check: `jq '.images' data.json`

**No processes found?**
- Deployment may be inactive
- Check: `jq '.inactive' data.json`

**API errors?**
- Verify token is valid
- Check: `curl -k -H "Authorization: Bearer <token>" https://staging.demo.stackrox.com/v1/deployments | jq .`

## Help

- Get help: `/help` in Claude Code
- Report issues: https://github.com/anthropics/claude-code/issues
