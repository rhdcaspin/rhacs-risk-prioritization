#!/bin/bash
# Demonstration of RHACS Risk Analysis Skill

echo "=== RHACS Risk Analysis Demonstration ==="
echo

# Step 1: List deployments
echo "Step 1: Listing available deployments..."
python3 rhacs_analyzer.py list 2>/dev/null | jq -r '.[] | "\(.name) (\(.id))"' | head -3
echo

# Step 2: Analyze a deployment
DEPLOYMENT_ID="83d64f14-3784-4a45-b12e-606cd323639d"
echo "Step 2: Analyzing deployment $DEPLOYMENT_ID..."
python3 rhacs_analyzer.py analyze "$DEPLOYMENT_ID" 2>/dev/null > demo_analysis.json
echo "✓ Data collected"
echo

# Step 3: Show summary
echo "Step 3: Summary Statistics"
jq '{
  deployment: .deploymentName,
  namespace: .namespace,
  risk_score: .originalRiskScore,
  statistics: {
    processes: (.suspiciousProcessExecutions | length),
    total_cves: (.imageVulnerabilities | length),
    critical_cves: ([.imageVulnerabilities[] | select(.cvss >= 9.0)] | length),
    high_cves: ([.imageVulnerabilities[] | select(.cvss >= 7.0 and .cvss < 9.0)] | length)
  }
}' demo_analysis.json
echo

# Step 4: Show top CVEs
echo "Step 4: Top 3 CVEs by CVSS"
jq '[.imageVulnerabilities[] | select(.cvss >= 7.0)] | sort_by(-.cvss) | .[0:3] | .[] | "  \(.cve): CVSS \(.cvss) in \(.component)"' -r demo_analysis.json
echo

# Step 5: Show sample processes
echo "Step 5: Sample Processes (first 3)"
jq '.suspiciousProcessExecutions[0:3] | .[] | "  \(.processName) (UID: \(.processUid), suspicious: \(.suspicious))"' -r demo_analysis.json
echo

echo "=== Next Steps ==="
echo "Run AI analysis with: /rhacs-risk-analysis $DEPLOYMENT_ID"
echo "This will generate risk.json with:"
echo "  - Gen AI Priority Score (0-100)"
echo "  - Process risk classifications (HIGH/MEDIUM/LOW)"
echo "  - CVE applicability assessments"
echo "  - Actionable recommendations"
echo

rm -f demo_analysis.json
