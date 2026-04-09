# RHACS Risk Prioritization with AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

AI-powered risk analysis for Red Hat Advanced Cluster Security (RHACS) deployments featuring exploit maturity analysis, process reassessment, and human-readable reports.

## 🌟 Key Features

- **🔍 Exploit Maturity Analysis** - Checks CVEs against CISA KEV, Metasploit, and ExploitDB
- **⚙️ Process Reassessment** - AI-powered HIGH/MEDIUM/LOW risk classification
- **🎯 CVE Applicability** - Runtime environment analysis with CVSS adjustment
- **📊 Human-Readable Reports** - Executive summaries with visual indicators
- **🤖 AI-Powered Scoring** - Gen AI Priority (0-100) based on actual exploitability

## 🚀 Quick Start

```bash
# Install dependencies
pip install requests urllib3

# List deployments
python3 rhacs_analyzer.py list

# Analyze with exploit checking
python3 rhacs_analyzer.py analyze <deployment-id> --exploits > analysis.json

# Generate human-readable report
python3 report_generator.py analysis.json

# View report
cat analysis_report.txt
```

## 📖 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in 30 seconds
- **[Exploit Maturity Guide](EXPLOIT_MATURITY.md)** - Understanding exploit analysis
- **[Human-Readable Reports](HUMAN_READABLE_REPORTS.md)** - Report formats and usage
- **[Complete Reference](COMPLETE_SYSTEM_SUMMARY.md)** - Full system documentation

## 🎯 What Problem Does This Solve?

Traditional vulnerability scanners prioritize by CVSS score alone:
- CVE with CVSS 9.8 but no exploits → **HIGH PRIORITY** ❌
- CVE with CVSS 7.0 actively exploited → **MEDIUM PRIORITY** ❌

This system checks if CVEs are **actually being exploited**:
- **CISA KEV** - Known exploited vulnerabilities (definitive "in the wild" data)
- **Metasploit** - Weaponized exploit modules (ready to use)
- **ExploitDB** - Public proof-of-concept code
- **NVD** - Exploit references

### Real-World Example

**Before:**
```
nginx deployment: 219 CVEs, 31 high-severity
→ Overwhelming, unclear priorities
```

**After:**
```
🟢 Priority: 40/100 (MEDIUM-LOW)
⚠️  Known Exploited: 0
💣 Weaponized: 0

All high-severity CVEs have THEORETICAL exploit maturity.
→ Focus on security config, not CVE remediation.
```

## 📊 Output Formats

### Machine-Readable JSON
For automation and tooling:
```json
{
  "genAIPriority": 85,
  "exploitMaturitySummary": {
    "knownExploited": 1,
    "hasMetasploit": 0
  }
}
```

### Human-Readable Report
For security teams and stakeholders:
```
════════════════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════════════

🟠 HIGH Overall Risk Priority: 85/100 (HIGH)

📦 Vulnerabilities:
   ⚠️  ACTIVELY EXPLOITED Known Exploited: 1

🔴 CRITICAL IMMEDIATE ACTION REQUIRED
1. URGENT: Update log4j-core to 2.17.1+ (CVE-2021-44228)
```

## 🔧 Components

### Core Tools

- **`rhacs_analyzer.py`** - RHACS API client with exploit integration
- **`exploit_checker.py`** - Exploit maturity analyzer (CISA KEV, Metasploit, ExploitDB)
- **`report_generator.py`** - Human-readable report generator
- **`rhacs-risk-analysis.md`** - Claude Code skill for AI analysis

### Usage

```bash
# Standalone exploit checking
python3 exploit_checker.py CVE-2021-44228 CVE-2019-0708

# RHACS deployment analysis
python3 rhacs_analyzer.py analyze <deployment-id> --exploits

# AI-powered analysis (Claude Code)
/rhacs-risk-analysis <deployment-id>
```

## 📈 Exploit Maturity Levels

| Level | Score | Meaning | Action |
|-------|-------|---------|--------|
| 🔴 **CRITICAL** | 80-100 | Known exploited + weaponized | Immediate |
| 🟠 **HIGH** | 50-79 | Known exploited OR weaponized | Urgent (days) |
| 🟡 **MEDIUM** | 20-49 | Public PoC available | Plan (weeks) |
| 🟢 **LOW** | 1-19 | Some exploit references | Monitor |
| 📖 **THEORETICAL** | 0 | No known exploits | Standard patching |

## 🎯 Visual Indicators

### Severity
- 🔴 **CRITICAL** (90-100) - Drop everything, fix now
- 🟠 **HIGH** (70-89) - Urgent, fix within days
- 🟡 **MEDIUM** (50-69) - Important, plan remediation
- 🟢 **LOW** (0-49) - Standard patching cycle

### Exploit Status
- ⚠️ **ACTIVELY EXPLOITED** - CISA KEV confirmed, in the wild
- 💣 **WEAPONIZED** - Metasploit module available
- 📝 **POC AVAILABLE** - Public proof-of-concept exists
- 📖 **THEORETICAL** - No known exploits

## 🔗 Integration Examples

### CI/CD Pipeline
```bash
python3 rhacs_analyzer.py analyze $DEPLOY_ID --exploits > analysis.json

if [ $(jq '.exploitMaturitySummary.knownExploited' analysis.json) -gt 0 ]; then
  echo "❌ FAILED: Known exploited CVEs detected"
  exit 1
fi
```

### Slack Notification
```python
from report_generator import ReportGenerator

generator = ReportGenerator(data)
summary = generator.generate_executive_summary()
send_to_slack(webhook_url, summary)
```

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- RHACS API access
- API token with Admin role

### Setup

```bash
# Clone repository
git clone https://github.com/rhdcaspin/rhacs-risk-prioritization.git
cd rhacs-risk-prioritization

# Install dependencies
pip install -r requirements.txt

# Configure (optional - demo credentials included)
cp .env.example .env
# Edit .env with your RHACS URL and API token
```

### Configuration

The project includes demo credentials for `staging.demo.stackrox.com`. For production use:

1. Copy `.env.example` to `.env`
2. Update `RHACS_URL` and `RHACS_API_TOKEN`
3. Update the constants in `rhacs_analyzer.py` if needed

## 📚 Examples

### Find Known Exploited CVEs
```bash
jq '[.imageVulnerabilities[] | select(.exploitMaturity.isKnownExploited)]' analysis.json
```

### Generate Executive Summary
```bash
python3 report_generator.py analysis.json
head -50 analysis_report.txt
```

### Check CVE Exploit Status
```bash
python3 exploit_checker.py CVE-2021-44228

Output:
  CVE-2021-44228 (Log4Shell)
  Maturity Level: HIGH
  Known Exploited: TRUE (CISA KEV)
  Maturity Score: 55/100
```

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **CISA** - Known Exploited Vulnerabilities Catalog
- **ExploitDB** - Offensive Security's exploit database
- **Metasploit** - Rapid7's penetration testing framework
- **NVD** - National Vulnerability Database
- **Claude Code** - AI-powered analysis and skill development

## 📞 Support

- **Documentation**: See the `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/rhdcaspin/rhacs-risk-prioritization/issues)
- **Discussions**: [GitHub Discussions](https://github.com/rhdcaspin/rhacs-risk-prioritization/discussions)

## 🔮 Roadmap

- [ ] ExploitDB database integration
- [ ] Metasploit module database scraping
- [ ] EPSS (Exploit Prediction Scoring System) integration
- [ ] HTML/PDF report generation
- [ ] Multi-deployment comparison
- [ ] Trend analysis over time
- [ ] Custom report templates

---

**Built with Claude Code** • 2026

Made with ❤️ for better security prioritization
