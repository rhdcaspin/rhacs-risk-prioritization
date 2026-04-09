#!/usr/bin/env python3
"""
Human-Readable Report Generator
Generates clear, actionable reports from risk analysis data
"""

import json
from typing import Dict, List, Any
from datetime import datetime

class ReportGenerator:
    """Generates human-readable risk analysis reports"""

    # Visual indicators
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🟢 LOW"
    INFO = "ℹ️  INFO"

    # Exploit maturity indicators
    EXPLOITED = "⚠️  ACTIVELY EXPLOITED"
    WEAPONIZED = "💣 WEAPONIZED"
    POC = "📝 POC AVAILABLE"
    THEORETICAL = "📖 THEORETICAL"

    def __init__(self, analysis_data: Dict[str, Any]):
        self.data = analysis_data

    def generate_executive_summary(self) -> str:
        """Generate executive summary for leadership"""

        deployment_name = self.data.get('deploymentName', 'Unknown')
        namespace = self.data.get('namespace', 'Unknown')
        cluster = self.data.get('clusterName', 'Unknown')
        original_risk = self.data.get('originalRiskScore', 0)
        gen_ai_priority = self.data.get('genAIPriority', 0)

        # Get statistics
        total_cves = len(self.data.get('imageVulnerabilities', []))
        high_severity_cves = len([v for v in self.data.get('imageVulnerabilities', [])
                                   if v.get('cvss', 0) >= 7.0])

        exploit_summary = self.data.get('exploitMaturitySummary', {})
        known_exploited = exploit_summary.get('knownExploited', 0)
        weaponized = exploit_summary.get('hasMetasploit', 0)

        total_processes = len(self.data.get('suspiciousProcessExecutions', []))
        suspicious_processes = len([p for p in self.data.get('suspiciousProcessExecutions', [])
                                    if p.get('suspicious', False)])

        # Determine severity
        if gen_ai_priority >= 90:
            severity_icon = self.CRITICAL
            severity_text = "CRITICAL"
        elif gen_ai_priority >= 70:
            severity_icon = self.HIGH
            severity_text = "HIGH"
        elif gen_ai_priority >= 50:
            severity_icon = self.MEDIUM
            severity_text = "MEDIUM"
        else:
            severity_icon = self.LOW
            severity_text = "LOW"

        lines = [
            "═" * 80,
            "EXECUTIVE SUMMARY",
            "═" * 80,
            "",
            f"Deployment:  {deployment_name}",
            f"Namespace:   {namespace}",
            f"Cluster:     {cluster}",
            f"Analysis:    {self.data.get('analysisTimestamp', 'N/A')}",
            "",
            "─" * 80,
            "RISK ASSESSMENT",
            "─" * 80,
            "",
            f"{severity_icon} Overall Risk Priority: {gen_ai_priority}/100 ({severity_text})",
            f"   RHACS Original Score: {original_risk}",
            "",
        ]

        # Add explanation if available
        if self.data.get('genAIPriorityExplanation'):
            lines.extend([
                "Risk Assessment:",
                self._wrap_text(self.data['genAIPriorityExplanation'], indent=2),
                ""
            ])

        lines.extend([
            "─" * 80,
            "KEY FINDINGS",
            "─" * 80,
            "",
            f"📦 Vulnerabilities:",
            f"   • Total CVEs: {total_cves}",
            f"   • High Severity (CVSS ≥ 7.0): {high_severity_cves}",
        ])

        if known_exploited > 0:
            lines.append(f"   {self.EXPLOITED} Known Exploited: {known_exploited}")
        if weaponized > 0:
            lines.append(f"   {self.WEAPONIZED} Weaponized: {weaponized}")

        lines.extend([
            "",
            f"⚙️  Processes:",
            f"   • Total Processes: {total_processes}",
            f"   • Flagged as Suspicious: {suspicious_processes}",
            "",
        ])

        # Add top recommendations
        recommendations = self.data.get('recommendations', [])
        if recommendations:
            lines.extend([
                "─" * 80,
                "TOP RECOMMENDATIONS",
                "─" * 80,
                ""
            ])
            for i, rec in enumerate(recommendations[:5], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.append("═" * 80)

        return "\n".join(lines)

    def generate_vulnerability_report(self) -> str:
        """Generate detailed vulnerability report"""

        vulns = self.data.get('imageVulnerabilities', [])
        if not vulns:
            return "\n📋 No vulnerabilities found.\n"

        # Filter and sort by priority
        high_severity = [v for v in vulns if v.get('cvss', 0) >= 7.0]

        # Group by exploit maturity
        exploited = [v for v in high_severity if v.get('exploitMaturity', {}).get('isKnownExploited', False)]
        weaponized = [v for v in high_severity if v.get('exploitMaturity', {}).get('hasMetasploitModule', False)]
        has_poc = [v for v in high_severity if v.get('exploitMaturity', {}).get('hasPublicExploit', False)]

        lines = [
            "═" * 80,
            "VULNERABILITY ANALYSIS",
            "═" * 80,
            "",
            f"Total Vulnerabilities: {len(vulns)}",
            f"High Severity (CVSS ≥ 7.0): {len(high_severity)}",
            "",
        ]

        # Known Exploited CVEs (HIGHEST PRIORITY)
        if exploited:
            lines.extend([
                "─" * 80,
                f"{self.EXPLOITED} KNOWN EXPLOITED VULNERABILITIES (CISA KEV)",
                "─" * 80,
                "",
                "These CVEs are being actively exploited in the wild. IMMEDIATE action required.",
                ""
            ])

            for vuln in sorted(exploited, key=lambda v: v.get('cvss', 0), reverse=True)[:10]:
                lines.extend(self._format_vulnerability(vuln, show_exploit=True))
                lines.append("")

        # Weaponized CVEs
        if weaponized:
            lines.extend([
                "─" * 80,
                f"{self.WEAPONIZED} WEAPONIZED VULNERABILITIES",
                "─" * 80,
                "",
                "These CVEs have Metasploit modules. Exploitation is trivial for attackers.",
                ""
            ])

            for vuln in sorted(weaponized, key=lambda v: v.get('cvss', 0), reverse=True)[:10]:
                if vuln not in exploited:  # Don't duplicate
                    lines.extend(self._format_vulnerability(vuln, show_exploit=True))
                    lines.append("")

        # Top High-Severity CVEs (not yet covered)
        remaining_high = [v for v in high_severity if v not in exploited and v not in weaponized]
        if remaining_high:
            lines.extend([
                "─" * 80,
                "HIGH SEVERITY VULNERABILITIES (CVSS ≥ 7.0)",
                "─" * 80,
                "",
                f"Showing top 10 of {len(remaining_high)} high-severity CVEs",
                ""
            ])

            for vuln in sorted(remaining_high, key=lambda v: v.get('cvss', 0), reverse=True)[:10]:
                lines.extend(self._format_vulnerability(vuln, show_exploit=True))
                lines.append("")

        return "\n".join(lines)

    def generate_process_report(self) -> str:
        """Generate process execution report"""

        processes = self.data.get('suspiciousProcessExecutions', [])
        if not processes:
            return "\n📋 No process executions found.\n"

        # Categorize by Gen AI classification if available
        high_risk = [p for p in processes if p.get('genAIClassification') == 'HIGH']
        medium_risk = [p for p in processes if p.get('genAIClassification') == 'MEDIUM']
        low_risk = [p for p in processes if p.get('genAIClassification') == 'LOW']
        unclassified = [p for p in processes if not p.get('genAIClassification')]

        lines = [
            "═" * 80,
            "PROCESS EXECUTION ANALYSIS",
            "═" * 80,
            "",
            f"Total Processes: {len(processes)}",
            f"High Risk: {len(high_risk)}",
            f"Medium Risk: {len(medium_risk)}",
            f"Low Risk: {len(low_risk)}",
            ""
        ]

        # High Risk Processes
        if high_risk:
            lines.extend([
                "─" * 80,
                f"{self.CRITICAL} HIGH RISK PROCESSES",
                "─" * 80,
                "",
                "These processes indicate risky behavior and should be investigated immediately.",
                ""
            ])

            for proc in high_risk[:10]:
                lines.extend(self._format_process(proc))
                lines.append("")

        # Medium Risk Processes
        if medium_risk:
            lines.extend([
                "─" * 80,
                f"{self.MEDIUM} MEDIUM RISK PROCESSES",
                "─" * 80,
                "",
                "These processes are potentially suspicious and warrant investigation.",
                ""
            ])

            for proc in medium_risk[:10]:
                lines.extend(self._format_process(proc))
                lines.append("")

        # Sample of Low Risk/Normal Processes
        if low_risk or unclassified:
            sample_processes = (low_risk + unclassified)[:5]
            lines.extend([
                "─" * 80,
                f"{self.LOW} NORMAL PROCESSES (Sample)",
                "─" * 80,
                "",
                f"Showing 5 of {len(low_risk) + len(unclassified)} normal processes",
                ""
            ])

            for proc in sample_processes:
                lines.extend(self._format_process(proc, brief=True))
                lines.append("")

        return "\n".join(lines)

    def generate_recommendations_report(self) -> str:
        """Generate actionable recommendations"""

        recommendations = self.data.get('recommendations', [])

        lines = [
            "═" * 80,
            "ACTIONABLE RECOMMENDATIONS",
            "═" * 80,
            ""
        ]

        if not recommendations:
            lines.append("✅ No specific recommendations. System appears well-configured.")
            lines.append("")
            return "\n".join(lines)

        # Categorize recommendations
        immediate = []
        urgent = []
        important = []
        general = []

        for rec in recommendations:
            rec_lower = rec.lower()
            if any(word in rec_lower for word in ['immediate', 'critical', 'urgent', 'now', 'asap']):
                immediate.append(rec)
            elif any(word in rec_lower for word in ['update', 'patch', 'fix', 'remediate']):
                urgent.append(rec)
            elif any(word in rec_lower for word in ['investigate', 'review', 'check']):
                important.append(rec)
            else:
                general.append(rec)

        if immediate:
            lines.extend([
                f"{self.CRITICAL} IMMEDIATE ACTION REQUIRED",
                "─" * 80,
                ""
            ])
            for i, rec in enumerate(immediate, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        if urgent:
            lines.extend([
                f"{self.HIGH} URGENT (Within Days)",
                "─" * 80,
                ""
            ])
            for i, rec in enumerate(urgent, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        if important:
            lines.extend([
                f"{self.MEDIUM} IMPORTANT (Within Weeks)",
                "─" * 80,
                ""
            ])
            for i, rec in enumerate(important, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        if general:
            lines.extend([
                f"{self.INFO} GENERAL IMPROVEMENTS",
                "─" * 80,
                ""
            ])
            for i, rec in enumerate(general, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return "\n".join(lines)

    def generate_full_report(self) -> str:
        """Generate complete human-readable report"""

        sections = [
            self.generate_executive_summary(),
            "",
            self.generate_vulnerability_report(),
            "",
            self.generate_process_report(),
            "",
            self.generate_recommendations_report(),
            "",
            "─" * 80,
            "END OF REPORT",
            "─" * 80,
            "",
            f"Generated by RHACS Risk Prioritization System",
            f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]

        return "\n".join(sections)

    def _format_vulnerability(self, vuln: Dict[str, Any], show_exploit: bool = False) -> List[str]:
        """Format a single vulnerability for display"""

        cve = vuln.get('cve', 'Unknown')
        cvss = vuln.get('cvss', 0)
        component = vuln.get('component', 'Unknown')
        version = vuln.get('componentVersion', '')
        fixed_by = vuln.get('fixedBy', '')

        # Severity indicator
        if cvss >= 9.0:
            severity = self.CRITICAL
        elif cvss >= 7.0:
            severity = self.HIGH
        elif cvss >= 4.0:
            severity = self.MEDIUM
        else:
            severity = self.LOW

        lines = [
            f"{severity} {cve} (CVSS: {cvss})"
        ]

        # Component info
        component_line = f"   Component: {component}"
        if version:
            component_line += f" ({version})"
        if fixed_by:
            component_line += f" → Fix: {fixed_by}"
        else:
            component_line += " → No fix available"
        lines.append(component_line)

        # Exploit maturity
        if show_exploit and vuln.get('exploitMaturity'):
            exploit = vuln['exploitMaturity']
            maturity_level = exploit.get('maturityLevel', 'UNKNOWN')
            maturity_score = exploit.get('maturityScore', 0)

            if exploit.get('isKnownExploited'):
                lines.append(f"   {self.EXPLOITED} (CISA KEV)")
                if exploit.get('cisaKEV'):
                    kev = exploit['cisaKEV']
                    lines.append(f"      Added: {kev.get('dateAdded', 'N/A')}")
                    if kev.get('requiredAction'):
                        lines.append(f"      Action: {kev['requiredAction'][:100]}...")
            elif exploit.get('hasMetasploitModule'):
                lines.append(f"   {self.WEAPONIZED} Metasploit module available")
            elif exploit.get('hasPublicExploit'):
                lines.append(f"   {self.POC} Public exploit available")
            else:
                lines.append(f"   {self.THEORETICAL} No known exploits (Maturity: {maturity_level})")

        # Gen AI message
        if vuln.get('genAIMessage'):
            lines.append(f"   AI Assessment:")
            lines.append(self._wrap_text(vuln['genAIMessage'], indent=6))

        # Summary (first 200 chars)
        if vuln.get('summary'):
            summary = vuln['summary'][:200]
            if len(vuln['summary']) > 200:
                summary += "..."
            lines.append(f"   Summary: {summary}")

        return lines

    def _format_process(self, process: Dict[str, Any], brief: bool = False) -> List[str]:
        """Format a single process for display"""

        name = process.get('processName', 'Unknown')
        args = process.get('processArgs', '')
        uid = process.get('processUid', 0)
        container = process.get('containerName', 'Unknown')

        # Risk indicator
        classification = process.get('genAIClassification', '')
        if classification == 'HIGH':
            risk_icon = self.CRITICAL
        elif classification == 'MEDIUM':
            risk_icon = self.MEDIUM
        elif classification == 'LOW':
            risk_icon = self.LOW
        else:
            risk_icon = self.INFO

        lines = [
            f"{risk_icon} {name}"
        ]

        if not brief:
            lines.append(f"   Container: {container}")
            lines.append(f"   Command: {args[:100]}{'...' if len(args) > 100 else ''}")
            lines.append(f"   UID: {uid} {'(root)' if uid == 0 else '(non-root)'}")

            if process.get('genAIExplanation'):
                lines.append(f"   AI Assessment:")
                lines.append(self._wrap_text(process['genAIExplanation'], indent=6))
        else:
            # Brief format
            lines.append(f"   {args[:80]}{'...' if len(args) > 80 else ''}")

        return lines

    def _wrap_text(self, text: str, width: int = 80, indent: int = 0) -> str:
        """Wrap text to specified width with indentation"""

        indent_str = " " * indent
        words = text.split()
        lines = []
        current_line = []
        current_length = indent

        for word in words:
            word_length = len(word) + 1  # +1 for space
            if current_length + word_length > width:
                if current_line:
                    lines.append(indent_str + " ".join(current_line))
                current_line = [word]
                current_length = indent + len(word)
            else:
                current_line.append(word)
                current_length += word_length

        if current_line:
            lines.append(indent_str + " ".join(current_line))

        return "\n".join(lines)


def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <risk.json>")
        print("Generates human-readable report from risk analysis JSON")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {input_file}: {e}")
        sys.exit(1)

    generator = ReportGenerator(data)
    report = generator.generate_full_report()

    # Save to file
    output_file = input_file.replace('.json', '_report.txt')
    with open(output_file, 'w') as f:
        f.write(report)

    print(report)
    print(f"\n✅ Report saved to: {output_file}")


if __name__ == "__main__":
    main()
