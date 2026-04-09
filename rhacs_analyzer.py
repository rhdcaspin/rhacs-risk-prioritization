#!/usr/bin/env python3
"""
RHACS Risk Analysis Tool
Analyzes RHACS deployments and reassesses risks using AI-powered analysis
"""

import json
import sys
import requests
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import urllib3
from exploit_checker import ExploitChecker

# Disable SSL warnings for demo environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# RHACS Configuration
RHACS_URL = "https://staging.demo.stackrox.com"
API_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6Imp3dGswIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL3N0YWNrcm94LmlvL2p3dC1zb3VyY2VzI2FwaS10b2tlbnMiLCJleHAiOjE4MDY1NTIwMDAsImlhdCI6MTc3NTc2NjI5MiwiaXNzIjoiaHR0cHM6Ly9zdGFja3JveC5pby9qd3QiLCJqdGkiOiI5ZmE3NmEyYy00NGU4LTRkYjMtYTRmZi1lZTk1Mzg1NTM0YWUiLCJuYW1lIjoiZGMtcmlzay1wcmlvIiwicm9sZXMiOlsiQWRtaW4iXX0.j8XinLqp5lrj9gC1C91uJNZm-BNpD83WMHKI1ITLDb1LVPW7ZJw_aELTXFLl8wSUjl5jDCUgNM0i3zjTmwcQFlqdIHk9-yLG8z49q4iKoOIdy8NydbOqbOLYZLrRGr6nMKE0za8Fk1aWWhMZ6JI5UOvde8KWyVXfaRBfgk9KacE7m4EbeCfiM7o9vebVYXuuTIXOVC6BoIPG2ZhJhSPVWBasquVp-4woL1tI_bBQPG7JsFuNiH5Eq64SP2i1r-VsGTcmOH0ZcY9IJ-DT69jJPBH_udv5bbqrRJHRE4ExMAJAdE_6G_8Yfb0tHeqN9zV-yyvdoe72BRQzk-9A3ZfGmch5T8Rm1_O_U2VdY4w91lLnJ6sFd_QWCXdyjW2uJDYGfNL0s3_opV-QudVTfX8gSK-0FeyT8pvKt4ybNOUOUuWK28GCGc50oQNn36neXwPR0EJZLdawF4T5WnSSfT8Au4GW6DpK6GMVYTeDB7IpqRt2KhRnyKVIcS-UriXUnBItY1S6CqtR5gYnvVwJ3z9abTHh6XkNf8wtkU9gbvGOSV-yjyYYRhT95tKhCvKBrmNV46jQ-HgvWAHDE1CLkDuUNd4J7JRRPzk6omBBPK-NVFVEx3x_bjgQAYHm0HP06Iik1PTZfq7iT5BIvydLOb3Wn4JvoOl6rWcw5BdBgO8otAk"

class RHACSAnalyzer:
    """Analyzer for RHACS deployment risk assessment"""

    def __init__(self, api_url: str = RHACS_URL, token: str = API_TOKEN, check_exploits: bool = False):
        self.api_url = api_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False  # For demo environment
        self.check_exploits = check_exploits
        self.exploit_checker = ExploitChecker() if check_exploits else None

    def get_deployment(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Fetch deployment details from RHACS"""
        try:
            url = f"{self.api_url}/v1/deployments/{deployment_id}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching deployment: {e}", file=sys.stderr)
            return None

    def get_deployment_with_risk(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Fetch deployment with risk information from RHACS"""
        try:
            url = f"{self.api_url}/v1/deploymentswithrisk/{deployment_id}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching deployment with risk: {e}", file=sys.stderr)
            return None

    def get_vulnerabilities(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Get vulnerability management data for deployment"""
        try:
            query = f"Deployment ID:{deployment_id}"
            url = f"{self.api_url}/v1/export/vuln-mgmt/workloads"
            response = self.session.get(url, params={'query': query})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching vulnerabilities: {e}", file=sys.stderr)
            return None

    def get_processes(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Get runtime process execution data for deployment"""
        try:
            url = f"{self.api_url}/v1/processes/deployment/{deployment_id}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching processes: {e}", file=sys.stderr)
            return None

    def get_processes_grouped(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Get process data grouped by container with suspicious flags"""
        try:
            url = f"{self.api_url}/v1/processes/deployment/{deployment_id}/grouped/container"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching grouped processes: {e}", file=sys.stderr)
            return None

    def get_process_baseline(self, cluster_id: str, namespace: str, deployment_id: str, container_name: str) -> Optional[Dict[str, Any]]:
        """Get process baseline for a specific container"""
        try:
            url = f"{self.api_url}/v1/processbaselines/key"
            params = {
                'key.clusterId': cluster_id,
                'key.namespace': namespace,
                'key.deploymentId': deployment_id,
                'key.containerName': container_name
            }
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching process baseline: {e}", file=sys.stderr)
            return None

    def list_deployments(self, limit: int = 50) -> Optional[List[Dict[str, Any]]]:
        """List all deployments"""
        try:
            url = f"{self.api_url}/v1/deployments"
            response = self.session.get(url, params={'pagination.limit': limit})
            response.raise_for_status()
            data = response.json()
            return data.get('deployments', [])
        except requests.exceptions.RequestException as e:
            print(f"Error listing deployments: {e}", file=sys.stderr)
            return None


    def extract_deployment_data(self, deployment: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant data from deployment object"""
        data = {
            'deploymentId': deployment.get('id', ''),
            'deploymentName': deployment.get('name', ''),
            'namespace': deployment.get('namespace', ''),
            'cluster': deployment.get('clusterId', ''),
            'clusterName': deployment.get('clusterName', ''),
            'analysisTimestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }

        # Extract containers and images
        containers = deployment.get('containers', [])
        data['containers'] = []
        data['images'] = []

        for container in containers:
            data['containers'].append({
                'name': container.get('name', ''),
                'image': container.get('image', {}).get('name', {}).get('fullName', '')
            })
            if container.get('image'):
                data['images'].append(container['image'])

        return data

    def extract_processes_data(self, processes_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract process executions from grouped process data"""
        all_processes = []

        groups = processes_data.get('groups', [])
        for group in groups:
            container_name = group.get('containerName', '')
            process_name = group.get('name', '')
            suspicious = group.get('suspicious', False)
            times_executed = group.get('timesExecuted', 0)

            # Get signal data from nested groups
            nested_groups = group.get('groups', [])
            for nested_group in nested_groups:
                args = nested_group.get('args', '')
                signals = nested_group.get('signals', [])

                # Get first signal as representative
                if signals:
                    first_signal_wrapper = signals[0]
                    signal = first_signal_wrapper.get('signal', {})

                    all_processes.append({
                        'containerName': container_name,
                        'processName': process_name,
                        'processExecFilePath': signal.get('execFilePath', ''),
                        'processArgs': args,
                        'processUid': signal.get('uid', 0),
                        'processGid': signal.get('gid', 0),
                        'timesExecuted': times_executed,
                        'suspicious': suspicious,
                        'parentExecFilePath': signal.get('lineageInfo', [{}])[0].get('parentExecFilePath', '') if signal.get('lineageInfo') else '',
                        'signalTime': signal.get('time', '')
                    })

        return all_processes

    def extract_vulnerabilities_data(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract CVE data from vulnerability management export"""
        vulnerabilities = []

        result = vuln_data.get('result', {})
        images = result.get('images', [])

        for image in images:
            scan = image.get('scan', {})
            components = scan.get('components', [])

            for component in components:
                component_name = component.get('name', '')
                component_version = component.get('version', '')
                component_vulns = component.get('vulns', [])

                for vuln in component_vulns:
                    # Extract CVSS score (prefer V3, fallback to V2)
                    cvss_v3 = vuln.get('cvssV3', {})
                    cvss_v2 = vuln.get('cvssV2', {})
                    cvss_score = vuln.get('cvss', 0)

                    if cvss_v3:
                        cvss_vector = cvss_v3.get('vector', '')
                        cvss_score = cvss_v3.get('baseScore', cvss_score)
                    elif cvss_v2:
                        cvss_vector = cvss_v2.get('vector', '')
                        cvss_score = cvss_v2.get('score', cvss_score)
                    else:
                        cvss_vector = ''

                    vulnerabilities.append({
                        'cve': vuln.get('cve', ''),
                        'severity': vuln.get('severity', ''),
                        'cvss': cvss_score,
                        'cvssVector': cvss_vector,
                        'component': component_name,
                        'componentVersion': component_version,
                        'fixedBy': component.get('fixedBy', ''),
                        'link': vuln.get('link', ''),
                        'summary': vuln.get('summary', ''),
                        'nvdCvss': vuln.get('nvdCvss', 0),
                        'scoreVersion': vuln.get('scoreVersion', ''),
                        'state': vuln.get('state', ''),
                    })

        return vulnerabilities

    def analyze_deployment(self, deployment_id: str, check_exploits: bool = None) -> Dict[str, Any]:
        """Main analysis function - fetches all deployment data"""
        print(f"Analyzing deployment: {deployment_id}", file=sys.stderr)

        # Fetch deployment with risk
        print("Fetching deployment with risk data...", file=sys.stderr)
        deployment_with_risk = self.get_deployment_with_risk(deployment_id)
        if not deployment_with_risk:
            return {'error': 'Failed to fetch deployment with risk'}

        deployment = deployment_with_risk.get('deployment', {})

        # Extract basic deployment data
        result = self.extract_deployment_data(deployment)

        # Get risk score from deployment
        risk = deployment_with_risk.get('risk', {})
        result['originalRiskScore'] = risk.get('score', 0)
        result['riskResults'] = risk.get('results', [])

        # Fetch processes grouped by container
        print("Fetching process data...", file=sys.stderr)
        processes_data = self.get_processes_grouped(deployment_id)
        if processes_data:
            result['suspiciousProcessExecutions'] = self.extract_processes_data(processes_data)
            result['processesRaw'] = processes_data
        else:
            result['suspiciousProcessExecutions'] = []

        # Fetch vulnerabilities
        print("Fetching vulnerability data...", file=sys.stderr)
        vuln_data = self.get_vulnerabilities(deployment_id)
        if vuln_data:
            result['imageVulnerabilities'] = self.extract_vulnerabilities_data(vuln_data)
            result['vulnerabilitiesRaw'] = vuln_data
        else:
            result['imageVulnerabilities'] = []

        # Fetch process baselines for each container
        print("Fetching process baselines...", file=sys.stderr)
        result['processBaselines'] = []
        cluster_id = deployment.get('clusterId', '')
        namespace = deployment.get('namespace', '')
        for container_info in result.get('containers', []):
            container_name = container_info.get('name', '')
            baseline = self.get_process_baseline(cluster_id, namespace, deployment_id, container_name)
            if baseline:
                result['processBaselines'].append({
                    'containerName': container_name,
                    'baseline': baseline
                })

        # Add risk factor analysis
        result['riskFactors'] = {
            'privilegedContainer': any(c.get('securityContext', {}).get('privileged', False) for c in deployment.get('containers', [])),
            'hostNetwork': deployment.get('hostNetwork', False),
            'hostPid': deployment.get('hostPid', False),
            'hostIpc': deployment.get('hostIpc', False),
        }

        # Add placeholders for Gen AI fields (to be filled by Claude)
        result['genAIPriority'] = None
        result['genAIPriorityExplanation'] = None

        # Check exploit maturity if requested
        if check_exploits is not None:
            should_check = check_exploits
        else:
            should_check = self.check_exploits

        if should_check and result['imageVulnerabilities']:
            print("Checking exploit maturity for high-severity CVEs...", file=sys.stderr)
            self._enrich_with_exploit_data(result)

        print("Analysis complete", file=sys.stderr)
        return result

    def _enrich_with_exploit_data(self, result: Dict[str, Any]) -> None:
        """Enrich vulnerability data with exploit maturity information"""
        if not self.exploit_checker:
            self.exploit_checker = ExploitChecker()

        # Focus on high-severity CVEs (CVSS >= 7.0)
        high_severity_cves = [
            vuln for vuln in result['imageVulnerabilities']
            if vuln.get('cvss', 0) >= 7.0
        ]

        # Limit to top 20 to avoid rate limits
        cves_to_check = high_severity_cves[:20]
        cve_ids = [vuln['cve'] for vuln in cves_to_check]

        if not cve_ids:
            print("No high-severity CVEs to check", file=sys.stderr)
            return

        print(f"Checking {len(cve_ids)} high-severity CVEs...", file=sys.stderr)

        # Batch check CVEs (verbose=False to avoid stdout pollution)
        exploit_data = self.exploit_checker.batch_check_cves(cve_ids, verbose=False)

        # Enrich vulnerability data
        for vuln in result['imageVulnerabilities']:
            cve_id = vuln['cve']
            if cve_id in exploit_data:
                exploit_info = exploit_data[cve_id]
                vuln['exploitMaturity'] = {
                    'maturityLevel': exploit_info['maturity_level'],
                    'maturityScore': exploit_info['maturity_score'],
                    'isKnownExploited': exploit_info['is_known_exploited'],
                    'hasMetasploitModule': exploit_info['has_metasploit_module'],
                    'hasPublicExploit': exploit_info['has_public_exploit'],
                    'exploitSources': exploit_info['exploit_sources'],
                    'riskFactors': exploit_info['risk_factors']
                }

                # Add CISA KEV info if available
                if exploit_info['is_known_exploited']:
                    kev_details = exploit_info['details']['cisa_kev']
                    vuln['exploitMaturity']['cisaKEV'] = {
                        'dateAdded': kev_details.get('date_added', ''),
                        'requiredAction': kev_details.get('required_action', ''),
                        'dueDate': kev_details.get('due_date', ''),
                        'vulnerabilityName': kev_details.get('vulnerability_name', '')
                    }

        # Add summary statistics
        result['exploitMaturitySummary'] = {
            'totalChecked': len(cve_ids),
            'knownExploited': sum(1 for e in exploit_data.values() if e['is_known_exploited']),
            'hasMetasploit': sum(1 for e in exploit_data.values() if e['has_metasploit_module']),
            'criticalMaturity': sum(1 for e in exploit_data.values() if e['maturity_level'] == 'CRITICAL'),
            'highMaturity': sum(1 for e in exploit_data.values() if e['maturity_level'] == 'HIGH'),
        }

        print(f"✓ Found {result['exploitMaturitySummary']['knownExploited']} known exploited CVEs", file=sys.stderr)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python rhacs_analyzer.py <command> [args] [options]")
        print("Commands:")
        print("  list                    - List all deployments")
        print("  analyze <deployment_id> - Analyze a specific deployment")
        print("  fetch <deployment_id>   - Fetch deployment data only")
        print("\nOptions:")
        print("  --exploits, -e         - Check exploit maturity (ExploitDB, Metasploit, CISA KEV)")
        sys.exit(1)

    command = sys.argv[1]
    analyzer = RHACSAnalyzer()

    if command == "list":
        deployments = analyzer.list_deployments()
        if deployments:
            print(json.dumps(deployments, indent=2))
        else:
            print("No deployments found or error occurred")

    elif command == "analyze":
        if len(sys.argv) < 3:
            print("Error: deployment_id required")
            sys.exit(1)

        deployment_id = sys.argv[2]

        # Check for --exploits flag
        check_exploits = '--exploits' in sys.argv or '-e' in sys.argv

        result = analyzer.analyze_deployment(deployment_id, check_exploits=check_exploits)
        print(json.dumps(result, indent=2))

    elif command == "fetch":
        if len(sys.argv) < 3:
            print("Error: deployment_id required")
            sys.exit(1)

        deployment_id = sys.argv[2]
        deployment = analyzer.get_deployment(deployment_id)
        if deployment:
            print(json.dumps(deployment, indent=2))
        else:
            print("Failed to fetch deployment")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
