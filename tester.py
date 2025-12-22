#!/usr/bin/env python3
"""
Comprehensive Website Testing Tool using Industry-Standard Tools
Tests: SEO, Security, Accessibility, Performance, QA
Uses: Lighthouse, Pa11y, OWASP ZAP, SSLyze, and more
"""

import argparse
import json
import os
import subprocess
import tempfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER
from urllib.parse import urlparse
import warnings
import dns.resolver
import html

warnings.filterwarnings('ignore')


class Tester:
    def __init__(self, url: str, max_workers: int = 5, output_directory: str = '/output', 
                 enable_zap: bool = False, enable_nuclei: bool = False):
        self.url = url
        self.max_workers = max_workers
        self.output_directory = output_directory
        self.enable_zap = enable_zap
        self.enable_nuclei = enable_nuclei
        self.enabled_tests = set()  # Track which tests are enabled
        
        # Ensure output directory exists
        if self.output_directory and not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory, exist_ok=True)
        self.results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'lighthouse': {},
            'pa11y': {},
            'security_headers': {},
            'ssl': {},
            'owasp_zap': {},
            'nuclei': {},
            'w3c_validator': {},
            'robots_sitemap': {},
            'dns': {}
        }

    def run_all_tests(self):
        """Run all tests in parallel based on configuration"""
        print(f"\n{'='*80}")
        print(f"Starting comprehensive tests for: {self.url}")
        print(f"{'='*80}\n")
        
        # Check if security scans are enabled (nuclei or zap)
        security_scans_enabled = self.enable_zap or self.enable_nuclei
        
        # Define all available tests (excluding lighthouse if security scans are enabled)
        all_tests = [
            ('Pa11y (Accessibility)', self.run_pa11y),
            ('Security Headers Analysis', self.check_security_headers),
            ('SSL/TLS Testing (sslyze)', self.test_ssl),
            ('W3C HTML Validator', self.validate_w3c),
            ('Robots.txt & Sitemap', self.check_robots_sitemap),
            ('DNS Records', self.check_dns),
        ]
        
        # Add lighthouse to parallel tests only if security scans are NOT enabled
        # (if security scans are enabled, lighthouse will run after they complete)
        if not security_scans_enabled:
            all_tests.insert(0, ('Lighthouse (Performance/SEO/Accessibility/Best Practices)', self.run_lighthouse))
        
        # Conditionally add security scans based on configuration
        if self.enable_zap:
            all_tests.append(('OWASP ZAP Security Scan', self.run_owasp_zap))
        
        if self.enable_nuclei:
            all_tests.append(('Nuclei Vulnerability Scanner', self.run_nuclei))
        
        print()  # Empty line for readability
        
        # Run tests in parallel (this includes nuclei/zap if enabled, but NOT lighthouse)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(test_func): name for name, test_func in all_tests}
            
            for future in as_completed(futures):
                test_name = futures[future]
                try:
                    future.result()
                    print(f"[✓] {test_name} completed")
                    # Track enabled tests for PDF generation
                    self.enabled_tests.add(test_name)
                except Exception as e:
                    print(f"[✗] {test_name} failed: {e}")
        
        # If security scans are enabled, run lighthouse AFTER they complete
        # to ensure lighthouse never runs in parallel with nuclei/zap
        if security_scans_enabled:
            print()  # Empty line before lighthouse
            print("[*] Running Lighthouse after security scans complete...")
            lighthouse_name = 'Lighthouse (Performance/SEO/Accessibility/Best Practices)'
            try:
                self.run_lighthouse()
                print(f"[✓] {lighthouse_name} completed")
                self.enabled_tests.add(lighthouse_name)
            except Exception as e:
                print(f"[✗] {lighthouse_name} failed: {e}")
        
        return self.results

    def _parse_url_hostname(self):
        """Helper method to parse URL and extract hostname consistently"""
        try:
            parsed_url = urlparse(self.url)
            hostname = parsed_url.netloc.split(':')[0]
            if not hostname:
                raise ValueError("Invalid URL format or missing hostname")
            return hostname
        except Exception as e:
            raise ValueError(f"URL parsing error: {str(e)}")

    def _parse_url_host(self):
        """Helper method to parse URL and extract host (with port if present) consistently"""
        try:
            parsed_url = urlparse(self.url)
            host = parsed_url.netloc
            if not host:
                raise ValueError("Invalid URL format or missing host")
            return host
        except Exception as e:
            raise ValueError(f"URL parsing error: {str(e)}")

    def _parse_url_base(self):
        """Helper method to parse URL and extract base URL (scheme + netloc) consistently"""
        try:
            parsed_url = urlparse(self.url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            return base_url
        except Exception as e:
            raise ValueError(f"URL parsing error: {str(e)}")

    def run_lighthouse(self):
        """Run Google Lighthouse tests"""
        print("[*] Running Lighthouse tests...")
        
        # Initialize result structure
        self.results['lighthouse'] = {}
        
        try:
            # Generate separate HTML report in the same directory as the PDF
            html_file = os.path.join(self.output_directory, 'lighthouse_report.html')
            cmd = [
                'lighthouse', self.url,
                '--output=html',
                f'--output-path={html_file}',
                '--chrome-flags="--headless --no-sandbox --disable-gpu"',
                '--quiet'
            ]

            result = subprocess.run(
                ' '.join(cmd),
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0 and os.path.exists(html_file):
                self.results['lighthouse'] = {
                    'html_report_generated': True,
                    'html_file': 'lighthouse_report.html',
                    'full_path': html_file,
                    'success': True
                }
            else:
                error_msg = result.stderr[:500] if result.stderr else 'Failed to generate Lighthouse HTML report'
                self.results['lighthouse'] = {'error': error_msg, 'success': False}
                
        except FileNotFoundError:
            self.results['lighthouse'] = {'error': 'Lighthouse command not found. Is lighthouse installed?'}
        except subprocess.TimeoutExpired:
            self.results['lighthouse'] = {'error': 'Lighthouse timed out after 300 seconds'}
        except Exception as e:
            self.results['lighthouse'] = {'error': f"Unexpected error: {str(e)}"}

    def run_pa11y(self):
        """Run Pa11y accessibility tests"""
        print("[*] Running Pa11y accessibility tests...")
        
        # Initialize result structure
        self.results['pa11y'] = {}
        
        try:
            # Create config file for Pa11y with Chrome flags for Docker
            config_file = None
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                config = {
                    "chromeLaunchConfig": {
                        "executablePath": "/usr/bin/chromium",
                        "args": ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
                    }
                }
                json.dump(config, f)
                config_file = f.name
            
            cmd = [
                'pa11y', self.url,
                '--runner', 'axe',
                '--config', config_file,
                '--reporter', 'json'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            # Clean up config file
            try:
                if config_file and os.path.exists(config_file):
                    os.unlink(config_file)
            except Exception:
                pass
            
            # Pa11y returns exit code 2 when issues are found, which is normal
            output = result.stdout.strip() if result.stdout else ''
            
            if not output:
                error_msg = result.stderr[:500] if result.stderr else 'No output from pa11y'
                self.results['pa11y'] = {'error': error_msg}
                return
            
            # Parse JSON output
            try:
                issues = json.loads(output)
            except json.JSONDecodeError as e:
                self.results['pa11y'] = {'error': f"JSON parsing error: {str(e)}"}
                return
            
            # Pa11y returns a list of issues
            if not isinstance(issues, list):
                issues = []
                
                # Categorize by type (error, warning, notice)
                errors = [i for i in issues if i.get('type') == 'error']
                warnings = [i for i in issues if i.get('type') == 'warning']
                notices = [i for i in issues if i.get('type') == 'notice']
                
                self.results['pa11y'] = {
                    'total_issues': len(issues),
                    'issues': [
                        {
                            'code': issue.get('code', ''),
                            'type': issue.get('type', 'unknown'),
                            'message': issue.get('message', ''),
                            'context': issue.get('context', '') if issue.get('context') else '',
                            'selector': issue.get('selector', ''),
                            'runner': issue.get('runner', '')
                        }
                        for issue in issues
                    ],
                    'summary': {
                        'errors': len(errors),
                        'warnings': len(warnings),
                        'notices': len(notices)
                    }
                }
                
        except FileNotFoundError:
            self.results['pa11y'] = {'error': 'pa11y command not found. Is pa11y installed?'}
        except subprocess.TimeoutExpired:
            self.results['pa11y'] = {'error': 'pa11y timed out after 180 seconds'}
        except Exception as e:
            self.results['pa11y'] = {'error': f"Unexpected error: {str(e)}"}

    def check_security_headers(self):
        """Check security headers using Mozilla Observatory API and manual check"""
        print("[*] Checking security headers...")
        
        # Initialize result structure
        self.results['security_headers'] = {}
        
        try:
            # Extract hostname
            host = self._parse_url_host()
            
            # Use the Mozilla Observatory v2 API endpoint
            api_url = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
            params = {'host': host}
            
            # Single POST request - the v2 API returns results directly (no polling needed)
            response = requests.post(api_url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            # The v2 API returns results directly in the response
            if data and 'grade' in data:
                self.results['security_headers'] = {
                    'grade': data.get('grade'),
                    'score': data.get('score'),
                    'tests_passed': data.get('tests_passed'),
                    'tests_failed': data.get('tests_failed'),
                    'tests_quantity': data.get('tests_quantity'),
                    'report_url': data.get('details_url', f"https://developer.mozilla.org/en-US/observatory/analyze?host={host}"),
                    'scan_id': data.get('id'),
                    'scanned_at': data.get('scanned_at')
                }
            elif data and 'error' in data and data['error']:
                self.results['security_headers'] = {'error': f"Mozilla Observatory API error: {data['error']}"}
                return
            else:
                self.results['security_headers'] = {'error': 'Invalid response from Mozilla Observatory API'}
                return

            # Manual Header Check
            try:
                response = requests.get(self.url, timeout=30, verify=True)
                headers = response.headers
                
                security_headers_check = {
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
                    'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
                    'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
                    'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
                    'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
                }
                
                self.results['security_headers']['headers'] = security_headers_check
                self.results['security_headers']['missing_headers'] = [
                    k for k, v in security_headers_check.items() if v == 'Missing'
                ]
                self.results['security_headers']['present_headers'] = [
                    k for k, v in security_headers_check.items() if v != 'Missing'
                ]
            except requests.exceptions.RequestException as req_e:
                # If header check fails, we still have Observatory data, just note the error
                if 'headers' not in self.results['security_headers']:
                    self.results['security_headers']['header_check_error'] = f"Failed to check headers: {str(req_e)}"
                
        except ValueError as e:
            self.results['security_headers'] = {'error': str(e)}
        except requests.exceptions.RequestException as req_e:
            self.results['security_headers'] = {'error': f"Request error: {str(req_e)}"}
        except Exception as e:
            self.results['security_headers'] = {'error': f"Unexpected error: {str(e)}"}

    def test_ssl(self):
        """Test SSL/TLS configuration using sslyze"""
        print("[*] Testing SSL/TLS configuration...")
        
        # Initialize result structure
        self.results['ssl'] = {}
        
        try:
            # Extract hostname
            hostname = self._parse_url_hostname()
            cmd = [
                'sslyze',
                '--json_out=-',
                hostname
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                self.results['ssl'] = {'error': f"sslyze failed: {result.stderr or result.stdout}"}
                return

            if result.stdout:
                data = json.loads(result.stdout)

                server_scan = None
                if 'server_scan_results' in data:
                    server_scan_results = data.get('server_scan_results', [])
                    if isinstance(server_scan_results, list) and len(server_scan_results) > 0:
                        server_scan = server_scan_results[0]
                elif 'server_scan_result' in data:
                    server_scan = data.get('server_scan_result')
                elif len(data) == 1 and isinstance(list(data.values())[0], dict):
                    server_scan = list(data.values())[0]

                if server_scan is None:
                    server_scan = data
                if not server_scan:
                    self.results['ssl'] = {'error': 'sslyze returned no server scan results.'}
                    return

                scan_results = None

                if 'scan_commands_results' in server_scan:
                    scan_results = server_scan['scan_commands_results']
                elif 'scan_result' in server_scan:
                    scan_results = server_scan['scan_result']
                elif isinstance(server_scan, dict):
                    scan_results = server_scan
                else:
                    scan_results = {}

                # --- Extract Certificate Info ---
                cert_info_result = scan_results.get('certificate_info', {})
                if not cert_info_result:
                    cert_info_result = scan_results.get('certificate', {})

                certificate_is_trusted = False
                cert_details = {}
                
                if cert_info_result:
                    result_data = cert_info_result.get('result', {})
                    deployments = result_data.get('certificate_deployments', [])
                    if deployments:
                        deployment = deployments[0]
                        certificate_is_trusted = deployment.get('verified_certificate_chain') is not None
                        
                        # Get certificate details
                        leaf_cert = deployment.get('received_certificate_chain', [{}])[0] if deployment.get('received_certificate_chain') else {}
                        cert_details = {
                            'subject': str(leaf_cert.get('subject', 'N/A')),
                            'issuer': str(leaf_cert.get('issuer', 'N/A')),
                            'not_valid_before': str(leaf_cert.get('not_valid_before', 'N/A')),
                            'not_valid_after': str(leaf_cert.get('not_valid_after', 'N/A')),
                        }

                # --- Extract TLS/SSL Versions ---
                tls_versions = {}
                has_weak_ciphers = False
                weak_protocols = []
                
                for version in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1', 'tls_1_2', 'tls_1_3']:
                    result_key = f'{version}_cipher_suites'
                    version_result = scan_results.get(result_key)
                    
                    if version_result:
                        result_data = version_result.get('result', {})
                        accepted_suites = result_data.get('accepted_cipher_suites', [])
                        is_enabled = len(accepted_suites) > 0
                        tls_versions[version] = is_enabled
                        
                        # Check for weak protocols
                        if is_enabled and version in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1']:
                            weak_protocols.append(version.replace('_', '.').upper())
                        
                        # Check for weak ciphers
                        for cipher_suite in accepted_suites:
                            cipher_name = cipher_suite.get('cipher_suite', {}).get('name', '')
                            if any(weak in cipher_name for weak in ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']):
                                has_weak_ciphers = True
                    else:
                        tls_versions[version] = False
                        
                self.results['ssl'] = {
                    'certificate_valid': certificate_is_trusted,
                    'certificate_details': cert_details,
                    'tls_versions_enabled': tls_versions,
                    'has_weak_ciphers': has_weak_ciphers,
                    'weak_protocols': weak_protocols,
                    'supports_tls_1_3': tls_versions.get('tls_1_3', False),
                    'supports_tls_1_2': tls_versions.get('tls_1_2', False),
                }
                
        except FileNotFoundError:
            self.results['ssl'] = {'error': 'sslyze command not found. Is sslyze installed?'}
        except subprocess.TimeoutExpired:
            self.results['ssl'] = {'error': 'sslyze timed out after 120 seconds'}
        except json.JSONDecodeError:
            self.results['ssl'] = {'error': 'Failed to parse sslyze JSON output'}
        except ValueError as e:
            self.results['ssl'] = {'error': str(e)}
        except Exception as e:
            self.results['ssl'] = {'error': f"Unexpected error: {str(e)}"}

    def run_owasp_zap(self):
        """Run OWASP ZAP baseline scan"""
        print("[*] Running OWASP ZAP baseline scan...")
        
        # Initialize result structure
        self.results['owasp_zap'] = {}
        
        try:
            # Check if Docker is available
            docker_check = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if docker_check.returncode != 0:
                self.results['owasp_zap'] = {'error': 'Docker CLI not available'}
                return
            
            # Check if ZAP image exists, pull if not
            image_check = subprocess.run(
                ['docker', 'image', 'inspect', 'zaproxy/zap-stable'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if image_check.returncode != 0:
                print("[*] ZAP Docker image not found locally, pulling...")
                pull_result = subprocess.run(
                    ['docker', 'pull', 'zaproxy/zap-stable'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if pull_result.returncode != 0:
                    self.results['owasp_zap'] = {
                        'error': f'Failed to pull ZAP image: {pull_result.stderr[:500] if pull_result.stderr else "Unknown error"}'
                    }
                    print(f"[!] Failed to pull ZAP image: {pull_result.stderr[:200] if pull_result.stderr else 'Unknown error'}")
                    return
            
            # For Docker-in-Docker: find the HOST path for the output directory
            # This must match the user's --output flag, not a hardcoded path
            json_file = os.path.join(self.output_directory, 'zap_report.json')
            zap_data = None
            host_output_path = None
            
            # Try to detect host path by inspecting container mounts
            # This respects the user's --output flag
            try:
                container_name = os.environ.get('HOSTNAME') or 'tester'
                inspect_result = subprocess.run(
                    ['docker', 'inspect', '--format', '{{json .Mounts}}', container_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if inspect_result.returncode == 0 and inspect_result.stdout:
                    mounts = json.loads(inspect_result.stdout)
                    for mount in mounts:
                        if mount.get('Destination') == self.output_directory:
                            host_output_path = mount.get('Source')
                            break
            except Exception:
                pass
            
            if not host_output_path:
                try:
                    with open('/proc/self/cgroup', 'r') as f:
                        for line in f:
                            if 'docker' in line or 'containerd' in line:
                                parts = line.split('/')
                                if len(parts) > 0:
                                    container_id = parts[-1]
                                    for cid in [container_id, container_id[:12]]:
                                        inspect_result = subprocess.run(
                                            ['docker', 'inspect', '--format', '{{json .Mounts}}', cid],
                                            capture_output=True,
                                            text=True,
                                            timeout=10
                                        )
                                        if inspect_result.returncode == 0 and inspect_result.stdout:
                                            mounts = json.loads(inspect_result.stdout)
                                            for mount in mounts:
                                                if mount.get('Destination') == self.output_directory:
                                                    host_output_path = mount.get('Source')
                                                    break
                                            if host_output_path:
                                                break
                                    if host_output_path:
                                        break
                except Exception:
                    pass
            
            if not host_output_path:
                host_output_path = self.output_directory
            
            try:
                cmd = [
                    'docker', 'run', '--rm',
                    '-v', f'{host_output_path}:/zap/wrk/:rw',
                    'zaproxy/zap-stable',
                    'zap-baseline.py',
                    '-t', self.url,
                    '-I',
                    '--autooff',  # Disable Automation Framework so -J flag works
                    '-J', '/zap/wrk/zap_report.json'  # JSON output format
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if not os.path.exists(json_file):
                    error_msg = result.stderr[:500] if result.stderr else 'ZAP scan completed but JSON file not found'
                    self.results['owasp_zap'] = {'error': f'ZAP scan failed: {error_msg}'}
                    return
                
                # Read JSON file
                try:
                    with open(json_file, 'r') as f:
                        zap_data = json.load(f)
                    if not zap_data:
                        self.results['owasp_zap'] = {'error': 'ZAP JSON file is empty'}
                        return
                except json.JSONDecodeError as e:
                    self.results['owasp_zap'] = {'error': f'Failed to parse ZAP JSON output: {str(e)}'}
                    return
                except Exception as e:
                    self.results['owasp_zap'] = {'error': f'Failed to read ZAP JSON file: {str(e)}'}
                    return
            finally:
                # Clean up the ZAP JSON file
                try:
                    if os.path.exists(json_file):
                        os.remove(json_file)
                except Exception:
                    pass
            
            # Extract alerts from JSON structure
            # ZAP JSON structure: {"site": [{"alerts": [...], "@name": "...", "@host": "..."}]}
            alerts = []
            if not zap_data:
                # If zap_data is None, set empty results
                self.results['owasp_zap'] = {
                    'total_alerts': 0,
                    'alerts': [],
                    'summary': {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                }
                return
                
            try:
                site_data = zap_data.get('site', [])
                
                if isinstance(site_data, list) and len(site_data) > 0:
                    # Get alerts from the first site entry
                    site_alerts = site_data[0].get('alerts', [])
                    
                    if isinstance(site_alerts, list):
                        for alert in site_alerts:
                            if not isinstance(alert, dict):
                                continue
                                
                            # Extract alert information
                            alert_instances = alert.get('instances', [])
                            alert_count = len(alert_instances) if alert_instances else 0
                            
                            # Map ZAP risk levels: 0=Informational, 1=Low, 2=Medium, 3=High, 4=Critical
                            risk_level = alert.get('riskcode')
                            if risk_level is None:
                                risk_level = alert.get('risk', 0)
                            
                            if isinstance(risk_level, str):
                                try:
                                    risk_level = int(risk_level)
                                except (ValueError, TypeError):
                                    risk_level = 0
                            elif risk_level is None:
                                risk_level = 0
                            
                            risk_map = {
                                0: 'Informational',
                                1: 'Low',
                                2: 'Medium',
                                3: 'High',
                                4: 'Critical'
                            }
                            risk = risk_map.get(risk_level, 'Unknown')
                            
                            alerts.append({
                                'name': alert.get('name', 'Unknown'),
                                'id': str(alert.get('pluginid', '')),
                                'risk': risk,
                                'count': alert_count,
                                'description': alert.get('desc', ''),
                                'solution': alert.get('solution', ''),
                                'reference': alert.get('reference', ''),
                                'cweid': alert.get('cweid', ''),
                                'wascid': alert.get('wascid', '')
                            })
            except Exception:
                pass
            
            high_count = len([a for a in alerts if a.get('risk') in ['High', 'Critical']])
            medium_count = len([a for a in alerts if a.get('risk') == 'Medium'])
            low_count = len([a for a in alerts if a.get('risk') == 'Low'])
            info_count = len([a for a in alerts if a.get('risk') == 'Informational'])
            total_alerts = len(alerts)
            
            self.results['owasp_zap'] = {
                'total_alerts': total_alerts,
                'alerts': alerts,
                'summary': {
                    'high': high_count,
                    'medium': medium_count,
                    'low': low_count,
                    'info': info_count
                }
            }
                
        except FileNotFoundError:
            self.results['owasp_zap'] = {'error': 'Docker command not found'}
        except subprocess.TimeoutExpired:
            self.results['owasp_zap'] = {'error': 'ZAP scan timed out after 300 seconds'}
        except Exception as e:
            self.results['owasp_zap'] = {'error': f"Unexpected error: {str(e)}"}

    def run_nuclei(self):
        """Run Nuclei vulnerability scanner"""
        print("[*] Running Nuclei vulnerability scanner...")
        
        # Initialize result structure
        self.results['nuclei'] = {}
        
        try:
            cmd = [
                'nuclei',
                '-u', self.url,
                '-jsonl',
                '-silent',
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.stdout:
                vulnerabilities = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            vuln = json.loads(line)
                            info = vuln.get('info', {})
                            vulnerabilities.append({
                            # Identity
                            'template_id': vuln.get('template-id'),
                            'name': info.get('name'),
                            'severity': info.get('severity', 'unknown'),
                            'type': vuln.get('type'),

                            # Description
                            'description': info.get('description'),
                            'impact': info.get('impact'),
                            'remediation': info.get('remediation'),

                            # Target
                            'host': vuln.get('host'),
                            'matched_at': vuln.get('matched-at'),

                            # Evidence sources (CRITICAL)
                            'extracted_results': vuln.get('extracted-results', []),
                            'matcher_name': vuln.get('matcher-name'),
                            'response': vuln.get('response'),
                            'request': vuln.get('request'),
                            'curl_command': vuln.get('curl-command'),

                            # Classification
                            'classification': {
                                'cvss_score': info.get('classification', {}).get('cvss-score'),
                                'cwe_id': info.get('classification', {}).get('cwe-id'),
                            },

                            # Metadata
                            'tags': info.get('tags', []),
                            'references': info.get('reference', []),
                            })

                        except json.JSONDecodeError:
                            continue

                self.results['nuclei'] = {
                    'total_vulnerabilities': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities,
                    'summary': {
                        'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                        'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                        'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                        'low': len([v for v in vulnerabilities if v.get('severity') == 'low']),
                        'info': len([v for v in vulnerabilities if v.get('severity') == 'info']),
                        'unknown': len([v for v in vulnerabilities if v.get('severity') == 'unknown'])
                    }
                }
            else:
                self.results['nuclei'] = {
                    'total_vulnerabilities': 0,
                    'vulnerabilities': [],
                    'summary': {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'info': 0,
                        'unknown': 0
                    }
                }
        
        except FileNotFoundError:
            self.results['nuclei'] = {'error': 'Nuclei command not found. Is nuclei installed?'}
        except subprocess.TimeoutExpired:
            self.results['nuclei'] = {'error': 'Nuclei scan timed out after 600 seconds'}
        except Exception as e:
            self.results['nuclei'] = {'error': f"Unexpected error: {str(e)}"}

    def validate_w3c(self):
        """Validate HTML using W3C Validator"""
        print("[*] Running W3C HTML Validator...")
        
        # Initialize result structure
        self.results['w3c_validator'] = {}
        
        try:
            api_url = f"https://validator.w3.org/nu/?doc={self.url}&out=json"
            
            response = requests.get(api_url, timeout=60, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; WebsiteTester/1.0)'
            })
            response.raise_for_status()
            data = response.json()
            
            messages = data.get('messages', [])
            errors = [m for m in messages if m.get('type') == 'error']
            warnings = [m for m in messages if m.get('type') == 'info' or m.get('subType') == 'warning']
            
            self.results['w3c_validator'] = {
                'total_issues': len(messages),
                'errors': errors,
                'warnings': warnings,
                'summary': {
                    'errors': len(errors),
                    'warnings': len(warnings)
                }
            }
            
        except requests.exceptions.RequestException as req_e:
            self.results['w3c_validator'] = {'error': f"Request error: {str(req_e)}"}
        except Exception as e:
            self.results['w3c_validator'] = {'error': f"Unexpected error: {str(e)}"}

    def check_robots_sitemap(self):
        """Check robots.txt and sitemap.xml"""
        print("[*] Checking robots.txt and sitemap.xml...")
        
        # Initialize result structure
        self.results['robots_sitemap'] = {
            'robots_txt': {},
            'sitemap': {}
        }
        
        try:
            base_url = self._parse_url_base()
            
            # Check robots.txt
            try:
                robots_url = f"{base_url}/robots.txt"
                response = requests.get(robots_url, timeout=30)
                if response.status_code == 200:
                    content = response.text
                    self.results['robots_sitemap']['robots_txt'] = {
                        'exists': True,
                        'size': len(content),
                        'has_sitemap_reference': 'sitemap' in content.lower(),
                        'has_disallow_rules': 'disallow' in content.lower(),
                    }
                else:
                    self.results['robots_sitemap']['robots_txt'] = {
                        'exists': False,
                        'status_code': response.status_code
                    }
            except requests.exceptions.RequestException as req_e:
                self.results['robots_sitemap']['robots_txt'] = {'error': f"Request error: {str(req_e)}"}
            except Exception as e:
                self.results['robots_sitemap']['robots_txt'] = {'error': f"Unexpected error: {str(e)}"}
            
            # Check sitemap.xml
            try:
                sitemap_url = f"{base_url}/sitemap.xml"
                response = requests.get(sitemap_url, timeout=30)
                if response.status_code == 200:
                    content = response.text
                    url_count = content.lower().count('<url>')
                    self.results['robots_sitemap']['sitemap'] = {
                        'exists': True,
                        'size': len(content),
                        'url_count': url_count,
                        'is_valid_xml': content.strip().startswith('<?xml') or content.strip().startswith('<urlset')
                    }
                else:
                    self.results['robots_sitemap']['sitemap'] = {
                        'exists': False,
                        'status_code': response.status_code
                    }
            except requests.exceptions.RequestException as req_e:
                self.results['robots_sitemap']['sitemap'] = {'error': f"Request error: {str(req_e)}"}
            except Exception as e:
                self.results['robots_sitemap']['sitemap'] = {'error': f"Unexpected error: {str(e)}"}
            
        except ValueError as e:
            self.results['robots_sitemap'] = {'error': str(e)}
        except Exception as e:
            self.results['robots_sitemap'] = {'error': f"Unexpected error: {str(e)}"}

    def check_dns(self):
        """Check DNS records for the domain"""
        print("[*] Checking DNS records...")
        
        # Initialize result structure
        self.results['dns'] = {
            'records': {}
        }
        
        try:
            hostname = self._parse_url_hostname()
            self.results['dns']['hostname'] = hostname
            
            # Check various DNS record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    self.results['dns']['records'][record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    self.results['dns']['records'][record_type] = []
                except dns.resolver.NXDOMAIN:
                    self.results['dns']['records'][record_type] = ['NXDOMAIN']
                except Exception:
                    self.results['dns']['records'][record_type] = []
            
            # Check for CAA records (Certificate Authority Authorization)
            try:
                answers = dns.resolver.resolve(hostname, 'CAA')
                self.results['dns']['records']['CAA'] = [str(rdata) for rdata in answers]
                self.results['dns']['has_caa'] = True
            except Exception:
                self.results['dns']['records']['CAA'] = []
                self.results['dns']['has_caa'] = False
            
            # Check if DNSSEC is enabled (basic check)
            try:
                answers = dns.resolver.resolve(hostname, 'DNSKEY')
                self.results['dns']['dnssec_enabled'] = True
            except Exception:
                self.results['dns']['dnssec_enabled'] = False
            
        except ValueError as e:
            self.results['dns'] = {'error': str(e)}
        except Exception as e:
            self.results['dns'] = {'error': f"Unexpected error: {str(e)}"}

    def _is_test_enabled(self, test_key: str) -> bool:
        """Check if a test was enabled and has results (not error-only)"""
        if test_key not in self.results:
            return False
        result = self.results[test_key]
        if isinstance(result, dict):
            # If only error key exists, don't show in PDF (test failed completely)
            if 'error' in result and len(result) == 1:
                return False
            if not result:  # Empty dict
                return False
        return True

    def generate_pdf_report(self, output_file: str = 'website_test_report.pdf'):
        """Generate comprehensive PDF report"""
        print(f"\n[*] Generating PDF report: {output_file}")
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        doc = SimpleDocTemplate(output_file, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c5aa0'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("Website Testing Report", title_style))
        story.append(Paragraph(f"URL: {self.url}", styles['Normal']))
        story.append(Paragraph(f"Generated: {self.results['timestamp']}", styles['Normal']))
        story.append(Paragraph(f"Tests Completed: {len(self.enabled_tests)}", styles['Normal']))
        story.append(Paragraph("<i>Note: Lighthouse performance analysis is available in separate HTML report (lighthouse_report.html)</i>", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = []
        
        # Note: Lighthouse results are available in separate HTML report
        
        # Pa11y violations
        if self._is_test_enabled('pa11y'):
            summary_data.append(['Accessibility Issues', str(self.results['pa11y'].get('total_issues', 0))])
        
        # Security Headers
        if self._is_test_enabled('security_headers'):
            sh = self.results['security_headers']
            grade = sh.get('grade', 'N/A')
            missing = len(sh.get('missing_headers', []))
            summary_data.append(['Security Headers Grade', str(grade)])
            summary_data.append(['Missing Security Headers', str(missing)])
        
        # SSL
        if self._is_test_enabled('ssl'):
            ssl = self.results['ssl']
            cert_status = "✓ Valid" if ssl.get('certificate_valid') else "✗ Invalid"
            summary_data.append(['SSL Certificate', cert_status])
            if ssl.get('weak_protocols'):
                summary_data.append(['Weak SSL Protocols', ', '.join(ssl['weak_protocols'])])
        
        # W3C Validator
        if self._is_test_enabled('w3c_validator'):
            w3c = self.results['w3c_validator']
            summary_data.append(['HTML Errors', str(w3c.get('summary', {}).get('errors', 0))])
        
        # OWASP ZAP (only if enabled)
        if self._is_test_enabled('owasp_zap'):
            zap = self.results['owasp_zap']
            summary_data.append(['Security Alerts (ZAP)', str(zap.get('total_alerts', 0))])
        
        # Nuclei (only if enabled)
        if self._is_test_enabled('nuclei'):
            nuclei = self.results['nuclei']
            summary_data.append(['Security Findings', str(nuclei.get('total_vulnerabilities', 0))])
        
        if summary_data:
            summary_table = Table(summary_data, colWidths=[4*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5f5f5')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(summary_table)
        
        story.append(PageBreak())
        
        # Detailed Results - only add sections for enabled tests
        # Note: Lighthouse results are available in separate HTML report
        
        if self._is_test_enabled('pa11y'):
            self._add_pa11y_details(story, styles, heading_style)
        
        if self._is_test_enabled('security_headers') or self._is_test_enabled('ssl'):
            self._add_security_details(story, styles, heading_style)
        
        if self._is_test_enabled('w3c_validator'):
            self._add_w3c_details(story, styles, heading_style)
        
        if self._is_test_enabled('owasp_zap') or self._is_test_enabled('nuclei'):
            self._add_vulnerability_details(story, styles, heading_style)
        
        if self._is_test_enabled('robots_sitemap'):
            self._add_seo_details(story, styles, heading_style)
        
        if self._is_test_enabled('dns'):
            self._add_dns_details(story, styles, heading_style)
        
        # Build PDF
        doc.build(story)
        print(f"[✓] PDF report generated: {output_file}")


    def _add_pa11y_details(self, story, styles, heading_style):
        """Add Pa11y accessibility details to PDF"""
        story.append(Paragraph("Accessibility Analysis", heading_style))
        pa11y = self.results['pa11y']
        
        # Handle errors first
        if pa11y.get('error'):
            story.append(Paragraph(f"<b>Error:</b> {pa11y.get('error')}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("Note: Pa11y requires Chrome/Chromium to be properly installed.", styles['Normal']))
            story.append(PageBreak())
            return
        
        # Summary stats
        total_issues = pa11y.get('total_issues', 0)
        summary = pa11y.get('summary', {})
        
        story.append(Paragraph(f"<b>Total Issues: {total_issues}</b>", styles['Normal']))
        story.append(Paragraph(f"<b>By Type:</b> Errors: {summary.get('errors', 0)} | "
                              f"Warnings: {summary.get('warnings', 0)} | "
                              f"Notices: {summary.get('notices', 0)}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        issues = pa11y.get('issues', [])
        
        if not issues:
            story.append(Paragraph("<b>✓ No accessibility issues found!</b>", styles['Normal']))
            story.append(PageBreak())
            return
        
        # Group issues by type
        errors = [i for i in issues if i.get('type') == 'error']
        warnings = [i for i in issues if i.get('type') == 'warning']
        notices = [i for i in issues if i.get('type') == 'notice']
        
        # Show errors first
        if errors:
            story.append(Paragraph(f"<b>Errors ({len(errors)}):</b>", styles['Normal']))
            for i, issue in enumerate(errors, 1):
                # Use readable message as title, show code as secondary info
                message = issue.get('message', '')
                title = html.escape(message) if message else 'Unknown issue'

                story.append(Paragraph(f"<b>{i}. {title}</b>", styles['Normal']))

                # Show technical code in smaller text
                code = issue.get('code', '')
                if code:
                    story.append(Paragraph(f"  <i>Code: {html.escape(code)}</i>", styles['Normal']))

                # Show selector
                selector = issue.get('selector', '')
                if selector:
                    story.append(Paragraph(f"  <b>Location:</b> {html.escape(selector)}", styles['Normal']))

                # Show full HTML context
                context = issue.get('context', '')
                if context:
                    ctx_clean = html.escape(context.strip())
                    story.append(Paragraph(f"  <b>HTML:</b> {ctx_clean}", styles['Normal']))

                story.append(Spacer(1, 0.1*inch))
            story.append(Spacer(1, 0.15*inch))

        # Show warnings
        if warnings:
            story.append(Paragraph(f"<b>Warnings ({len(warnings)}):</b>", styles['Normal']))
            for i, issue in enumerate(warnings, 1):
                # Use readable message as title
                message = issue.get('message', '')
                title = html.escape(message) if message else 'Unknown issue'

                story.append(Paragraph(f"<b>{i}. {title}</b>", styles['Normal']))

                # Show technical code
                code = issue.get('code', '')
                if code:
                    story.append(Paragraph(f"  <i>Code: {html.escape(code)}</i>", styles['Normal']))

                # Show selector
                selector = issue.get('selector', '')
                if selector:
                    story.append(Paragraph(f"  <b>Location:</b> {html.escape(selector)}", styles['Normal']))

                story.append(Spacer(1, 0.08*inch))
            story.append(Spacer(1, 0.15*inch))
        
        # Show notices
        if notices:
            story.append(Paragraph(f"<b>Notices ({len(notices)}):</b>", styles['Normal']))
            for i, issue in enumerate(notices, 1):
                message = issue.get('message', '')
                title = html.escape(message) if message else 'Unknown notice'
                story.append(Paragraph(f"  {i}. {title}", styles['Normal']))
        
        story.append(PageBreak())

    def _add_security_details(self, story, styles, heading_style):
        """Add security details to PDF"""
        story.append(Paragraph("Security Analysis", heading_style))
        
        # Security Headers
        if self._is_test_enabled('security_headers'):
            sh = self.results['security_headers']
            story.append(Paragraph("<b>Security Headers:</b>", styles['Normal']))
            
            if 'grade' in sh:
                story.append(Paragraph(f"Mozilla Observatory Grade: {sh.get('grade', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"Score: {sh.get('score', 'N/A')}/100", styles['Normal']))
                story.append(Paragraph(f"Tests Passed: {sh.get('tests_passed', 0)}/{sh.get('tests_quantity', 0)}", styles['Normal']))
            
            missing = sh.get('missing_headers', [])
            if missing:
                story.append(Paragraph(f"<b>Missing Headers ({len(missing)}):</b>", styles['Normal']))
                for header in missing:
                    story.append(Paragraph(f"• {header}", styles['Normal']))
            
            present = sh.get('present_headers', [])
            if present:
                story.append(Paragraph(f"<b>Present Headers ({len(present)}):</b>", styles['Normal']))
                for header in present:
                    story.append(Paragraph(f"✓ {header}", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # SSL/TLS
        if self._is_test_enabled('ssl'):
            ssl = self.results['ssl']
            story.append(Paragraph("<b>SSL/TLS Configuration:</b>", styles['Normal']))
            
            if 'certificate_valid' in ssl:
                status = "✓ Valid" if ssl['certificate_valid'] else "✗ Invalid"
                story.append(Paragraph(f"Certificate: {status}", styles['Normal']))
            
            # Certificate details
            cert_details = ssl.get('certificate_details', {})
            if cert_details:
                story.append(Paragraph(f"Subject: {cert_details.get('subject', 'N/A')[:50]}", styles['Normal']))
                story.append(Paragraph(f"Valid Until: {cert_details.get('not_valid_after', 'N/A')}", styles['Normal']))
            
            if ssl.get('supports_tls_1_3'):
                story.append(Paragraph("✓ TLS 1.3 Supported", styles['Normal']))
            if ssl.get('supports_tls_1_2'):
                story.append(Paragraph("✓ TLS 1.2 Supported", styles['Normal']))
            
            if ssl.get('weak_protocols'):
                story.append(Paragraph(f"⚠ Weak Protocols Enabled: {', '.join(ssl['weak_protocols'])}", styles['Normal']))
            
            if ssl.get('has_weak_ciphers'):
                story.append(Paragraph("⚠ Weak cipher suites detected", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
        
        story.append(PageBreak())

    def _add_w3c_details(self, story, styles, heading_style):
        """Add W3C validation details to PDF"""
        story.append(Paragraph("HTML Validation (W3C)", heading_style))
        w3c = self.results['w3c_validator']
        
        summary = w3c.get('summary', {})
        story.append(Paragraph(
            f"<b>Errors: {summary.get('errors', 0)} | Warnings: {summary.get('warnings', 0)}</b>",
            styles['Normal']
        ))
        story.append(Spacer(1, 0.2*inch))
        
        errors = w3c.get('errors', [])
        if errors:
            story.append(Paragraph("<b>Errors:</b>", styles['Normal']))
            for error in errors:
                msg = error.get('message', 'N/A')
                line = error.get('lastLine', 'N/A')
                story.append(Paragraph(f"• Line {line}: {msg}", styles['Normal']))
        
        warnings = w3c.get('warnings', [])
        if warnings:
            story.append(Paragraph("<b>Warnings:</b>", styles['Normal']))
            for warning in warnings:
                msg = warning.get('message', 'N/A')
                line = warning.get('lastLine', 'N/A')
                story.append(Paragraph(f"• Line {line}: {msg}", styles['Normal']))
        
        story.append(PageBreak())

    def _add_vulnerability_details(self, story, styles, heading_style):
        """Add vulnerability scan details to PDF"""
        story.append(Paragraph("Security Scans", heading_style))
        
        # OWASP ZAP
        if self._is_test_enabled('owasp_zap'):
            zap = self.results['owasp_zap']
            story.append(Paragraph(f"<b>OWASP Scan: {zap.get('total_alerts', 0)} alerts</b>", styles['Normal']))
            
            summary = zap.get('summary', {})
            story.append(Paragraph(
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)} | "
                f"Info: {summary.get('info', 0)}",
                styles['Normal']
            ))
            
            alerts = zap.get('alerts', [])
            if alerts:
                # Group alerts by risk level
                high_alerts = [a for a in alerts if a.get('risk') == 'High']
                medium_alerts = [a for a in alerts if a.get('risk') == 'Medium']
                low_alerts = [a for a in alerts if a.get('risk') == 'Low']
                info_alerts = [a for a in alerts if a.get('risk') == 'Informational']
                
                if high_alerts:
                    story.append(Paragraph(f"<b>High Risk Alerts ({len(high_alerts)}):</b>", styles['Normal']))
                    for alert in high_alerts[:10]:
                        story.append(Paragraph(f"• {html.escape(alert.get('name', 'Unknown'))}", styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                
                if medium_alerts:
                    story.append(Paragraph(f"<b>Medium Risk Alerts ({len(medium_alerts)}):</b>", styles['Normal']))
                    for alert in medium_alerts[:10]:
                        story.append(Paragraph(f"• {html.escape(alert.get('name', 'Unknown'))}", styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                
                if low_alerts:
                    story.append(Paragraph(f"<b>Low Risk Alerts ({len(low_alerts)}):</b>", styles['Normal']))
                    for alert in low_alerts[:10]:
                        story.append(Paragraph(f"• {html.escape(alert.get('name', 'Unknown'))}", styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
                
                if info_alerts:
                    story.append(Paragraph(f"<b>Informational ({len(info_alerts)}):</b>", styles['Normal']))
                    for alert in info_alerts[:5]:
                        story.append(Paragraph(f"• {html.escape(alert.get('name', 'Unknown'))}", styles['Normal']))
            else:
                story.append(Paragraph("<b>✓ No security alerts found.</b>", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Nuclei
        if self._is_test_enabled('nuclei'):
            nuclei = self.results['nuclei']

            story.append(Paragraph(
                f"<b>Security Scan — {nuclei.get('total_vulnerabilities', 0)} Findings</b>",
                styles['Normal']
            ))

            summary = nuclei.get('summary', {})
            story.append(Paragraph(
                f"<b>Severity Breakdown:</b> "
                f"Critical {summary.get('critical', 0)} | "
                f"High {summary.get('high', 0)} | "
                f"Medium {summary.get('medium', 0)} | "
                f"Low {summary.get('low', 0)} | "
                f"Info {summary.get('info', 0)} | "
                f"Unknown {summary.get('unknown', 0)}",
                styles['Normal']
            ))
            story.append(Spacer(1, 0.25 * inch))

            vulns = nuclei.get('vulnerabilities', [])
            
            if not vulns:
                story.append(Paragraph("<b>✓ No vulnerabilities found.</b>", styles['Normal']))
                story.append(PageBreak())
                return

            for idx, vuln in enumerate(vulns, start=1):
                severity = (vuln.get('severity') or 'unknown').upper()
                scan_type = (vuln.get('type') or 'unknown').lower()

                # ── Stable finding header ─────────────────────────────
                story.append(Paragraph(
                    f"• <b>Finding #{idx}</b> — <b>[{severity}]</b> {vuln.get('name', 'Unnamed Issue')}",
                    styles['Normal']
                ))

                # Template ID (always)
                story.append(Paragraph(
                    f"<b>Template ID:</b> {vuln.get('template_id', 'N/A')}",
                    styles['Normal']
                ))

                # Scan type (always)
                story.append(Paragraph(
                    f"<b>Scan Type:</b> {scan_type}",
                    styles['Normal']
                ))

                target = (
                    vuln.get('matched_at')
                    or vuln.get('host')
                    or vuln.get('target')
                    or 'N/A'
                )

                story.append(Paragraph(
                    f"<b>Target:</b> {target}",
                    styles['Normal']
                ))

                # ── Description (only if meaningful) ──────────────────
                if vuln.get('description'):
                    story.append(Paragraph(
                        f"<b>Description:</b> {vuln['description']}",
                        styles['Normal']
                    ))

                # ── Impact (skip for tech/info noise) ─────────────────
                if vuln.get('impact'):
                    story.append(Paragraph(
                        f"<b>Impact:</b> {vuln['impact']}",
                        styles['Normal']
                    ))

                # ── Classification (if exists) ────────────────────────
                classification = vuln.get('classification', {})
                class_parts = []

                if classification.get('cvss_score'):
                    class_parts.append(f"CVSS {classification['cvss_score']}")
                if classification.get('cwe_id'):
                    cwe = classification['cwe_id']
                    if isinstance(cwe, list):
                        cwe = ', '.join(cwe)
                    class_parts.append(f"CWE {cwe}")

                if class_parts:
                    story.append(Paragraph(
                        f"<b>Classification:</b> {' | '.join(class_parts)}",
                        styles['Normal']
                    ))

                # ── Evidence ──────────────────────────────
                extracted = vuln.get('extracted_results', [])
                if extracted:
                    story.append(Paragraph(
                        f"<b>Extracted Results:</b> {', '.join(map(str, extracted))}",
                        styles['Normal']
                    ))

                # ── Matcher name (very important for tech / info templates)
                if vuln.get('matcher_name'):
                    story.append(Paragraph(
                        f"<b>Matcher:</b> {vuln['matcher_name']}",
                        styles['Normal']
                    ))

                # ── Reproduction (only if useful) ──────────────────────
                if vuln.get('curl_command'):
                    story.append(Paragraph(
                        f"<b>Reproduce:</b> {vuln['curl_command']}",
                        styles['Normal']
                    ))

                # ── Remediation (only if exists) ───────────────────────
                if vuln.get('remediation'):
                    story.append(Paragraph(
                        f"<b>Remediation:</b> {vuln['remediation']}",
                        styles['Normal']
                    ))

                # ── References (optional) ──────────────────────────────
                references = vuln.get('references', [])
                if references:
                    ref_text = ', '.join(references[:2])
                    if len(references) > 2:
                        ref_text += f" (+{len(references) - 2} more)"
                    story.append(Paragraph(
                        f"<b>References:</b> {ref_text}",
                        styles['Normal']
                    ))

                story.append(Spacer(1, 0.2 * inch))


        
        story.append(PageBreak())

    def _add_seo_details(self, story, styles, heading_style):
        """Add SEO-related details to PDF"""
        story.append(Paragraph("SEO Analysis", heading_style))
        
        rs = self.results['robots_sitemap']
        
        # Robots.txt
        story.append(Paragraph("<b>Robots.txt:</b>", styles['Normal']))
        robots = rs.get('robots_txt', {})
        if robots.get('exists'):
            story.append(Paragraph("✓ robots.txt found", styles['Normal']))
            story.append(Paragraph(f"  Size: {robots.get('size', 0)} bytes", styles['Normal']))
            if robots.get('has_sitemap_reference'):
                story.append(Paragraph("  ✓ References sitemap", styles['Normal']))
            else:
                story.append(Paragraph("  ⚠ No sitemap reference found", styles['Normal']))
            if robots.get('has_disallow_rules'):
                story.append(Paragraph("  ✓ Contains disallow rules", styles['Normal']))
        else:
            story.append(Paragraph("✗ robots.txt not found", styles['Normal']))
        
        story.append(Spacer(1, 0.1*inch))
        
        # Sitemap
        story.append(Paragraph("<b>Sitemap:</b>", styles['Normal']))
        sitemap = rs.get('sitemap', {})
        if sitemap.get('exists'):
            story.append(Paragraph("✓ sitemap.xml found", styles['Normal']))
            story.append(Paragraph(f"  URLs found: {sitemap.get('url_count', 0)}", styles['Normal']))
            if sitemap.get('is_valid_xml'):
                story.append(Paragraph("  ✓ Valid XML format", styles['Normal']))
            else:
                story.append(Paragraph("  ⚠ Invalid XML format", styles['Normal']))
        else:
            story.append(Paragraph("✗ sitemap.xml not found", styles['Normal']))
        
        story.append(PageBreak())

    def _add_dns_details(self, story, styles, heading_style):
        """Add DNS details to PDF"""
        story.append(Paragraph("DNS Analysis", heading_style))
        
        dns_data = self.results['dns']
        story.append(Paragraph(f"<b>Hostname: {dns_data.get('hostname', 'N/A')}</b>", styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        records = dns_data.get('records', {})
        for record_type, values in records.items():
            if values:
                story.append(Paragraph(f"<b>{record_type} Records:</b>", styles['Normal']))
                for value in values[:5]:  # Limit to 5 per type
                    story.append(Paragraph(f"  • {value[:80]}", styles['Normal']))
        
        story.append(Spacer(1, 0.1*inch))
        
        if dns_data.get('has_caa'):
            story.append(Paragraph("✓ CAA records configured", styles['Normal']))
        else:
            story.append(Paragraph("⚠ No CAA records (Certificate Authority Authorization)", styles['Normal']))
        
        if dns_data.get('dnssec_enabled'):
            story.append(Paragraph("✓ DNSSEC enabled", styles['Normal']))
        else:
            story.append(Paragraph("⚠ DNSSEC not detected", styles['Normal']))
        
        story.append(PageBreak())


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive Website Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tester.py https://example.com
  python tester.py https://example.com -o ./reports -w 8
  python tester.py https://example.com --json results.json
  python tester.py https://example.com --enable-zap --enable-nuclei

Tests performed:
  - Lighthouse (Performance, SEO, Accessibility, Best Practices)
  - Pa11y (Accessibility)
  - Security Headers (Mozilla Observatory)
  - SSL/TLS Testing (sslyze)
  - W3C HTML Validator
  - Robots.txt & Sitemap Check
  - DNS Records Analysis
  
Optional (use flags to enable):
  - OWASP ZAP (Security Scan) - use --enable-zap
  - Nuclei (Vulnerability Scanner) - use --enable-nuclei
        """
    )
    
    parser.add_argument('url', help='Website URL to test')
    parser.add_argument('-o', '--output', default='/output',
                       help='Output directory for reports (default: /output). PDF and HTML reports will be generated here.')
    parser.add_argument('-j', '--json', help='Save JSON results to file')
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Number of parallel workers (default: 5)')
    parser.add_argument('--enable-zap', action='store_true',
                       help='Enable OWASP ZAP security scan (requires Docker socket access)')
    parser.add_argument('--enable-nuclei', action='store_true',
                       help='Enable Nuclei vulnerability scanner')
    
    args = parser.parse_args()
    
    # Both are disabled by default, only enabled if flags are provided
    enable_zap = args.enable_zap
    enable_nuclei = args.enable_nuclei
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print("\n" + "="*80)
    print("  COMPREHENSIVE WEBSITE TESTING TOOL")
    print("="*80)
    
    # Run tests
    tester = Tester(
        args.url, 
        max_workers=args.workers, 
        output_directory=args.output,
        enable_zap=enable_zap,
        enable_nuclei=enable_nuclei
    )
    test_results = tester.run_all_tests()

    # Save JSON if requested
    if args.json:
        json_dir = os.path.dirname(args.json)
        if json_dir and not os.path.exists(json_dir):
            os.makedirs(json_dir, exist_ok=True)
        with open(args.json, 'w') as f:
            json.dump(test_results, f, indent=2, default=str)
        print(f"\n[✓] JSON results saved to: {args.json}")

    # Generate PDF report in the output directory
    pdf_filename = os.path.join(args.output, 'report.pdf')
    tester.generate_pdf_report(pdf_filename)
    
    print("\n" + "="*80)
    print("  TESTING COMPLETE")
    print("="*80 + "\n")


if __name__ == '__main__':
    main()
