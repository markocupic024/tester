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
import time
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
    def __init__(self, url: str, max_workers: int = 5, output_directory: str = '/output'):
        self.url = url
        self.max_workers = max_workers
        self.output_directory = output_directory
        self.enabled_tests = set()  # Track which tests are enabled
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
        """Run all tests in parallel"""
        print(f"\n{'='*80}")
        print(f"Starting comprehensive tests for: {self.url}")
        print(f"{'='*80}\n")
        
        # Define test functions - comment/uncomment to enable/disable tests
        tests = [
            ('Lighthouse (Performance/SEO/Accessibility/Best Practices)', self.run_lighthouse),
            ('Pa11y (Accessibility)', self.run_pa11y),
            ('Security Headers Analysis', self.check_security_headers),
            ('SSL/TLS Testing (sslyze)', self.test_ssl),
            ('W3C HTML Validator', self.validate_w3c),
            ('Robots.txt & Sitemap', self.check_robots_sitemap),
            ('DNS Records', self.check_dns),
            # Uncomment the following lines to enable additional security scans:
            # ('OWASP ZAP Security Scan', self.run_owasp_zap),
            # ('Nuclei Vulnerability Scanner', self.run_nuclei),
        ]
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(test_func): name for name, test_func in tests}
            
            for future in as_completed(futures):
                test_name = futures[future]
                try:
                    future.result()
                    print(f"[✓] {test_name} completed")
                    # Track enabled tests for PDF generation
                    self.enabled_tests.add(test_name)
                except Exception as e:
                    print(f"[✗] {test_name} failed: {e}")
        
        return self.results

    def run_lighthouse(self):
        """Run Google Lighthouse tests"""
        print("[*] Running Lighthouse tests...")
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
                    'html_file': 'lighthouse_report.html',  # Relative path for user reference
                    'full_path': html_file,
                    'success': True
                }
                print(f"[✓] Lighthouse HTML report generated: lighthouse_report.html")
            else:
                self.results['lighthouse'] = {
                    'error': result.stderr or 'Failed to generate Lighthouse HTML report',
                    'success': False
                }
                
        except Exception as e:
            self.results['lighthouse']['error'] = str(e)

    def run_pa11y(self):
        """Run Pa11y accessibility tests"""
        print("[*] Running Pa11y accessibility tests...")
        try:
            # Create config file for Pa11y with Chrome flags for Docker
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
                os.unlink(config_file)
            except Exception:
                pass
            
            # Pa11y returns exit code 2 when issues are found, which is normal
            output = result.stdout.strip() if result.stdout else ''
            
            if not output:
                if result.stderr:
                    self.results['pa11y'] = {'error': result.stderr[:500], 'ran': True}
                    print(f"[!] Pa11y error: {result.stderr[:200]}")
                else:
                    self.results['pa11y'] = {'error': 'No output from pa11y', 'ran': True}
                return
            
            # Parse JSON output
            try:
                issues = json.loads(output)
            except json.JSONDecodeError as e:
                self.results['pa11y'] = {'error': f"JSON parsing error: {e}", 'ran': True}
                print(f"[!] Pa11y JSON error: {e}")
                return
            
            # Pa11y returns a list of issues
            if not isinstance(issues, list):
                issues = []
            
            # Categorize by type (error, warning, notice)
            errors = [i for i in issues if i.get('type') == 'error']
            warnings = [i for i in issues if i.get('type') == 'warning']
            notices = [i for i in issues if i.get('type') == 'notice']
            
            self.results['pa11y'] = {
                'ran': True,
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
            
            print(f"[✓] Pa11y found {len(errors)} errors, {len(warnings)} warnings, {len(notices)} notices")
                
        except FileNotFoundError:
            self.results['pa11y'] = {'error': 'pa11y command not found. Is pa11y installed?', 'ran': False}
            print("[!] Pa11y command not found")
        except subprocess.TimeoutExpired:
            self.results['pa11y'] = {'error': 'pa11y timed out after 180 seconds', 'ran': True}
            print("[!] Pa11y timed out")
        except Exception as e:
            self.results['pa11y'] = {'error': f"Unexpected error: {str(e)}", 'ran': True}
            print(f"[!] Pa11y error: {e}")

    def check_security_headers(self):
        """Check security headers using Mozilla Observatory API and manual check"""
        print("[*] Checking security headers...")
        
        # 1. Robustly extract the hostname
        try:
            parsed_url = urlparse(self.url)
            host = parsed_url.netloc
            if not host:
                raise ValueError("Invalid URL format.")
        except Exception as e:
            self.results['security_headers'] = {'error': f"URL Parsing Error: {str(e)}"}
            return

        api_url = "https://http-observatory.security.mozilla.org/api/v1/analyze"
        params = {'host': host, 'rescan': 'true'}
        
        try:
            # --- PHASE 1: Start Scan ---
            response = requests.post(api_url, params=params, timeout=30)
            response.raise_for_status()
            scan_data = response.json()
            
            if scan_data and 'scan_id' in scan_data:
                result_url = f"{api_url}?host={host}"
                
                # --- PHASE 2: Polling for Results ---
                max_attempts = 12
                for _ in range(max_attempts):
                    time.sleep(10) 
                    
                    result = requests.get(result_url, timeout=30)
                    result.raise_for_status()
                    data = result.json()
                    
                    state = data.get('state')
                    
                    if state == 'FINISHED':
                        self.results['security_headers'] = {
                            'grade': data.get('grade'),
                            'score': data.get('score'),
                            'tests_passed': data.get('tests_passed'),
                            'tests_failed': data.get('tests_failed'),
                            'tests_quantity': data.get('tests_quantity'),
                            'report_url': f"https://observatory.mozilla.org/analyze?host={host}"
                        }
                        break
                    elif state == 'ABORTED':
                        self.results['security_headers'] = {'error': 'Mozilla Observatory scan was aborted.'}
                        return
                else:
                    self.results['security_headers'] = {'error': 'Mozilla Observatory scan timed out after 120 seconds.'}
                    return

            # --- PHASE 3: Manual Header Check ---
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
            
            if 'security_headers' not in self.results:
                self.results['security_headers'] = {}

            self.results['security_headers']['headers'] = security_headers_check
            self.results['security_headers']['missing_headers'] = [
                k for k, v in security_headers_check.items() if v == 'Missing'
            ]
            self.results['security_headers']['present_headers'] = [
                k for k, v in security_headers_check.items() if v != 'Missing'
            ]
                
        except requests.exceptions.RequestException as req_e:
            self.results['security_headers']['error'] = f"Request Error: {str(req_e)}"
        except Exception as e:
            self.results['security_headers']['error'] = f"General Error: {str(e)}"

    def test_ssl(self):
        """Test SSL/TLS configuration using sslyze"""
        print("[*] Testing SSL/TLS configuration...")

        try:
            parsed_url = urlparse(self.url)
            hostname = parsed_url.netloc.split(':')[0]
            if not hostname:
                raise ValueError("Invalid URL format or missing hostname.")
        except Exception as e:
            self.results['ssl'] = {'error': f"URL Parsing Error: {str(e)}"}
            return

        try:
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
                
        except json.JSONDecodeError:
            self.results['ssl'] = {'error': f"Failed to parse sslyze JSON output."}
        except FileNotFoundError:
            self.results['ssl'] = {'error': 'sslyze not installed', 'https_enabled': self.url.startswith('https')}
        except Exception as e:
            self.results['ssl'] = {'error': str(e)}

    def run_owasp_zap(self):
        """Run OWASP ZAP baseline scan"""
        print("[*] Running OWASP ZAP baseline scan...")
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                report_file = f.name
            
            cmd = [
                'docker', 'run', '--rm',
                '-v', f'{os.path.dirname(report_file)}:/zap/wrk:rw',
                'owasp/zap2docker-stable',
                'zap-baseline.py',
                '-t', self.url,
                '-J', f'/zap/wrk/{os.path.basename(report_file)}',
                '-I'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if os.path.exists(report_file):
                with open(report_file, 'r') as f:
                    data = json.load(f)
                
                alerts = data.get('site', [{}])[0].get('alerts', [])
                
                self.results['owasp_zap'] = {
                    'total_alerts': len(alerts),
                    'alerts': [
                        {
                            'name': alert.get('name'),
                            'risk': alert.get('riskdesc'),
                            'confidence': alert.get('confidence'),
                            'description': alert.get('desc', '')[:200]
                        }
                        for alert in alerts
                    ],
                    'summary': {
                        'high': len([a for a in alerts if 'High' in a.get('riskdesc', '')]),
                        'medium': len([a for a in alerts if 'Medium' in a.get('riskdesc', '')]),
                        'low': len([a for a in alerts if 'Low' in a.get('riskdesc', '')]),
                        'info': len([a for a in alerts if 'Informational' in a.get('riskdesc', '')])
                    }
                }
                
                os.unlink(report_file)
            else:
                self.results['owasp_zap'] = {'skipped': 'ZAP Docker not available or scan failed'}
                
        except FileNotFoundError:
            self.results['owasp_zap'] = {'skipped': 'Docker not available'}
        except Exception as e:
            self.results['owasp_zap'] = {'error': str(e)}

    def run_nuclei(self):
        """Run Nuclei vulnerability scanner"""
        print("[*] Running Nuclei vulnerability scanner...")
        try:
            cmd = [
                'nuclei',
                '-u', self.url,
                '-json',
                '-silent'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                vulnerabilities = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append({
                                'template': vuln.get('template-id'),
                                'name': vuln.get('info', {}).get('name'),
                                'severity': vuln.get('info', {}).get('severity'),
                                'matched_at': vuln.get('matched-at')
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
                        'low': len([v for v in vulnerabilities if v.get('severity') == 'low'])
                    }
                }
            else:
                self.results['nuclei'] = {'completed': True, 'total_vulnerabilities': 0, 'vulnerabilities': []}
                
        except FileNotFoundError:
            self.results['nuclei'] = {'skipped': 'Nuclei not installed'}
        except Exception as e:
            self.results['nuclei'] = {'error': str(e)}

    def validate_w3c(self):
        """Validate HTML using W3C Validator"""
        print("[*] Running W3C HTML Validator...")
        try:
            api_url = f"https://validator.w3.org/nu/?doc={self.url}&out=json"
            
            response = requests.get(api_url, timeout=60, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; WebsiteTester/1.0)'
            })
            data = response.json()
            
            messages = data.get('messages', [])
            
            self.results['w3c_validator'] = {
                'total_issues': len(messages),
                'errors': [m for m in messages if m.get('type') == 'error'],
                'warnings': [m for m in messages if m.get('type') == 'info' or m.get('subType') == 'warning'],
                'summary': {
                    'errors': len([m for m in messages if m.get('type') == 'error']),
                    'warnings': len([m for m in messages if m.get('type') == 'info' or m.get('subType') == 'warning'])
                }
            }
            
        except Exception as e:
            self.results['w3c_validator'] = {'error': str(e)}

    def check_robots_sitemap(self):
        """Check robots.txt and sitemap.xml"""
        print("[*] Checking robots.txt and sitemap.xml...")
        
        try:
            parsed_url = urlparse(self.url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            result = {
                'robots_txt': {},
                'sitemap': {}
            }
            
            # Check robots.txt
            try:
                robots_url = f"{base_url}/robots.txt"
                response = requests.get(robots_url, timeout=30)
                if response.status_code == 200:
                    content = response.text
                    result['robots_txt'] = {
                        'exists': True,
                        'size': len(content),
                        'has_sitemap_reference': 'sitemap' in content.lower(),
                        'has_disallow_rules': 'disallow' in content.lower(),
                    }
                else:
                    result['robots_txt'] = {'exists': False, 'status_code': response.status_code}
            except Exception as e:
                result['robots_txt'] = {'error': str(e)}
            
            # Check sitemap.xml
            try:
                sitemap_url = f"{base_url}/sitemap.xml"
                response = requests.get(sitemap_url, timeout=30)
                if response.status_code == 200:
                    content = response.text
                    # Count URLs in sitemap
                    url_count = content.lower().count('<url>')
                    result['sitemap'] = {
                        'exists': True,
                        'size': len(content),
                        'url_count': url_count,
                        'is_valid_xml': content.strip().startswith('<?xml') or content.strip().startswith('<urlset')
                    }
                else:
                    result['sitemap'] = {'exists': False, 'status_code': response.status_code}
            except Exception as e:
                result['sitemap'] = {'error': str(e)}
            
            self.results['robots_sitemap'] = result
            
        except Exception as e:
            self.results['robots_sitemap'] = {'error': str(e)}

    def check_dns(self):
        """Check DNS records for the domain"""
        print("[*] Checking DNS records...")
        
        try:
            parsed_url = urlparse(self.url)
            hostname = parsed_url.netloc.split(':')[0]
            
            result = {
                'hostname': hostname,
                'records': {}
            }
            
            # Check various DNS record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    result['records'][record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    result['records'][record_type] = []
                except dns.resolver.NXDOMAIN:
                    result['records'][record_type] = ['NXDOMAIN']
                except Exception:
                    result['records'][record_type] = []
            
            # Check for CAA records (Certificate Authority Authorization)
            try:
                answers = dns.resolver.resolve(hostname, 'CAA')
                result['records']['CAA'] = [str(rdata) for rdata in answers]
                result['has_caa'] = True
            except Exception:
                result['records']['CAA'] = []
                result['has_caa'] = False
            
            # Check if DNSSEC is enabled (basic check)
            try:
                answers = dns.resolver.resolve(hostname, 'DNSKEY')
                result['dnssec_enabled'] = True
            except Exception:
                result['dnssec_enabled'] = False
            
            self.results['dns'] = result
            
        except Exception as e:
            self.results['dns'] = {'error': str(e)}

    def _is_test_enabled(self, test_key: str) -> bool:
        """Check if a test was enabled and has results (not skipped/error only)"""
        if test_key not in self.results:
            return False
        result = self.results[test_key]
        if isinstance(result, dict):
            if result.get('skipped'):
                return False
            # For pa11y, show in PDF even if there was an error (so user knows it ran)
            if test_key == 'pa11y' and result.get('ran'):
                return True
            # For other tests, skip if only error and nothing else useful
            if result.get('error') and len(result) <= 2:  # error + ran
                return False
            if not result:  # Empty dict
                return False
        return True

    def generate_pdf_report(self, output_file: str = 'website_test_report.pdf'):
        """Generate comprehensive PDF report"""
        print(f"\n[*] Generating PDF report: {output_file}")
        
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
            summary_data.append(['Vulnerabilities (Nuclei)', str(nuclei.get('total_vulnerabilities', 0))])
        
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
        story.append(Paragraph("Vulnerability Scans", heading_style))
        
        # OWASP ZAP
        if self._is_test_enabled('owasp_zap'):
            zap = self.results['owasp_zap']
            story.append(Paragraph(f"<b>OWASP ZAP Scan: {zap.get('total_alerts', 0)} alerts</b>", styles['Normal']))
            
            summary = zap.get('summary', {})
            story.append(Paragraph(
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)} | "
                f"Info: {summary.get('info', 0)}",
                styles['Normal']
            ))
            
            alerts = zap.get('alerts', [])[:10]
            for alert in alerts:
                story.append(Paragraph(f"• [{alert.get('risk', 'N/A')}] {alert.get('name', 'N/A')}", styles['Normal']))
            
            story.append(Spacer(1, 0.2*inch))
        
        # Nuclei
        if self._is_test_enabled('nuclei'):
            nuclei = self.results['nuclei']
            
            story.append(Paragraph(f"<b>Nuclei Scan: {nuclei.get('total_vulnerabilities', 0)} vulnerabilities</b>", styles['Normal']))
            
            summary = nuclei.get('summary', {})
            story.append(Paragraph(
                f"Critical: {summary.get('critical', 0)} | "
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)}",
                styles['Normal']
            ))
            story.append(Spacer(1, 0.2*inch))
            
            vulns = nuclei.get('vulnerabilities', [])
            for vuln in vulns:
                story.append(Paragraph(
                    f"• [{vuln.get('severity', 'N/A').upper()}] {vuln.get('name', 'N/A')}",
                    styles['Normal']
                ))
                story.append(Paragraph(f"  Template: {vuln.get('template', 'N/A')}", styles['Normal']))
                story.append(Spacer(1, 0.05*inch))
        
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

Tests performed:
  - Lighthouse (Performance, SEO, Accessibility, Best Practices)
  - Pa11y (Accessibility)
  - Security Headers (Mozilla Observatory)
  - SSL/TLS Testing (sslyze)
  - W3C HTML Validator
  - Robots.txt & Sitemap Check
  - DNS Records Analysis
  
Optional (uncomment in code to enable):
  - OWASP ZAP (Security Scan)
  - Nuclei (Vulnerability Scanner)
        """
    )
    
    parser.add_argument('url', help='Website URL to test')
    parser.add_argument('-o', '--output', default='/output',
                       help='Output directory for reports (default: /output). PDF and HTML reports will be generated here.')
    parser.add_argument('-j', '--json', help='Save JSON results to file')
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Number of parallel workers (default: 5)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print("\n" + "="*80)
    print("  COMPREHENSIVE WEBSITE TESTING TOOL")
    print("="*80)
    
    # Run tests
    tester = Tester(args.url, max_workers=args.workers, output_directory=args.output)
    test_results = tester.run_all_tests()

    # Save JSON if requested
    if args.json:
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
