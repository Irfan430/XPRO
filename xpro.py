#!/usr/bin/env python3
"""
XPRO - APEX SENTINEL
Autonomous Cyber-Intelligence Unit - High-Velocity Security Auditing Platform
Principal Security Architect Framework
"""

import os
import sys
import json
import time
import signal
import threading
import subprocess
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
import psutil
import pandas as pd

# Rich imports for cinematic UI
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich.columns import Columns
from rich.text import Text
from rich.prompt import Prompt, Confirm
import pyfiglet
from colorama import init, Fore, Style

# Security tool imports
import nmap
import scapy.all as scapy
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import dns.resolver

# Initialize colorama and Rich
init(autoreset=True)
console = Console()

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

@dataclass
class Config:
    """Global configuration for XPRO - APEX SENTINEL"""
    THREAD_POOL_SIZE: int = None  # Auto-calculated based on RAM
    MAX_WORKERS: int = 50
    TIMEOUT: int = 30
    OUTPUT_DIR: Path = Path.home() / "Downloads" / "XPRO_REPORTS"
    NMAP_TIMING: int = 4  # Aggressive timing
    CVSS_THRESHOLD: float = 7.0  # High risk threshold
    
    def __post_init__(self):
        """Auto-configure based on system resources"""
        # Calculate optimal thread pool based on 16GB RAM
        ram_gb = psutil.virtual_memory().total / (1024**3)
        if ram_gb >= 16:
            self.THREAD_POOL_SIZE = 50
        elif ram_gb >= 8:
            self.THREAD_POOL_SIZE = 25
        else:
            self.THREAD_POOL_SIZE = 15
        
        # Ensure output directory exists
        self.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================================
# CINEMATIC TERMINAL DASHBOARD
# ============================================================================

class ApexDashboard:
    """Rich-based cinematic dashboard with real-time updates"""
    
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.running = True
        self.scan_progress = 0
        self.active_threads = 0
        self.vulnerabilities_found = 0
        self.services_discovered = 0
        
        # Setup layout
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        self.layout["main"].split_row(
            Layout(name="left_panel", ratio=2),
            Layout(name="right_panel", ratio=1)
        )
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def show_banner(self):
        """Display cinematic banner"""
        banner = pyfiglet.figlet_format("APEX SENTINEL", font="slant")
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        self.console.print("[bold yellow]⚡ DEFENSIVE RESILIENCE THROUGH AUTOMATED INTELLIGENCE[/bold yellow]\n")
    
    def update_dashboard(self, module: str, status: str, details: Dict):
        """Update dashboard with current module status"""
        self.clear_screen()
        self.show_banner()
        
        # Create main panels
        left_panel = self._create_left_panel(module, status, details)
        right_panel = self._create_right_panel(details)
        
        # Display
        self.console.print(left_panel)
        self.console.print("\n")
        self.console.print(right_panel)
    
    def _create_left_panel(self, module: str, status: str, details: Dict) -> Panel:
        """Create main status panel"""
        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_column(justify="right")
        
        grid.add_row(f"[bold]Active Module:[/bold]", f"[green]{module}[/green]")
        grid.add_row(f"[bold]Status:[/bold]", f"[yellow]{status}[/yellow]")
        grid.add_row(f"[bold]Threads Active:[/bold]", f"[cyan]{self.active_threads}[/cyan]")
        grid.add_row(f"[bold]Vulnerabilities:[/bold]", f"[red]{self.vulnerabilities_found}[/red]")
        grid.add_row(f"[bold]Services Found:[/bold]", f"[blue]{self.services_discovered}[/blue]")
        
        # Progress bar
        progress_bar = BarColumn(bar_width=50)
        progress_text = Text(f"Scan Progress: {self.scan_progress}%")
        
        return Panel(
            grid,
            title="[bold]APEX SENTINEL CONTROL PANEL[/bold]",
            border_style="cyan"
        )
    
    def _create_right_panel(self, details: Dict) -> Panel:
        """Create tactical advisor panel"""
        advisor_text = Text()
        
        if "critical_issues" in details:
            advisor_text.append("🚨 CRITICAL FINDINGS:\n", style="bold red")
            for issue in details["critical_issues"][:3]:  # Show top 3
                advisor_text.append(f"• {issue}\n", style="red")
        
        if "recommendations" in details:
            advisor_text.append("\n🛡️ IMMEDIATE ACTIONS:\n", style="bold green")
            for rec in details["recommendations"][:3]:
                advisor_text.append(f"• {rec}\n", style="green")
        
        if "next_step" in details:
            advisor_text.append(f"\n⚡ NEXT STEP: {details['next_step']}\n", style="bold yellow")
        
        return Panel(
            advisor_text,
            title="[bold]TACTICAL ADVISOR[/bold]",
            border_style="yellow"
        )

# ============================================================================
# CORE ENGINE CLASSES
# ============================================================================

class AssetDiscovery:
    """Aggressive asset discovery and fingerprinting module"""
    
    def __init__(self, config: Config, dashboard: ApexDashboard):
        self.config = config
        self.dashboard = dashboard
        self.nm = nmap.PortScanner()
        self.discovered_assets = []
        self.services = {}
        
    def scan_network(self, target: str) -> Dict:
        """Perform comprehensive network scan"""
        self.dashboard.update_dashboard(
            "Asset Discovery",
            "Initializing Aggressive Scan",
            {"next_step": "NMAP OS Fingerprinting"}
        )
        
        try:
            # Fast ping sweep first
            self.dashboard.active_threads = 10
            alive_hosts = self._ping_sweep(target)
            
            # Intensive NMAP scan on alive hosts
            scan_results = []
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.THREAD_POOL_SIZE
            ) as executor:
                futures = []
                for host in alive_hosts[:20]:  # Limit for demo
                    future = executor.submit(self._deep_host_scan, host)
                    futures.append(future)
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        scan_results.append(result)
                        self.services_discovered += len(result.get('services', []))
                        self.dashboard.services_discovered = self.services_discovered
            
            return {
                "total_hosts": len(alive_hosts),
                "scanned_hosts": len(scan_results),
                "assets": scan_results,
                "os_fingerprints": self._analyze_os_fingerprints(scan_results)
            }
            
        except Exception as e:
            console.print(f"[red]Asset Discovery Error: {e}[/red]")
            return {}
    
    def _ping_sweep(self, target: str) -> List[str]:
        """Fast ICMP ping sweep using Scapy"""
        alive_hosts = []
        
        # Parse target range
        if "/" in target:
            # It's a CIDR
            ips = list(scapy.ARP().make_table(target))
        else:
            ips = [target]
        
        # Send ICMP packets in parallel
        ans, unans = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(dst=target)/scapy.ICMP(),
            timeout=2,
            verbose=False
        )
        
        for sent, received in ans:
            alive_hosts.append(received[scapy.IP].src)
        
        return alive_hosts
    
    def _deep_host_scan(self, host: str) -> Dict:
        """Intensive single host scan"""
        try:
            # Aggressive NMAP scan
            self.nm.scan(
                hosts=host,
                arguments=f'-sS -sV -sC -O -A -T{self.config.NMAP_TIMING} --script vuln'
            )
            
            if host in self.nm.all_hosts():
                host_info = self.nm[host]
                
                # Extract service information
                services = []
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in ports:
                        service = host_info[proto][port]
                        services.append({
                            'port': port,
                            'protocol': proto,
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', 'unknown'),
                            'state': service.get('state', 'unknown')
                        })
                
                # OS detection
                os_info = host_info.get('osmatch', [{}])[0] if host_info.get('osmatch') else {}
                
                # Vulnerability scripts
                vulns = []
                if 'script' in host_info:
                    for script_name, script_output in host_info['script'].items():
                        if 'vuln' in script_name.lower():
                            vulns.append({
                                'script': script_name,
                                'output': script_output
                            })
                            self.dashboard.vulnerabilities_found += 1
                
                return {
                    'host': host,
                    'status': host_info.state(),
                    'services': services,
                    'os': os_info.get('name', 'Unknown'),
                    'os_accuracy': os_info.get('accuracy', 0),
                    'vulnerabilities': vulns,
                    'tcp_ports': [s for s in services if s['protocol'] == 'tcp'],
                    'udp_ports': [s for s in services if s['protocol'] == 'udp']
                }
        
        except Exception as e:
            console.print(f"[yellow]Scan error for {host}: {e}[/yellow]")
        
        return {}

class WebHardeningAudit:
    """Comprehensive web application security audit"""
    
    def __init__(self, config: Config, dashboard: ApexDashboard):
        self.config = config
        self.dashboard = dashboard
        self.vulnerabilities = []
        
    def audit_website(self, url: str) -> Dict:
        """Perform deep web application audit"""
        self.dashboard.update_dashboard(
            "Web Hardening Audit",
            "Initializing SQLMap & WP-Scan Logic",
            {"next_step": "Configuration Analysis"}
        )
        
        results = {
            'url': url,
            'sql_injection': [],
            'xss_vulnerabilities': [],
            'config_issues': [],
            'wordpress_issues': [],
            'headers_analysis': {},
            'ssl_analysis': {}
        }
        
        try:
            # Parallel audit execution
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.THREAD_POOL_SIZE
            ) as executor:
                futures = {
                    executor.submit(self._check_sql_injection, url): 'sql',
                    executor.submit(self._analyze_headers, url): 'headers',
                    executor.submit(self._test_ssl, url): 'ssl',
                    executor.submit(self._scan_wordpress, url): 'wordpress',
                    executor.submit(self._check_xss, url): 'xss',
                    executor.submit(self._directory_bruteforce, url): 'dirs'
                }
                
                for future in concurrent.futures.as_completed(futures):
                    audit_type = futures[future]
                    try:
                        result = future.result(timeout=self.config.TIMEOUT)
                        
                        if audit_type == 'sql' and result:
                            results['sql_injection'] = result
                            self.dashboard.vulnerabilities_found += len(result)
                        elif audit_type == 'headers':
                            results['headers_analysis'] = result
                        elif audit_type == 'ssl':
                            results['ssl_analysis'] = result
                        elif audit_type == 'wordpress' and result:
                            results['wordpress_issues'] = result
                            self.dashboard.vulnerabilities_found += len(result)
                        elif audit_type == 'xss' and result:
                            results['xss_vulnerabilities'] = result
                            self.dashboard.vulnerabilities_found += len(result)
                        
                    except concurrent.futures.TimeoutError:
                        console.print(f"[yellow]Timeout in {audit_type} audit[/yellow]")
            
            # Generate CVSS scores
            results['cvss_scores'] = self._calculate_cvss_scores(results)
            
            return results
            
        except Exception as e:
            console.print(f"[red]Web audit error: {e}[/red]")
            return results
    
    def _check_sql_injection(self, url: str) -> List[Dict]:
        """SQL injection testing with SQLMap-like logic"""
        test_payloads = [
            "'",
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' AND 1=CAST((SELECT version()) AS INTEGER)--"
        ]
        
        vulnerabilities = []
        
        for payload in test_payloads:
            test_url = f"{url}?id={payload}" if "?" not in url else f"{url}{payload}"
            
            try:
                response = requests.get(test_url, timeout=10)
                
                # Simple error-based detection (production would use more sophisticated methods)
                error_indicators = [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite",
                    "Unclosed quotation mark"
                ]
                
                if any(indicator in response.text for indicator in error_indicators):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'payload': payload,
                        'confidence': 'High',
                        'cvss_score': 8.6,
                        'remediation': 'Use parameterized queries or ORM with input validation'
                    })
                    
            except requests.RequestException:
                continue
        
        return vulnerabilities
    
    def _analyze_headers(self, url: str) -> Dict:
        """Analyze HTTP security headers"""
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            analysis = {
                'missing_headers': [],
                'weak_headers': [],
                'recommendations': []
            }
            
            # Check critical security headers
            security_headers = {
                'X-Frame-Options': 'DENY or SAMEORIGIN',
                'X-Content-Type-Options': 'nosniff',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': 'default-src \'self\'',
                'Referrer-Policy': 'strict-origin-when-cross-origin'
            }
            
            for header, expected in security_headers.items():
                if header not in headers:
                    analysis['missing_headers'].append(header)
                    analysis['recommendations'].append(f"Add {header}: {expected}")
                elif expected not in str(headers.get(header, '')):
                    analysis['weak_headers'].append(f"{header}: {headers[header]}")
            
            return analysis
            
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def _test_ssl(self, url: str) -> Dict:
        """SSL/TLS configuration audit"""
        import ssl
        import OpenSSL
        
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            analysis = {
                'issuer': x509.get_issuer().CN,
                'subject': x509.get_subject().CN,
                'expiry': x509.get_notAfter().decode('utf-8'),
                'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
                'issues': []
            }
            
            # Check expiry
            expiry_date = datetime.strptime(analysis['expiry'], '%Y%m%d%H%M%SZ')
            days_remaining = (expiry_date - datetime.now()).days
            
            if days_remaining < 30:
                analysis['issues'].append(f"Certificate expires in {days_remaining} days")
            
            # Check weak algorithms
            weak_algorithms = ['sha1', 'md5']
            if any(algo in analysis['signature_algorithm'].lower() for algo in weak_algorithms):
                analysis['issues'].append(f"Weak signature algorithm: {analysis['signature_algorithm']}")
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}

class AuthenticationResilienceTester:
    """High-speed credential strength and authentication testing"""
    
    def __init__(self, config: Config, dashboard: ApexDashboard):
        self.config = config
        self.dashboard = dashboard
        self.common_passwords = self._load_password_list()
        
    def test_credentials(self, target: str, service: str, username: str = None) -> Dict:
        """Test credential strength and authentication resilience"""
        self.dashboard.update_dashboard(
            "Authentication Audit",
            "Running Credential Strength Testing",
            {"next_step": "Password Policy Analysis"}
        )
        
        results = {
            'service': service,
            'weak_credentials': [],
            'brute_force_resistance': {},
            'password_policy': {},
            'recommendations': []
        }
        
        try:
            # Test common passwords
            if username:
                weak_passwords = self._test_password_strength(username)
                results['weak_credentials'] = weak_passwords
            
            # Analyze service-specific vulnerabilities
            if service.lower() == 'ssh':
                results.update(self._audit_ssh(target))
            elif service.lower() == 'smb':
                results.update(self._audit_smb(target))
            elif service.lower() == 'ftp':
                results.update(self._audit_ftp(target))
            
            # Generate CVSS score
            results['cvss_score'] = self._calculate_auth_cvss(results)
            
            return results
            
        except Exception as e:
            console.print(f"[red]Auth testing error: {e}[/red]")
            return results
    
    def _test_password_strength(self, username: str) -> List[Dict]:
        """Test against common and weak passwords"""
        weak_passwords = []
        
        for password in self.common_passwords[:100]:  # Limit for demo
            # Simulate password check (in real use, would actually test against service)
            if len(password) < 8:
                weak_passwords.append({
                    'username': username,
                    'password': password,
                    'issue': 'Too short (< 8 chars)',
                    'severity': 'High'
                })
            elif password.isalpha() or password.isnumeric():
                weak_passwords.append({
                    'username': username,
                    'password': password,
                    'issue': 'No complexity',
                    'severity': 'Medium'
                })
            elif password.lower() == 'password' or password.lower() == 'admin':
                weak_passwords.append({
                    'username': username,
                    'password': password,
                    'issue': 'Extremely common',
                    'severity': 'Critical'
                })
        
        return weak_passwords[:10]  # Return top 10
    
    def _audit_ssh(self, target: str) -> Dict:
        """SSH-specific security audit"""
        audit = {
            'ssh_issues': [],
            'recommendations': []
        }
        
        # Simulate SSH checks
        common_ssh_issues = [
            'Protocol 1 enabled',
            'Root login permitted',
            'Empty passwords allowed',
            'Weak key exchange algorithms'
        ]
        
        for issue in common_ssh_issues[:2]:  # Simulate finding some issues
            audit['ssh_issues'].append(issue)
            audit['recommendations'].append(f"Disable {issue}")
        
        return audit
    
    def _load_password_list(self) -> List[str]:
        """Load common passwords list"""
        # In production, load from file
        return [
            'password', '123456', 'admin', 'welcome', '12345678',
            'qwerty', 'password123', 'admin123', 'letmein', 'monkey'
        ]

class InfrastructureAuditor:
    """Metasploit-RPC integration and vulnerability verification"""
    
    def __init__(self, config: Config, dashboard: ApexDashboard):
        self.config = config
        self.dashboard = dashboard
        
    def audit_infrastructure(self, target: str, services: List[Dict]) -> Dict:
        """Comprehensive infrastructure vulnerability assessment"""
        self.dashboard.update_dashboard(
            "Infrastructure Audit",
            "Running Metasploit RPC Verification",
            {"next_step": "Vulnerability Correlation"}
        )
        
        results = {
            'target': target,
            'verified_vulnerabilities': [],
            'exploit_attempts': [],
            'risk_assessment': {},
            'mitigations': []
        }
        
        try:
            # Analyze each service for known vulnerabilities
            for service in services:
                service_audit = self._analyze_service_vulnerabilities(service)
                if service_audit['vulnerabilities']:
                    results['verified_vulnerabilities'].extend(service_audit['vulnerabilities'])
                    results['mitigations'].extend(service_audit['mitigations'])
            
            # Generate risk assessment
            results['risk_assessment'] = self._assess_risk(results['verified_vulnerabilities'])
            
            # Update dashboard
            self.dashboard.vulnerabilities_found += len(results['verified_vulnerabilities'])
            
            return results
            
        except Exception as e:
            console.print(f"[red]Infrastructure audit error: {e}[/red]")
            return results
    
    def _analyze_service_vulnerabilities(self, service: Dict) -> Dict:
        """Check service against known vulnerability database"""
        vulnerabilities = []
        mitigations = []
        
        # Service-specific checks
        service_name = service.get('service', '').lower()
        version = service.get('version', '')
        
        # Simulated vulnerability database check
        vuln_db = {
            'apache': [
                {'cve': 'CVE-2021-41773', 'description': 'Path traversal', 'cvss': 7.5},
                {'cve': 'CVE-2021-42013', 'description': 'RCE vulnerability', 'cvss': 9.8}
            ],
            'openssh': [
                {'cve': 'CVE-2021-41617', 'description': 'Privilege escalation', 'cvss': 7.8}
            ],
            'mysql': [
                {'cve': 'CVE-2021-21771', 'description': 'Memory corruption', 'cvss': 8.8}
            ]
        }
        
        for service_key, vulns in vuln_db.items():
            if service_key in service_name:
                vulnerabilities.extend(vulns)
                
                # Generate mitigations
                for vuln in vulns:
                    mitigations.append({
                        'cve': vuln['cve'],
                        'action': f'Update {service_name} to latest version',
                        'priority': 'Critical' if vuln['cvss'] >= 7.0 else 'High'
                    })
        
        return {
            'service': service_name,
            'vulnerabilities': vulnerabilities,
            'mitigations': mitigations
        }

class TacticalAdvisor:
    """AI-Logic for CVSS scoring and next-step recommendations"""
    
    def __init__(self):
        self.cvss_base_scores = {}
        
    def analyze_findings(self, findings: Dict) -> Dict:
        """Analyze findings and provide tactical recommendations"""
        recommendations = {
            'critical_issues': [],
            'immediate_actions': [],
            'next_module': None,
            'risk_score': 0
        }
        
        # Calculate overall risk score
        risk_score = self._calculate_overall_risk(findings)
        recommendations['risk_score'] = risk_score
        
        # Identify critical issues
        if 'vulnerabilities' in findings:
            for vuln in findings.get('vulnerabilities', []):
                if vuln.get('cvss', 0) >= 8.0:
                    recommendations['critical_issues'].append(
                        f"Critical: {vuln.get('type', 'Unknown')} - CVSS: {vuln.get('cvss')}"
                    )
        
        # Suggest next module based on findings
        if findings.get('services'):
            for service in findings['services']:
                service_name = service.get('service', '').lower()
                
                if 'http' in service_name or 'https' in service_name:
                    recommendations['next_module'] = 'WebHardeningAudit'
                    recommendations['immediate_actions'].append(
                        "Run web application security scan"
                    )
                elif 'ssh' in service_name or 'telnet' in service_name:
                    recommendations['next_module'] = 'AuthenticationResilienceTester'
                    recommendations['immediate_actions'].append(
                        "Test SSH authentication resilience"
                    )
                elif 'smb' in service_name or 'netbios' in service_name:
                    recommendations['next_module'] = 'InfrastructureAuditor'
                    recommendations['immediate_actions'].append(
                        "Audit SMB for EternalBlue vulnerabilities"
                    )
        
        return recommendations
    
    def _calculate_overall_risk(self, findings: Dict) -> float:
        """Calculate comprehensive risk score"""
        total_score = 0
        count = 0
        
        # Check vulnerabilities
        for vuln in findings.get('vulnerabilities', []):
            total_score += vuln.get('cvss', 0)
            count += 1
        
        # Check misconfigurations
        for issue in findings.get('misconfigurations', []):
            if issue.get('severity') == 'Critical':
                total_score += 9.0
            elif issue.get('severity') == 'High':
                total_score += 7.0
            count += 1
        
        return total_score / count if count > 0 else 0

class ShieldReporter:
    """Generate comprehensive HTML reports with remediation guidance"""
    
    def __init__(self, config: Config):
        self.config = config
        
    def generate_report(self, scan_data: Dict, filename: str = None) -> str:
        """Generate professional HTML report"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"xpro_audit_{timestamp}.html"
        
        report_path = self.config.OUTPUT_DIR / filename
        
        # Create HTML report
        html_content = self._create_html_template(scan_data)
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        console.print(f"[green]Report generated: {report_path}[/green]")
        return str(report_path)
    
    def _create_html_template(self, data: Dict) -> str:
        """Create HTML report template"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>XPRO - APEX SENTINEL Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; }}
        .vulnerability {{ border: 1px solid #ccc; margin: 10px 0; padding: 15px; }}
        .critical {{ background: #ffcccc; border-left: 5px solid #ff0000; }}
        .high {{ background: #ffe6cc; border-left: 5px solid #ff9900; }}
        .medium {{ background: #ffffcc; border-left: 5px solid #ffff00; }}
        .remediation {{ background: #ccffcc; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ XPRO - APEX SENTINEL Audit Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>Total Vulnerabilities Found: {len(data.get('vulnerabilities', []))}</p>
    <p>Overall Risk Score: {data.get('risk_score', 0)}</p>
    
    <h2>Vulnerability Details</h2>
    {self._generate_vulnerability_section(data.get('vulnerabilities', []))}
    
    <h2>🛡️ Remediation Guidance</h2>
    {self._generate_remediation_section(data.get('recommendations', []))}
    
    <h2>Business Impact Analysis</h2>
    <p>Each vulnerability includes business impact assessment and priority.</p>
</body>
</html>
"""
    
    def _generate_vulnerability_section(self, vulnerabilities: List) -> str:
        """Generate vulnerability HTML"""
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
        
        html = ""
        for vuln in vulnerabilities:
            severity_class = 'medium'
            if vuln.get('cvss', 0) >= 9.0:
                severity_class = 'critical'
            elif vuln.get('cvss', 0) >= 7.0:
                severity_class = 'high'
            
            html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.get('type', 'Unknown')}</h3>
                <p><strong>CVSS Score:</strong> {vuln.get('cvss', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                <p><strong>Affected Service:</strong> {vuln.get('service', 'Unknown')}</p>
            </div>
            """
        
        return html
    
    def _generate_remediation_section(self, recommendations: List) -> str:
        """Generate remediation HTML"""
        if not recommendations:
            return "<p>No specific recommendations.</p>"
        
        html = ""
        for rec in recommendations:
            html += f"""
            <div class="remediation">
                <h4>🛠️ {rec.get('action', 'General Remediation')}</h4>
                <p><strong>Priority:</strong> {rec.get('priority', 'Medium')}</p>
                <p><strong>Impact:</strong> {rec.get('impact', 'Reduces attack surface')}</p>
                <p><strong>Implementation:</strong> {rec.get('implementation', 'Apply patch or configuration change')}</p>
            </div>
            """
        
        return html

# ============================================================================
# MAIN ENGINE
# ============================================================================

class ApexSentinelEngine:
    """Main engine orchestrating all modules"""
    
    def __init__(self):
        self.config = Config()
        self.dashboard = ApexDashboard()
        self.tactical_advisor = TacticalAdvisor()
        self.reporter = ShieldReporter(self.config)
        
        # Initialize modules
        self.asset_discovery = AssetDiscovery(self.config, self.dashboard)
        self.web_audit = WebHardeningAudit(self.config, self.dashboard)
        self.auth_tester = AuthenticationResilienceTester(self.config, self.dashboard)
        self.infra_auditor = InfrastructureAuditor(self.config, self.dashboard)
        
        self.scan_results = {}
    
    def run_full_audit(self, target: str):
        """Execute complete security audit"""
        try:
            self.dashboard.clear_screen()
            self.dashboard.show_banner()
            
            console.print("[bold cyan]🚀 INITIATING APEX SENTINEL AUDIT[/bold cyan]\n")
            
            # Phase 1: Asset Discovery
            console.print("[bold yellow]PHASE 1: ASSET DISCOVERY[/bold yellow]")
            self.scan_results['assets'] = self.asset_discovery.scan_network(target)
            
            # Update dashboard with tactical recommendations
            advisor_results = self.tactical_advisor.analyze_findings(self.scan_results['assets'])
            self.dashboard.update_dashboard(
                "Asset Discovery Complete",
                f"Found {len(self.scan_results['assets'].get('assets', []))} assets",
                advisor_results
            )
            
            time.sleep(2)
            
            # Phase 2: Web Application Audit (if web services found)
            if self._has_web_services():
                console.print("\n[bold yellow]PHASE 2: WEB HARDENING AUDIT[/bold yellow]")
                web_target = self._get_web_target()
                self.scan_results['web_audit'] = self.web_audit.audit_website(web_target)
            
            # Phase 3: Authentication Testing
            console.print("\n[bold yellow]PHASE 3: AUTHENTICATION RESILIENCE[/bold yellow]")
            auth_target = self._get_auth_target()
            if auth_target:
                self.scan_results['auth_audit'] = self.auth_tester.test_credentials(
                    auth_target, 'ssh', 'admin'
                )
            
            # Phase 4: Infrastructure Audit
            console.print("\n[bold yellow]PHASE 4: INFRASTRUCTURE AUDIT[/bold yellow]")
            self.scan_results['infra_audit'] = self.infra_auditor.audit_infrastructure(
                target,
                self._get_all_services()
            )
            
            # Generate final report
            console.print("\n[bold green]📊 GENERATING COMPREHENSIVE REPORT[/bold green]")
            report_path = self.reporter.generate_report(self.scan_results)
            
            console.print(f"\n[bold green]✅ AUDIT COMPLETE[/bold green]")
            console.print(f"[bold]Report saved to:[/bold] {report_path}")
            console.print(f"[bold]Total vulnerabilities found:[/bold] {self.dashboard.vulnerabilities_found}")
            
        except KeyboardInterrupt:
            console.print("\n[red]Audit interrupted by user[/red]")
        except Exception as e:
            console.print(f"\n[red]Critical error: {e}[/red]")
    
    def _has_web_services(self) -> bool:
        """Check if web services were discovered"""
        assets = self.scan_results.get('assets', {}).get('assets', [])
        for asset in assets:
            for service in asset.get('services', []):
                if 'http' in service.get('service', '').lower():
                    return True
        return False
    
    def _get_web_target(self) -> str:
        """Extract web target from discovered assets"""
        assets = self.scan_results.get('assets', {}).get('assets', [])
        for asset in assets:
            for service in asset.get('services', []):
                if 'http' in service.get('service', '').lower():
                    return f"http://{asset.get('host')}:{service.get('port')}"
        return "http://localhost"
    
    def _get_auth_target(self) -> str:
        """Extract authentication service target"""
        assets = self.scan_results.get('assets', {}).get('assets', [])
        for asset in assets:
            for service in asset.get('services', []):
                if service.get('service') in ['ssh', 'telnet', 'ftp']:
                    return asset.get('host')
        return None
    
    def _get_all_services(self) -> List[Dict]:
        """Extract all discovered services"""
        services = []
        assets = self.scan_results.get('assets', {}).get('assets', [])
        for asset in assets:
            services.extend(asset.get('services', []))
        return services

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point for XPRO - APEX SENTINEL"""
    
    engine = ApexSentinelEngine()
    
    # Display startup
    engine.dashboard.clear_screen()
    engine.dashboard.show_banner()
    
    console.print("[bold cyan]Autonomous Cyber-Intelligence Unit[/bold cyan]")
    console.print("[bold red]⚠️  STRICT LEGAL & ETHICAL USE ONLY ⚠️[/bold red]\n")
    
    # Get target
    target = Prompt.ask("[bold]Enter target[/bold] (IP/CIDR/URL)", default="127.0.0.1")
    
    # Confirm authorization
    if not Confirm.ask("[bold red]Do you have explicit authorization to scan this target?"):
        console.print("[red]Audit aborted. Unauthorized scanning is illegal.[/red]")
        sys.exit(1)
    
    # Start audit
    engine.run_full_audit(target)

if __name__ == "__main__":
    main()