#!/usr/bin/env python3
"""
XPRO - APEX SENTINEL v2.0
Autonomous Cyber-Intelligence Unit
GitHub: https://github.com/Irfan430/XPRO
Ultimate Security Auditing Framework for Kali Linux
"""

import os
import sys
import json
import time
import socket
import ssl
import asyncio
import threading
import subprocess
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from queue import Queue
import warnings
warnings.filterwarnings('ignore')

# Core Imports
import psutil
import pandas as pd
import numpy as np

# Rich UI for cinematic experience
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.columns import Columns
from rich.text import Text
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.markdown import Markdown
import pyfiglet
from colorama import init, Fore, Style

# Security Tool Integrations
import nmap
import scapy.all as scapy
import requests
from bs4 import BeautifulSoup
import dns.resolver

# Initialize
init(autoreset=True)
console = Console()

# ============================================================================
# CONFIGURATION ENGINE
# ============================================================================

@dataclass
class XPROConfig:
    """Auto-configured settings based on system resources"""
    
    # System Detection
    SYSTEM_RAM: float = field(init=False)
    CPU_CORES: int = field(init=False)
    OS_TYPE: str = field(init=False)
    
    # Performance Settings
    THREAD_POOL_SIZE: int = field(init=False)
    MAX_WORKERS: int = 50
    TIMEOUT: int = 30
    NMAP_TIMING: int = 4
    
    # Paths
    HOME_DIR: Path = Path.home()
    XPRO_DIR: Path = HOME_DIR / ".xpro"
    REPORT_DIR: Path = HOME_DIR / "XPRO_REPORTS"
    LOG_DIR: Path = XPRO_DIR / "logs"
    TOOL_DIR: Path = XPRO_DIR / "tools"
    
    # Risk Thresholds
    CRITICAL_CVSS: float = 9.0
    HIGH_CVSS: float = 7.0
    MEDIUM_CVSS: float = 4.0
    
    def __post_init__(self):
        """Auto-detect and configure system settings"""
        # Detect system specs
        self.SYSTEM_RAM = psutil.virtual_memory().total / (1024**3)  # GB
        self.CPU_CORES = psutil.cpu_count(logical=True)
        self.OS_TYPE = self._detect_os()
        
        # Auto-scale thread pool based on RAM
        if self.SYSTEM_RAM >= 16:
            self.THREAD_POOL_SIZE = min(self.CPU_CORES * 4, 64)
        elif self.SYSTEM_RAM >= 8:
            self.THREAD_POOL_SIZE = min(self.CPU_CORES * 2, 32)
        else:
            self.THREAD_POOL_SIZE = min(self.CPU_CORES, 16)
        
        # Create directories
        for directory in [self.XPRO_DIR, self.REPORT_DIR, self.LOG_DIR, self.TOOL_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Save config
        self._save_config()
    
    def _detect_os(self) -> str:
        """Detect operating system"""
        if os.path.exists("/etc/kali-release"):
            return "kali"
        elif os.path.exists("/etc/arch-release"):
            return "arch"
        elif sys.platform == "win32":
            return "windows"
        else:
            return "linux"
    
    def _save_config(self):
        """Save configuration to file"""
        config_data = {
            "system_ram_gb": self.SYSTEM_RAM,
            "cpu_cores": self.CPU_CORES,
            "os_type": self.OS_TYPE,
            "thread_pool": self.THREAD_POOL_SIZE,
            "config_date": datetime.now().isoformat()
        }
        
        config_file = self.XPRO_DIR / "config.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=4)
    
    def check_tools(self) -> Dict[str, bool]:
        """Check if required tools are installed"""
        tools = {
            "nmap": False, "sqlmap": False, "hydra": False, "john": False,
            "nikto": False, "dirb": False, "gobuster": False, "whatweb": False,
            "sslscan": False, "nuclei": False, "ffuf": False, "amass": False,
            "masscan": False, "metasploit": False, "skipfish": False
        }
        
        for tool in tools.keys():
            try:
                if tool == "metasploit":
                    # Special check for Metasploit
                    tools[tool] = os.path.exists("/usr/bin/msfconsole") or os.path.exists("/opt/metasploit-framework/bin/msfconsole")
                else:
                    result = subprocess.run(["which", tool], capture_output=True, text=True)
                    tools[tool] = result.returncode == 0
            except:
                tools[tool] = False
        
        return tools

# ============================================================================
# CINEMATIC DASHBOARD
# ============================================================================

class XPRODashboard:
    """Advanced Rich-based dashboard with real-time monitoring"""
    
    def __init__(self, config: XPROConfig):
        self.config = config
        self.console = Console()
        self.start_time = datetime.now()
        
        # Metrics
        self.scan_progress = 0
        self.active_threads = 0
        self.vulnerabilities = 0
        self.services = 0
        self.hosts = 0
        self.current_module = "Initializing"
        self.current_status = "Ready"
        
        # Color schemes
        self.colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "cyan",
            "low": "green",
            "info": "blue"
        }
    
    def clear(self):
        """Clear terminal with style"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def show_banner(self):
        """Display XPRO banner"""
        self.clear()
        banner = pyfiglet.figlet_format("XPRO SENTINEL", font="slant")
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="center")
        
        grid.add_row(f"[bold cyan]{banner}[/bold cyan]")
        grid.add_row(f"[bold yellow]Version 2.0 | GitHub: https://github.com/Irfan430/XPRO[/bold yellow]")
        grid.add_row(f"[bold green]RAM: {self.config.SYSTEM_RAM:.1f}GB | Cores: {self.config.CPU_CORES} | Threads: {self.config.THREAD_POOL_SIZE}[/bold green]")
        grid.add_row("")
        
        self.console.print(grid)
        self.console.print("[bold red]⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️[/bold red]\n")
    
    def update_dashboard(self, module: str, status: str, findings: Dict = None):
        """Update dashboard display"""
        self.current_module = module
        self.current_status = status
        
        # Calculate elapsed time
        elapsed = datetime.now() - self.start_time
        elapsed_str = str(elapsed).split('.')[0]
        
        # Create main display
        main_table = Table(show_header=True, header_style="bold magenta", expand=True)
        main_table.add_column("METRIC", width=20)
        main_table.add_column("VALUE", width=30)
        main_table.add_column("STATUS", width=25)
        
        main_table.add_row("Active Module", module, f"[green]{status}[/green]")
        main_table.add_row("Elapsed Time", elapsed_str, "")
        main_table.add_row("Threads Active", str(self.active_threads), 
                          f"[{'green' if self.active_threads < self.config.THREAD_POOL_SIZE else 'yellow'}]{self.active_threads}/{self.config.THREAD_POOL_SIZE}[/]")
        main_table.add_row("Vulnerabilities", str(self.vulnerabilities), 
                          f"[{'red' if self.vulnerabilities > 0 else 'green'}]{self.vulnerabilities} found[/]")
        main_table.add_row("Services Found", str(self.services), "")
        main_table.add_row("Hosts Discovered", str(self.hosts), "")
        
        # Create panels
        left_panel = Panel(
            main_table,
            title="[bold]XPRO CONTROL PANEL[/bold]",
            border_style="cyan",
            padding=(1, 2)
        )
        
        # Right panel with findings
        right_content = ""
        if findings:
            if "critical" in findings:
                right_content += "[bold red]🚨 CRITICAL FINDINGS:[/bold red]\n"
                for item in findings["critical"][:3]:
                    right_content += f"• {item}\n"
                right_content += "\n"
            
            if "recommendations" in findings:
                right_content += "[bold green]🛡️ RECOMMENDATIONS:[/bold green]\n"
                for item in findings["recommendations"][:3]:
                    right_content += f"• {item}\n"
        
        right_panel = Panel(
            right_content or "[yellow]No findings yet...[/yellow]",
            title="[bold]TACTICAL ADVISOR[/bold]",
            border_style="yellow",
            padding=(1, 2)
        )
        
        # Display
        self.clear()
        self.show_banner()
        
        columns = Columns([left_panel, right_panel])
        self.console.print(columns)
        self.console.print("\n")
    
    def show_progress(self, task: str, current: int, total: int):
        """Show progress bar"""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        )
        
        with progress:
            task_id = progress.add_task(f"[cyan]{task}", total=total)
            progress.update(task_id, completed=current)
            self.scan_progress = int((current / total) * 100) if total > 0 else 0

# ============================================================================
# INTELLIGENT SCANNING ENGINE
# ============================================================================

class XPROScanner:
    """High-performance scanning engine with auto-scaling"""
    
    def __init__(self, config: XPROConfig, dashboard: XPRODashboard):
        self.config = config
        self.dashboard = dashboard
        self.nm = nmap.PortScanner()
        self.results = {}
        self.lock = threading.Lock()
        
    def network_discovery(self, target: str) -> Dict:
        """Perform comprehensive network discovery"""
        self.dashboard.update_dashboard(
            "Network Discovery",
            "Starting aggressive scan...",
            {"recommendations": ["Initial ping sweep", "OS fingerprinting"]}
        )
        
        try:
            # Phase 1: Fast ping sweep
            alive_hosts = self._fast_ping_sweep(target)
            self.dashboard.hosts = len(alive_hosts)
            
            if not alive_hosts:
                return {"error": "No hosts alive"}
            
            # Phase 2: Parallel port scanning
            self.dashboard.update_dashboard(
                "Port Scanning",
                f"Scanning {len(alive_hosts)} hosts...",
                {"critical": ["Running on all threads"]}
            )
            
            scan_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.THREAD_POOL_SIZE) as executor:
                future_to_host = {
                    executor.submit(self._deep_scan_host, host): host 
                    for host in alive_hosts[:50]  # Limit for performance
                }
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result(timeout=self.config.TIMEOUT)
                        if result:
                            scan_results.append(result)
                            with self.lock:
                                self.dashboard.services += len(result.get('services', []))
                    except Exception as e:
                        self.console.print(f"[yellow]Scan failed for {host}: {e}[/yellow]")
                    
                    completed += 1
                    self.dashboard.show_progress("Host Scanning", completed, len(future_to_host))
            
            # Phase 3: Vulnerability detection
            vuln_results = self._detect_vulnerabilities(scan_results)
            
            return {
                "total_hosts": len(alive_hosts),
                "scanned_hosts": len(scan_results),
                "alive_hosts": alive_hosts,
                "scan_results": scan_results,
                "vulnerabilities": vuln_results,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.console.print(f"[red]Network discovery error: {e}[/red]")
            return {"error": str(e)}
    
    def _fast_ping_sweep(self, target: str) -> List[str]:
        """Ultra-fast ICMP ping sweep"""
        alive_hosts = []
        
        try:
            # Use system ping for speed
            if "/" in target:
                # CIDR notation
                cmd = ["nmap", "-sn", target, "-oG", "-"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                for line in result.stdout.split('\n'):
                    if "Host:" in line and "Up" in line:
                        parts = line.split()
                        if len(parts) > 1:
                            alive_hosts.append(parts[1])
            else:
                # Single host
                alive_hosts.append(target)
                
        except:
            # Fallback to traditional method
            try:
                ans, unans = scapy.srp(
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(dst=target)/scapy.ICMP(),
                    timeout=2,
                    verbose=0
                )
                alive_hosts = [received[scapy.IP].src for sent, received in ans]
            except:
                alive_hosts = [target]
        
        return alive_hosts
    
    def _deep_scan_host(self, host: str) -> Dict:
        """Deep scan single host with multiple techniques"""
        host_result = {
            "host": host,
            "status": "unknown",
            "services": [],
            "os": "Unknown",
            "vulnerabilities": []
        }
        
        try:
            # Aggressive NMAP scan
            self.nm.scan(
                hosts=host,
                arguments=f'-sS -sV -sC -O -A -T{self.config.NMAP_TIMING} --script vuln,discovery,auth'
            )
            
            if host in self.nm.all_hosts():
                host_info = self.nm[host]
                host_result["status"] = host_info.state()
                
                # Extract services
                for proto in host_info.all_protocols():
                    ports = host_info[proto].keys()
                    for port in ports:
                        service = host_info[proto][port]
                        service_info = {
                            'port': port,
                            'protocol': proto,
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extra': service.get('extrainfo', ''),
                            'cpe': service.get('cpe', '')
                        }
                        host_result["services"].append(service_info)
                
                # OS detection
                if 'osmatch' in host_info and host_info['osmatch']:
                    host_result["os"] = host_info['osmatch'][0].get('name', 'Unknown')
                    host_result["os_accuracy"] = host_info['osmatch'][0].get('accuracy', 0)
                
                # Extract vulnerabilities from scripts
                if 'script' in host_info:
                    for script, output in host_info['script'].items():
                        if any(vuln in script.lower() for vuln in ['vuln', 'exploit', 'cve']):
                            host_result["vulnerabilities"].append({
                                'type': 'nmap_script',
                                'script': script,
                                'output': str(output)[:500],
                                'cvss': self._estimate_cvss_from_nmap(script)
                            })
                
                # Update dashboard
                with self.lock:
                    self.dashboard.vulnerabilities += len(host_result["vulnerabilities"])
        
        except Exception as e:
            host_result["error"] = str(e)
        
        return host_result
    
    def _detect_vulnerabilities(self, scan_results: List[Dict]) -> List[Dict]:
        """Detect vulnerabilities from scan results"""
        vulnerabilities = []
        
        for host in scan_results:
            for service in host.get('services', []):
                # Check for common vulnerable services
                vuln_check = self._check_service_vulnerability(service)
                if vuln_check:
                    vuln_check.update({
                        'host': host['host'],
                        'port': service['port']
                    })
                    vulnerabilities.append(vuln_check)
        
        return vulnerabilities
    
    def _check_service_vulnerability(self, service: Dict) -> Optional[Dict]:
        """Check if service has known vulnerabilities"""
        service_name = service.get('name', '').lower()
        product = service.get('product', '').lower()
        version = service.get('version', '')
        
        # Common vulnerability checks
        vuln_patterns = {
            'ftp': {'check': lambda: 'anonymous' in service.get('extra', '').lower(),
                   'type': 'FTP Anonymous Access',
                   'cvss': 5.3,
                   'remediation': 'Disable anonymous FTP access'},
            
            'ssh': {'check': lambda: any(x in service.get('extra', '').lower() 
                                        for x in ['weak', 'old', 'vulnerable']),
                   'type': 'SSH Weak Configuration',
                   'cvss': 7.5,
                   'remediation': 'Update SSH configuration'},
            
            'http': {'check': lambda: any(x in service.get('product', '').lower() 
                                         for x in ['apache', 'nginx', 'iis']) and
                                     any(x in version for x in ['1.', '2.0', '2.2']),
                   'type': 'Web Server Version Vulnerability',
                   'cvss': 8.0,
                   'remediation': 'Update web server to latest version'},
            
            'microsoft-ds': {'check': lambda: 'SMB' in service.get('product', ''),
                           'type': 'SMB Protocol Vulnerability',
                           'cvss': 8.8,
                           'remediation': 'Apply SMB security patches'},
            
            'mysql': {'check': lambda: version and version.startswith('5.'),
                     'type': 'MySQL Old Version',
                     'cvss': 7.2,
                     'remediation': 'Upgrade MySQL database'}
        }
        
        for pattern, vuln_info in vuln_patterns.items():
            if pattern in service_name or pattern in product:
                try:
                    if vuln_info['check']():
                        return {
                            'type': vuln_info['type'],
                            'cvss': vuln_info['cvss'],
                            'severity': 'Critical' if vuln_info['cvss'] >= 9.0 else 
                                       'High' if vuln_info['cvss'] >= 7.0 else 
                                       'Medium',
                            'remediation': vuln_info['remediation'],
                            'evidence': f"Service: {service_name} {product} {version}"
                        }
                except:
                    continue
        
        return None
    
    def _estimate_cvss_from_nmap(self, script: str) -> float:
        """Estimate CVSS score from NMAP script name"""
        script_lower = script.lower()
        
        if any(word in script_lower for word in ['critical', 'exploit', 'rce', 'remote']):
            return 9.0
        elif any(word in script_lower for word in ['vuln', 'vulnerability', 'cve']):
            return 7.5
        elif any(word in script_lower for word in ['weak', 'misconfig', 'info']):
            return 5.0
        else:
            return 3.0

# ============================================================================
# WEB APPLICATION AUDITOR
# ============================================================================

class WebAuditor:
    """Comprehensive web application security testing"""
    
    def __init__(self, config: XPROConfig, dashboard: XPRODashboard):
        self.config = config
        self.dashboard = dashboard
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def audit_website(self, url: str) -> Dict:
        """Perform complete web application audit"""
        self.dashboard.update_dashboard(
            "Web Application Audit",
            f"Auditing {url}",
            {"recommendations": ["Checking headers", "Testing for injections"]}
        )
        
        results = {
            'url': url,
            'security_headers': {},
            'vulnerabilities': [],
            'technologies': [],
            'directories': [],
            'ssl_info': {}
        }
        
        try:
            # Check if URL is accessible
            response = self.session.get(url, timeout=10, verify=False)
            results['status_code'] = response.status_code
            
            # 1. Security headers check
            results['security_headers'] = self._check_security_headers(response.headers)
            
            # 2. Technology detection
            results['technologies'] = self._detect_technologies(response)
            
            # 3. Run parallel tests
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.THREAD_POOL_SIZE) as executor:
                futures = []
                
                futures.append(executor.submit(self._test_sql_injection, url))
                futures.append(executor.submit(self._test_xss, url))
                futures.append(executor.submit(self._test_directory_traversal, url))
                futures.append(executor.submit(self._check_ssl, url))
                futures.append(executor.submit(self._find_directories, url))
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result(timeout=15)
                        if result:
                            if 'sql' in str(future):
                                results['vulnerabilities'].extend(result)
                            elif 'xss' in str(future):
                                results['vulnerabilities'].extend(result)
                            elif 'directory' in str(future):
                                results['directories'] = result
                            elif 'ssl' in str(future):
                                results['ssl_info'] = result
                    except Exception as e:
                        continue
            
            # Calculate risk score
            results['risk_score'] = self._calculate_web_risk(results)
            
            # Update dashboard
            self.dashboard.vulnerabilities += len(results['vulnerabilities'])
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def _check_security_headers(self, headers: Dict) -> Dict:
        """Check security headers"""
        analysis = {
            'missing': [],
            'weak': [],
            'good': []
        }
        
        security_headers = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'X-XSS-Protection': ['1; mode=block'],
            'Strict-Transport-Security': ['max-age='],
            'Content-Security-Policy': ['default-src', 'script-src'],
            'Referrer-Policy': ['no-referrer', 'strict-origin']
        }
        
        for header, expected_values in security_headers.items():
            if header in headers:
                header_value = headers[header]
                if any(expected in header_value for expected in expected_values):
                    analysis['good'].append(f"{header}: {header_value}")
                else:
                    analysis['weak'].append(f"{header}: {header_value}")
            else:
                analysis['missing'].append(header)
        
        return analysis
    
    def _detect_technologies(self, response) -> List[str]:
        """Detect web technologies"""
        tech = []
        
        # Check headers
        server = response.headers.get('Server', '')
        if server:
            tech.append(f"Server: {server}")
        
        # Check cookies
        cookies = response.headers.get('Set-Cookie', '')
        if 'PHPSESSID' in cookies:
            tech.append("PHP")
        if 'JSESSIONID' in cookies:
            tech.append("Java")
        if 'ASP.NET_SessionId' in cookies:
            tech.append("ASP.NET")
        
        # Check HTML for frameworks
        html = response.text[:5000]
        if 'wp-content' in html:
            tech.append("WordPress")
        if 'drupal' in html.lower():
            tech.append("Drupal")
        if 'jquery' in html.lower():
            tech.append("jQuery")
        if 'react' in html.lower():
            tech.append("React")
        if 'vue' in html.lower():
            tech.append("Vue.js")
        
        return tech
    
    def _test_sql_injection(self, url: str) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        test_payloads = [
            "'",
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND SLEEP(5)--"
        ]
        
        vulnerabilities = []
        
        for payload in test_payloads[:3]:  # Limit for demo
            test_url = f"{url}?id={payload}" if "?" not in url else f"{url}&test={payload}"
            
            try:
                start = time.time()
                response = self.session.get(test_url, timeout=10, verify=False)
                elapsed = time.time() - start
                
                # Time-based detection
                if elapsed > 4:
                    vulnerabilities.append({
                        'type': 'SQL Injection (Time-based)',
                        'payload': payload,
                        'cvss': 8.6,
                        'severity': 'High',
                        'remediation': 'Use parameterized queries with input validation'
                    })
                    continue
                
                # Error-based detection
                error_patterns = [
                    'sql syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                    'SQLite', 'unclosed quotation', 'syntax error'
                ]
                
                if any(pattern in response.text.lower() for pattern in error_patterns):
                    vulnerabilities.append({
                        'type': 'SQL Injection (Error-based)',
                        'payload': payload,
                        'cvss': 8.6,
                        'severity': 'High',
                        'remediation': 'Implement prepared statements and proper error handling'
                    })
                
            except:
                continue
        
        return vulnerabilities
    
    def _test_xss(self, url: str) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '" onmouseover="alert(1)"',
            'javascript:alert(1)'
        ]
        
        vulnerabilities = []
        
        for payload in payloads[:2]:  # Limit for demo
            test_url = f"{url}?q={payload}" if "?" not in url else f"{url}&xss={payload}"
            
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'payload': payload[:50],
                        'cvss': 6.1,
                        'severity': 'Medium',
                        'remediation': 'Implement output encoding and Content Security Policy'
                    })
                
            except:
                continue
        
        return vulnerabilities
    
    def _find_directories(self, url: str) -> List[str]:
        """Find common directories"""
        common_dirs = [
            'admin', 'login', 'wp-admin', 'administrator',
            'backup', 'config', 'db', 'sql',
            'test', 'debug', 'api', 'doc'
        ]
        
        found = []
        
        for directory in common_dirs[:10]:  # Limit for demo
            test_url = f"{url.rstrip('/')}/{directory}/"
            
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                if response.status_code < 400:
                    found.append(f"{directory} ({response.status_code})")
            except:
                continue
        
        return found
    
    def _check_ssl(self, url: str) -> Dict:
        """Check SSL/TLS configuration"""
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiry
                    not_after = cert['notAfter']
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.now()).days
                    
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                        'valid_until': not_after,
                        'days_left': days_left,
                        'protocol': ssock.version(),
                        'issues': [] if days_left > 30 else ['Certificate expiring soon']
                    }
        
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_web_risk(self, results: Dict) -> float:
        """Calculate overall web risk score"""
        score = 0
        factors = 0
        
        # Vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            score += vuln.get('cvss', 0)
            factors += 1
        
        # Missing headers
        missing = len(results.get('security_headers', {}).get('missing', []))
        score += missing * 2
        factors += missing
        
        # SSL issues
        if results.get('ssl_info', {}).get('issues'):
            score += 5
            factors += 1
        
        return round(score / max(factors, 1), 1)

# ============================================================================
# REPORTING ENGINE
# ============================================================================

class XPROReporter:
    """Professional reporting system with multiple formats"""
    
    def __init__(self, config: XPROConfig):
        self.config = config
        self.template_dir = self.config.XPRO_DIR / "templates"
        self.template_dir.mkdir(exist_ok=True)
        
        # Create default template
        self._create_default_template()
    
    def generate_report(self, scan_data: Dict, format: str = "html") -> str:
        """Generate comprehensive report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format.lower() == "html":
            return self._generate_html_report(scan_data, timestamp)
        elif format.lower() == "json":
            return self._generate_json_report(scan_data, timestamp)
        else:
            return self._generate_text_report(scan_data, timestamp)
    
    def _generate_html_report(self, data: Dict, timestamp: str) -> str:
        """Generate HTML report"""
        filename = f"xpro_report_{timestamp}.html"
        report_path = self.config.REPORT_DIR / filename
        
        # Prepare data
        vulnerabilities = data.get('vulnerabilities', [])
        services = data.get('services', [])
        hosts = data.get('hosts', [])
        
        # Calculate statistics
        stats = {
            'total_vulns': len(vulnerabilities),
            'critical_vulns': len([v for v in vulnerabilities if v.get('cvss', 0) >= 9.0]),
            'high_vulns': len([v for v in vulnerabilities if 7.0 <= v.get('cvss', 0) < 9.0]),
            'services_found': len(services),
            'hosts_scanned': len(hosts),
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Create HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XPRO Security Audit Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px 0; text-align: center; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .stat-card.critical {{ border-top: 4px solid #dc3545; }}
        .stat-card.high {{ border-top: 4px solid #fd7e14; }}
        .stat-card.medium {{ border-top: 4px solid #ffc107; }}
        .stat-card.info {{ border-top: 4px solid #17a2b8; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        
        .section {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }}
        .section-title {{ color: #1a1a2e; border-bottom: 2px solid #eaeaea; padding-bottom: 10px; margin-bottom: 20px; font-size: 1.5em; }}
        
        .vulnerability {{ border-left: 4px solid #dc3545; margin: 15px 0; padding: 15px; background: #fff5f5; }}
        .vulnerability.high {{ border-left-color: #fd7e14; background: #fff9f0; }}
        .vulnerability.medium {{ border-left-color: #ffc107; background: #fffef0; }}
        .vulnerability.low {{ border-left-color: #28a745; background: #f0fff4; }}
        
        .remediation {{ background: #e8f4fd; border-left: 4px solid #17a2b8; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #eaeaea; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
        .badge.critical {{ background: #dc3545; color: white; }}
        .badge.high {{ background: #fd7e14; color: white; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.low {{ background: #28a745; color: white; }}
        
        .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #666; font-size: 0.9em; border-top: 1px solid #eaeaea; }}
        
        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
            .container {{ padding: 10px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ XPRO Security Audit Report</h1>
            <div class="subtitle">Autonomous Cyber-Intelligence Unit | {stats['scan_date']}</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <div>Critical Vulnerabilities</div>
                <div class="stat-number">{stats['critical_vulns']}</div>
            </div>
            <div class="stat-card high">
                <div>High Vulnerabilities</div>
                <div class="stat-number">{stats['high_vulns']}</div>
            </div>
            <div class="stat-card">
                <div>Total Vulnerabilities</div>
                <div class="stat-number">{stats['total_vulns']}</div>
            </div>
            <div class="stat-card">
                <div>Services Found</div>
                <div class="stat-number">{stats['services_found']}</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <p>This security audit was conducted using XPRO - APEX SENTINEL v2.0. The scan discovered {stats['total_vulns']} security issues across {stats['hosts_scanned']} hosts.</p>
            
            <div class="remediation">
                <strong>🛡️ Immediate Actions Required:</strong>
                <ul style="margin-top: 10px; padding-left: 20px;">
                    <li>Address {stats['critical_vulns']} critical vulnerabilities within 24 hours</li>
                    <li>Review and patch all services with high-risk vulnerabilities</li>
                    <li>Implement recommended security controls</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Vulnerability Details</h2>
            """
        
        # Add vulnerabilities
        for i, vuln in enumerate(vulnerabilities[:20]):  # Limit for report
            severity = vuln.get('severity', 'medium').lower()
            html += f"""
            <div class="vulnerability {severity}">
                <h3>#{i+1}: {vuln.get('type', 'Unknown Vulnerability')}</h3>
                <p><strong>CVSS Score:</strong> <span class="badge {severity}">{vuln.get('cvss', 'N/A')}</span></p>
                <p><strong>Host:</strong> {vuln.get('host', 'Unknown')}:{vuln.get('port', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('evidence', 'No description available')}</p>
                <div class="remediation">
                    <strong>Remediation:</strong> {vuln.get('remediation', 'Apply security best practices')}
                </div>
            </div>
            """
        
        html += """
        </div>
        
        <div class="section">
            <h2 class="section-title">Scanned Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add services
        for service in services[:50]:  # Limit for report
            html += f"""
                <tr>
                    <td>{service.get('host', 'N/A')}</td>
                    <td>{service.get('port', 'N/A')}</td>
                    <td>{service.get('name', 'Unknown')}</td>
                    <td>{service.get('version', 'N/A')}</td>
                    <td><span class="badge {'critical' if 'vulnerable' in str(service).lower() else 'low'}">
                        {'Vulnerable' if 'vulnerable' in str(service).lower() else 'Secure'}
                    </span></td>
                </tr>
            """
        
        html += """
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by XPRO - APEX SENTINEL v2.0</p>
            <p>GitHub: <a href="https://github.com/Irfan430/XPRO">https://github.com/Irfan430/XPRO</a></p>
            <p>⚠️ This report is for authorized security testing only. Unauthorized use is prohibited.</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Save report
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(report_path)
    
    def _create_default_template(self):
        """Create default report template"""
        template = self.template_dir / "default.html"
        if not template.exists():
            with open(template, 'w') as f:
                f.write("<!-- Default XPRO Template -->")

# ============================================================================
# MAIN CONTROLLER
# ============================================================================

class XPROController:
    """Main controller for XPRO framework"""
    
    def __init__(self):
        self.config = XPROConfig()
        self.dashboard = XPRODashboard(self.config)
        self.scanner = XPROScanner(self.config, self.dashboard)
        self.webauditor = WebAuditor(self.config, self.dashboard)
        self.reporter = XPROReporter(self.config)
        
        # Results storage
        self.results = {
            'network': {},
            'web': {},
            'summary': {}
        }
    
    def run(self):
        """Main execution flow"""
        try:
            # Show banner
            self.dashboard.show_banner()
            
            # Check tools
            self._check_environment()
            
            # Get target
            target = self._get_target()
            
            # Run network scan
            self.results['network'] = self.scanner.network_discovery(target)
            
            # Check for web services
            web_targets = self._extract_web_targets(self.results['network'])
            if web_targets:
                self.results['web'] = self.webauditor.audit_website(web_targets[0])
            
            # Generate report
            self._generate_final_report()
            
            # Show completion
            self._show_completion()
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted by user[/yellow]")
        except Exception as e:
            self.console.print(f"\n[red]Fatal error: {e}[/red]")
            import traceback
            traceback.print_exc()
    
    def _check_environment(self):
        """Check if required tools are installed"""
        self.dashboard.update_dashboard(
            "Environment Check",
            "Verifying tools...",
            {}
        )
        
        tools = self.config.check_tools()
        missing = [tool for tool, installed in tools.items() if not installed]
        
        if missing:
            self.dashboard.update_dashboard(
                "Environment Check",
                f"Missing {len(missing)} tools",
                {"critical": [f"Missing: {', '.join(missing[:3])}"]}
            )
            
            if Confirm.ask("[yellow]Some tools are missing. Continue anyway?"):
                return
            else:
                self.console.print("[green]Please install missing tools and try again.")
                sys.exit(1)
        
        self.dashboard.update_dashboard(
            "Environment Check",
            "All tools verified",
            {"recommendations": ["Starting scan..."]}
        )
        time.sleep(1)
    
    def _get_target(self) -> str:
        """Get target from user"""
        while True:
            target = Prompt.ask("[bold cyan]Enter target (IP/CIDR/URL)[/bold cyan]")
            
            if not target:
                continue
            
            # Validate target format
            if self._validate_target(target):
                # Legal warning
                self.console.print("\n[bold red]LEGAL WARNING:[/bold red]")
                self.console.print("This tool is for authorized security testing only.")
                self.console.print("You must have explicit permission to scan the target.")
                
                if Confirm.ask("[bold red]Do you have authorization to scan this target?"):
                    return target
                else:
                    self.console.print("[yellow]Scan cancelled. Only scan authorized targets.")
            else:
                self.console.print("[red]Invalid target format. Use IP, CIDR, or URL.")
    
    def _validate_target(self, target: str) -> bool:
        """Validate target format"""
        # Simple validation
        if target.startswith(('http://', 'https://')):
            return True
        if '/' in target:  # CIDR
            try:
                parts = target.split('/')
                if len(parts) == 2 and 0 <= int(parts[1]) <= 32:
                    return True
            except:
                return False
        # IP address
        try:
            socket.inet_aton(target)
            return True
        except:
            return False
    
    def _extract_web_targets(self, network_data: Dict) -> List[str]:
        """Extract web targets from network scan"""
        web_targets = []
        
        for host in network_data.get('scan_results', []):
            for service in host.get('services', []):
                if service.get('name') in ['http', 'https', 'http-alt']:
                    proto = 'https' if service.get('name') == 'https' else 'http'
                    web_targets.append(f"{proto}://{host['host']}:{service['port']}")
        
        return web_targets[:5]  # Limit to 5 targets
    
    def _generate_final_report(self):
        """Generate final comprehensive report"""
        self.dashboard.update_dashboard(
            "Report Generation",
            "Creating final report...",
            {"recommendations": ["HTML report", "Executive summary"]}
        )
        
        # Combine all results
        combined = {
            'scan_summary': {
                'total_hosts': self.results['network'].get('total_hosts', 0),
                'scanned_hosts': self.results['network'].get('scanned_hosts', 0),
                'vulnerabilities_found': self.dashboard.vulnerabilities,
                'scan_duration': str(datetime.now() - self.dashboard.start_time),
                'timestamp': datetime.now().isoformat()
            },
            'vulnerabilities': [],
            'services': [],
            'hosts': []
        }
        
        # Extract vulnerabilities
        net_vulns = self.results['network'].get('vulnerabilities', [])
        web_vulns = self.results['web'].get('vulnerabilities', [])
        combined['vulnerabilities'] = net_vulns + web_vulns
        
        # Extract services
        for host in self.results['network'].get('scan_results', []):
            for service in host.get('services', []):
                service['host'] = host['host']
                combined['services'].append(service)
        
        # Generate report
        report_path = self.reporter.generate_report(combined, "html")
        
        # Update dashboard
        self.dashboard.update_dashboard(
            "Report Complete",
            f"Report saved to: {report_path}",
            {
                "critical": [f"Found {len(combined['vulnerabilities'])} vulnerabilities"],
                "recommendations": ["Review report immediately", "Prioritize critical fixes"]
            }
        )
    
    def _show_completion(self):
        """Show completion summary"""
        duration = datetime.now() - self.dashboard.start_time
        
        summary_table = Table(title="🎯 SCAN COMPLETE", show_header=False, box=None)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Total Time", str(duration).split('.')[0])
        summary_table.add_row("Hosts Scanned", str(self.dashboard.hosts))
        summary_table.add_row("Services Found", str(self.dashboard.services))
        summary_table.add_row("Vulnerabilities", str(self.dashboard.vulnerabilities))
        summary_table.add_row("Threads Used", f"{self.config.THREAD_POOL_SIZE}")
        summary_table.add_row("RAM Usage", f"{psutil.Process().memory_info().rss / 1024**2:.1f} MB")
        
        self.dashboard.clear()
        self.dashboard.show_banner()
        self.console.print(summary_table)
        self.console.print("\n[bold green]✅ XPRO audit completed successfully![/bold green]")
        self.console.print(f"[bold]Reports saved in:[/bold] {self.config.REPORT_DIR}")
        self.console.print(f"[bold]GitHub:[/bold] https://github.com/Irfan430/XPRO\n")

# ============================================================================
# QUICK INSTALL SCRIPT
# ============================================================================

def quick_install():
    """Quick installation for XPRO"""
    console = Console()
    
    console.print("[bold cyan]XPRO Quick Installer[/bold cyan]")
    console.print("=" * 50)
    
    # Check Python
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        console.print("[red]Python 3.8+ is required[/red]")
        sys.exit(1)
    
    console.print("[green]✓ Python version OK[/green]")
    
    # Install dependencies
    console.print("\n[cyan]Installing dependencies...[/cyan]")
    
    requirements = [
        "rich", "scapy", "python-nmap", "requests",
        "beautifulsoup4", "pyfiglet", "psutil", "pandas"
    ]
    
    import subprocess
    import importlib
    
    for package in requirements:
        try:
            importlib.import_module(package.replace('-', '_'))
            console.print(f"[green]✓ {package} already installed[/green]")
        except ImportError:
            console.print(f"[yellow]Installing {package}...[/yellow]")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                console.print(f"[green]✓ {package} installed[/green]")
            except:
                console.print(f"[red]✗ Failed to install {package}[/red]")
    
    # Create launcher script
    launcher_path = Path.home() / "xpro.py"
    if not launcher_path.exists():
        current_file = Path(__file__).resolve()
        if current_file != launcher_path:
            import shutil
            shutil.copy(current_file, launcher_path)
            launcher_path.chmod(0o755)
            console.print(f"[green]✓ Launcher created: {launcher_path}[/green]")
    
    console.print("\n[bold green]🎉 XPRO Installation Complete![/bold green]")
    console.print("\nRun XPRO using:")
    console.print(f"  [cyan]python3 {launcher_path}[/cyan]")
    console.print(f"  [cyan]chmod +x {launcher_path} && ./{launcher_path}[/cyan]")
    console.print("\n[bold]GitHub: https://github.com/Irfan430/XPRO[/bold]")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Check for install argument
    if len(sys.argv) > 1 and sys.argv[1] in ['--install', '-i', 'install']:
        quick_install()
        sys.exit(0)
    
    # Check for help
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        console.print("[bold cyan]XPRO - APEX SENTINEL v2.0[/bold cyan]")
        console.print("Usage:")
        console.print("  python3 xpro.py              # Start interactive scan")
        console.print("  python3 xpro.py --install    # Quick install")
        console.print("  python3 xpro.py --help       # Show this help")
        console.print("\nExamples:")
        console.print("  python3 xpro.py")
        console.print("  ./xpro.py --install")
        console.print("\nGitHub: https://github.com/Irfan430/XPRO")
        sys.exit(0)
    
    # Run main controller
    try:
        controller = XPROController()
        controller.run()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        console.print("[yellow]Try running with --install to setup dependencies[/yellow]")
        sys.exit(1)