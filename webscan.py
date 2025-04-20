#!/usr/bin/env python3
"""
WebScan - Website Vulnerability Scanner & Technology Detector
Author: Anshtech Solutions (Anshul Kumar - @Anshulrazz)
Website: https://www.anshtechsolutions.tech
License: MIT
"""

print('''
 __        __   _     ____                                  
 \ \      / /__| |__ |  _ \ _ __ _____  ___   _              
  \ \ /\ / / _ \ '_ \| |_) | '__/ _ \ \/ / | | |             
   \ V  V /  __/ |_) |  __/| | | (_) >  <| |_| |             
    \_/\_/ \___|_.__/|_|   |_|  \___/_/\_\\__, |             
                                            |___/            
-------------------------------------------------------------
 WebScan - Website Vulnerability Scanner & Technology Detector
 Author  : Anshtech Solutions (Anshul Kumar - @Anshulrazz)
 Website : https://www.anshtechsolutions.tech
 License : MIT
-------------------------------------------------------------
''')

import argparse
import json
import os
import sys
import time
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    import builtwith
    import nmap
    import OpenSSL
    from tqdm import tqdm
except ImportError as e:
    print(f"{Fore.RED}Error: Missing required dependencies. {e}")
    print("Please install required packages: pip install builtwith requests bs4 colorama python-nmap pyOpenSSL tqdm")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

class WebScanner:
    def __init__(self, target_url, output_file=None, scan_level="quick"):
        self.target_url = target_url
        self.output_file = output_file
        self.scan_level = scan_level
        self.results = {
            "target": target_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "technologies": [],
            "vulnerabilities": [],
            "open_ports": [],
            "ssl_info": None,
            "headers": {}
        }
        
        print(f"{Fore.BLUE}[*] Initializing WebScanner for {Fore.YELLOW}{target_url}")
        
        # Validate URL format
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(f"{Fore.RED}[!] Invalid URL format. Please provide a URL with scheme (http:// or https://)")
            sys.exit(1)
            
        self.base_domain = parsed_url.netloc
        self.scheme = parsed_url.scheme
    
    def scan_website(self):
        """Main scanning function that coordinates all scanning activities"""
        print(f"{Fore.GREEN}[+] Starting comprehensive scan of {Fore.YELLOW}{self.target_url}")
        
        # Run scans
        self._check_headers()
        self._detect_technologies()
        self._scan_ports()
        
        if self.scheme == "https":
            self._check_ssl_security()
        
        # Save results
        self._save_results()
        
        print(f"\n{Fore.GREEN}[+] Scan completed! Results saved to {self.output_file if self.output_file else 'console'}")
    
    def _check_headers(self):
        """Check HTTP response headers for security issues"""
        print(f"{Fore.BLUE}[*] Checking HTTP headers...")
        
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            self.results["headers"] = dict(headers)
            
            # Check for security headers
            security_headers = {
                "Strict-Transport-Security": "Missing HSTS header",
                "Content-Security-Policy": "Missing CSP header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-Frame-Options": "Missing X-Frame-Options header",
                "X-XSS-Protection": "Missing X-XSS-Protection header",
                "Referrer-Policy": "Missing Referrer-Policy header",
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    self.results["vulnerabilities"].append({
                        "type": "missing_security_header",
                        "name": header,
                        "description": message,
                        "severity": "Medium"
                    })
                    print(f"{Fore.YELLOW}  [-] {message}")
            
            server_header = headers.get("Server", "")
            if server_header and not server_header.startswith("cloudflare"):
                self.results["vulnerabilities"].append({
                    "type": "information_disclosure",
                    "name": "Server Header Disclosure",
                    "description": f"Server header reveals: {server_header}",
                    "severity": "Low"
                })
                print(f"{Fore.YELLOW}  [-] Server header reveals technology: {server_header}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking HTTP headers: {e}")
    
    def _detect_technologies(self):
        """Detect technologies using builtwith"""
        print(f"{Fore.BLUE}[*] Detecting technologies...")
        
        try:
            # Detect technologies
            technologies = builtwith.builtwith(self.target_url)
            
            if technologies:
                print(f"{Fore.GREEN}  [+] Detected technologies:")
                for tech_category, tech_list in technologies.items():
                    for tech in tech_list:
                        tech_name = tech.split('?')[0]  # Remove version/parameters if present
                        tech_data = {
                            "name": tech_name,
                            "category": tech_category,
                            "version": "Unknown"
                        }
                        
                        self.results["technologies"].append(tech_data)
                        print(f"{Fore.CYAN}    - {tech_name} ({tech_category})")
                        
                        # Check for known vulnerabilities
                        self._check_technology_vulnerabilities(tech_name, "Unknown")
            else:
                print(f"{Fore.YELLOW}  [-] No technologies detected")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting technologies: {e}")
    
    def _check_technology_vulnerabilities(self, tech_name, version):
        """Check if detected technology versions have known vulnerabilities"""
        vulnerable_technologies = {
            "Apache": {"versions": ["2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4"], "cve": "DoS vulnerabilities"},
            "nginx": {"versions": ["1.16.", "1.15.", "1.14."], "cve": "HTTP/2 DoS vulnerabilities"},
            "PHP": {"versions": ["5.", "7.0", "7.1", "7.2"], "cve": "Multiple security issues"},
            "WordPress": {"versions": ["4.", "5.0", "5.1", "5.2", "5.3", "5.4"], "cve": "Multiple vulnerabilities"},
            "IIS": {"versions": ["7.0", "7.5", "8.0", "8.5"], "cve": "Multiple vulnerabilities"}
        }
        
        if tech_name in vulnerable_technologies:
            vuln_info = vulnerable_technologies[tech_name]
            for vuln_version in vuln_info["versions"]:
                if version == "Unknown" or version.startswith(vuln_version):
                    self.results["vulnerabilities"].append({
                        "type": "outdated_technology",
                        "name": tech_name,
                        "version": version,
                        "description": f"Potential outdated {tech_name} version with {vuln_info['cve']}",
                        "severity": "High"
                    })
                    print(f"{Fore.RED}    ! Potential vulnerable technology detected: {tech_name}")
                    break
    
    def _scan_ports(self):
        """Scan for open ports using python-nmap"""
        print(f"{Fore.BLUE}[*] Scanning for open ports...")
        
        try:
            # Add Nmap path for Windows
            nmap_path = r"C:\Program Files (x86)\Nmap"
            if os.path.exists(nmap_path) and nmap_path not in os.environ["PATH"]:
                os.environ["PATH"] = nmap_path + os.pathsep + os.environ["PATH"]
                print(f"{Fore.CYAN}  [*] Added {nmap_path} to PATH")
            
            # Initialize nmap PortScanner
            nm = nmap.PortScanner()
            
            # Verify nmap executable exists
            nmap_exe = "nmap.exe" if sys.platform.startswith("win") else "nmap"
            if not any(os.path.isfile(os.path.join(path, nmap_exe)) for path in os.environ["PATH"].split(os.pathsep)):
                raise Exception(f"{nmap_exe} not found in PATH. Ensure Nmap is installed.")
            
            # Set scan parameters based on scan level
            scan_args = '-sS -T4'  # TCP SYN scan, aggressive timing
            if self.scan_level == "quick":
                ports = "21,22,23,80,443,3306,3389,8080"
            else:
                ports = "1-1000"
            
            print(f"{Fore.CYAN}  [*] Scanning ports: {ports}")
            
            # Start the scan
            nm.scan(hosts=self.base_domain, ports=ports, arguments=scan_args)
            
            # Process results
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = nm[host][proto][port]
                        if port_info['state'] == 'open':
                            service_info = {
                                "port": port,
                                "protocol": proto,
                                "service": port_info.get('name', 'unknown'),
                                "state": port_info['state']
                            }
                            self.results["open_ports"].append(service_info)
                            print(f"{Fore.GREEN}  [+] Port {port}/{proto}: {port_info.get('name', 'unknown')}")
                            
                            # Check for potentially dangerous open ports
                            dangerous_ports = {
                                21: "FTP - Plain text authentication",
                                23: "Telnet - Plain text authentication",
                                1433: "MS-SQL - Database access",
                                3306: "MySQL - Database access",
                                3389: "RDP - Remote desktop access",
                                5432: "PostgreSQL - Database access"
                            }
                            
                            if port in dangerous_ports:
                                self.results["vulnerabilities"].append({
                                    "type": "open_dangerous_port",
                                    "name": f"Open {port_info.get('name', 'unknown')} port",
                                    "description": f"Port {port} ({dangerous_ports[port]}) is open",
                                    "severity": "Medium"
                                })
                                print(f"{Fore.YELLOW}    ! {dangerous_ports[port]} - consider restricting access")
            
            if not self.results["open_ports"]:
                print(f"{Fore.YELLOW}  [-] No open ports detected in scanned range")
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Port scanning skipped: {e}")
            print(f"{Fore.YELLOW}  [-] Ensure Nmap is installed at {nmap_path} and nmap.exe is in PATH.")
    
    def _check_ssl_security(self):
        """Check SSL/TLS security configuration"""
        print(f"{Fore.BLUE}[*] Checking SSL/TLS security...")
        
        try:
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.netloc.split(':')[0]
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    cert_info = {
                        "subject": dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in x509.get_subject().get_components()),
                        "issuer": dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in x509.get_issuer().get_components()),
                        "version": x509.get_version(),
                        "serialNumber": x509.get_serial_number(),
                        "notBefore": x509.get_notBefore().decode('utf-8'),
                        "notAfter": x509.get_notAfter().decode('utf-8'),
                        "protocol_version": ssock.version(),
                        "cipher": ssock.cipher(),
                    }
                    
                    # Format dates
                    not_before = datetime.strptime(cert_info["notBefore"], "%Y%m%d%H%M%SZ")
                    not_after = datetime.strptime(cert_info["notAfter"], "%Y%m%d%H%M%SZ")
                    cert_info["notBefore"] = not_before.strftime("%Y-%m-%d %H:%M:%S")
                    cert_info["notAfter"] = not_after.strftime("%Y-%m-%d %H:%M:%S")
                    cert_info["days_remaining"] = (not_after - datetime.now()).days
                    
                    self.results["ssl_info"] = cert_info
                    
                    # Check for issues
                    if cert_info["days_remaining"] < 30:
                        self.results["vulnerabilities"].append({
                            "type": "ssl_expiring",
                            "name": "SSL Certificate Expiring Soon",
                            "description": f"SSL certificate expires in {cert_info['days_remaining']} days",
                            "severity": "High" if cert_info["days_remaining"] < 7 else "Medium"
                        })
                        print(f"{Fore.RED}  [!] SSL certificate expires in {cert_info['days_remaining']} days")
                    
                    # Check protocol version
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.results["vulnerabilities"].append({
                            "type": "weak_ssl_protocol",
                            "name": "Weak SSL/TLS Protocol",
                            "description": f"Using outdated protocol: {ssock.version()}",
                            "severity": "High"
                        })
                        print(f"{Fore.RED}  [!] Using outdated protocol: {ssock.version()}")
                    
                    print(f"{Fore.GREEN}  [+] SSL Certificate:")
                    print(f"{Fore.CYAN}    - Issued to: {cert_info['subject'].get('CN', 'Unknown')}")
                    print(f"{Fore.CYAN}    - Issued by: {cert_info['issuer'].get('CN', 'Unknown')}")
                    print(f"{Fore.CYAN}    - Valid until: {cert_info['notAfter']} ({cert_info['days_remaining']} days)")
                    print(f"{Fore.CYAN}    - Protocol: {cert_info['protocol_version']}")
                    print(f"{Fore.CYAN}    - Cipher: {cert_info['cipher'][0]}")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking SSL/TLS security: {e}")
    
    def _save_results(self):
        """Save scan results to file"""
        if self.output_file:
            try:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4, ensure_ascii=False)
                print(f"{Fore.GREEN}[+] Results saved to {self.output_file}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error saving results: {e}")
        
        # Print a summary
        print(f"\n{Fore.BLUE}[*] Scan Summary for {Fore.YELLOW}{self.target_url}")
        print(f"{Fore.CYAN}  - Technologies detected: {len(self.results['technologies'])}")
        print(f"{Fore.CYAN}  - Open ports: {len(self.results['open_ports'])}")
        
        vuln_count = len(self.results['vulnerabilities'])
        if vuln_count == 0:
            print(f"{Fore.GREEN}  - Vulnerabilities found: {vuln_count}")
        else:
            print(f"{Fore.RED}  - Vulnerabilities found: {vuln_count}")
            
            # Count by severity
            high = sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'High')
            medium = sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'Medium')
            low = sum(1 for v in self.results['vulnerabilities'] if v.get('severity') == 'Low')
            
            if high:
                print(f"{Fore.RED}    • High: {high}")
            if medium:
                print(f"{Fore.YELLOW}    • Medium: {medium}")
            if low:
                print(f"{Fore.GREEN}    • Low: {low}")

def main():
    parser = argparse.ArgumentParser(description='WebScan - Website Vulnerability Scanner & Technology Detector')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--output', '-o', help='Output file for scan results (JSON format)')
    parser.add_argument('--level', choices=['quick', 'full'], default='quick', help='Scan level (quick or full)')
    
    args = parser.parse_args()
    
    # Set default output file if not specified
    if not args.output:
        domain = urlparse(args.url).netloc.replace(':', '_')  # Replace colons for valid filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"webscan_{domain}_{timestamp}.json"
    
    # Create scanner and run scan
    scanner = WebScanner(
        target_url=args.url,
        output_file=args.output,
        scan_level=args.level
    )
    
    scanner.scan_website()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
