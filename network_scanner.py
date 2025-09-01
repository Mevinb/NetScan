#!/usr/bin/env python3
"""
Network Security Scanner
A comprehensive tool for network discovery and vulnerability scanning.

Author: Network Security Tool
Version: 1.0.0
"""

import argparse
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from ipaddress import IPv4Network
import json

try:
    import netifaces
    from colorama import Fore, Style, init
    from tabulate import tabulate
    import requests
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Please install requirements: pip install colorama tabulate netifaces requests")
    sys.exit(1)

# Initialize colorama for Windows compatibility
init(autoreset=True)

class NetworkScanner:
    def __init__(self):
        self.discovered_hosts = []
        self.scan_results = {}
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5900]
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}================================================================
                    Network Security Scanner                  
                        Version 1.0.0                        
              For Educational Purposes Only                   
================================================================{Style.RESET_ALL}
"""
        print(banner)
        
    def get_local_networks(self):
        """Get local network ranges"""
        networks = []
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        if ip and netmask and not ip.startswith('127.'):
                            # Calculate network
                            network = IPv4Network(f"{ip}/{netmask}", strict=False)
                            # Prioritize common home networks and skip virtual interfaces
                            network_str = str(network.network_address) + '/' + str(network.prefixlen)
                            if any(network_str.startswith(prefix) for prefix in ['192.168.1.', '192.168.0.', '10.0.0.']):
                                networks.insert(0, network_str)  # Prioritize common home networks
                            elif not any(network_str.startswith(prefix) for prefix in ['192.168.56.', '192.168.137.', '172.16.']):
                                networks.append(network_str)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not detect local networks: {e}{Style.RESET_ALL}")
            # Fallback to common private networks
            networks = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']
        
        return networks
    
    def ping_sweep(self, network):
        """Perform ping sweep to discover live hosts"""
        print(f"{Fore.BLUE}[INFO] Performing ping sweep on {network}...{Style.RESET_ALL}")
        
        try:
            # Parse network
            net = IPv4Network(network, strict=False)
            live_hosts = []
            
            # Use threading for faster scanning
            def ping_host(ip):
                try:
                    # Use system ping command
                    if sys.platform.startswith('win'):
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                              capture_output=True, text=True, timeout=5)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                              capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(str(ip))[0]
                        except:
                            hostname = 'Unknown'
                        
                        live_hosts.append({
                            'ip': str(ip),
                            'hostname': hostname,
                            'status': 'up'
                        })
                        print(f"{Fore.GREEN}[+] Found: {ip} ({hostname}){Style.RESET_ALL}")
                        
                except Exception:
                    pass
            
            # Create threads for parallel ping
            threads = []
            for ip in list(net.hosts())[:50]:  # Limit to first 50 IPs
                thread = threading.Thread(target=ping_host, args=(ip,))
                threads.append(thread)
                thread.start()
                
                # Limit concurrent threads
                if len(threads) >= 20:
                    for t in threads:
                        t.join(timeout=2)
                    threads = []
            
            # Wait for remaining threads
            for thread in threads:
                thread.join(timeout=2)
                    
            return live_hosts
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Ping sweep failed: {e}{Style.RESET_ALL}")
            return []
    
    def port_scan(self, target, port_range='1-1000'):
        """Perform port scan on target"""
        print(f"{Fore.BLUE}[INFO] Scanning ports on {target}...{Style.RESET_ALL}")
        
        try:
            # Parse port range
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                ports = range(start_port, min(end_port + 1, 1001))  # Limit to reasonable range
            else:
                ports = self.common_ports
            
            open_ports = []
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        # Try to get service name
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = 'unknown'
                        
                        open_ports.append({
                            'port': port,
                            'state': 'open',
                            'service': service
                        })
                        print(f"{Fore.GREEN}[+] {target}:{port} - {service}{Style.RESET_ALL}")
                        
                except Exception:
                    pass
            
            # Create threads for parallel scanning
            threads = []
            for port in ports:
                thread = threading.Thread(target=scan_port, args=(port,))
                threads.append(thread)
                thread.start()
                
                # Limit concurrent threads
                if len(threads) >= 50:
                    for t in threads:
                        t.join(timeout=1)
                    threads = []
            
            # Wait for remaining threads
            for thread in threads:
                thread.join(timeout=1)
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(target)[0]
            except:
                hostname = 'Unknown'
            
            results = {
                target: {
                    'hostname': hostname,
                    'state': 'up',
                    'ports': open_ports
                }
            }
            
            return results
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Port scan failed: {e}{Style.RESET_ALL}")
            return {}
    
    def vulnerability_scan(self, target):
        """Perform basic vulnerability checks"""
        print(f"{Fore.BLUE}[INFO] Performing vulnerability scan on {target}...{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        try:
            # Check for common vulnerable services
            common_vulns = self._check_common_vulnerabilities(target)
            vulnerabilities.extend(common_vulns)
            
            # Check for web vulnerabilities if port 80 or 443 is open
            if self._is_port_open(target, 80) or self._is_port_open(target, 443):
                web_vulns = self._check_web_vulnerabilities(target)
                vulnerabilities.extend(web_vulns)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Vulnerability scan had issues: {e}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def _check_common_vulnerabilities(self, target):
        """Check for common vulnerabilities"""
        vulns = []
        
        # Check for common vulnerable ports
        vulnerable_ports = {
            21: 'FTP - Check for anonymous login',
            22: 'SSH - Check for weak passwords',
            23: 'Telnet - Unencrypted protocol',
            25: 'SMTP - Check for open relay',
            53: 'DNS - Check for zone transfer',
            80: 'HTTP - Check for web vulnerabilities',
            110: 'POP3 - Unencrypted email',
            135: 'RPC - Windows RPC endpoint',
            139: 'NetBIOS - File sharing vulnerabilities',
            443: 'HTTPS - Check SSL/TLS configuration',
            445: 'SMB - Check for SMB vulnerabilities',
            993: 'IMAPS - Check SSL configuration',
            995: 'POP3S - Check SSL configuration'
        }
        
        for port, description in vulnerable_ports.items():
            if self._is_port_open(target, port):
                severity = 'High' if port in [21, 23, 135, 139, 445] else 'Medium'
                vulns.append({
                    'host': target,
                    'port': port,
                    'description': description,
                    'severity': severity
                })
        
        return vulns
    
    def _check_web_vulnerabilities(self, target):
        """Check for basic web vulnerabilities"""
        vulns = []
        
        try:
            # Check HTTP
            if self._is_port_open(target, 80):
                url = f"http://{target}"
                self._check_http_security(url, vulns, target)
            
            # Check HTTPS
            if self._is_port_open(target, 443):
                url = f"https://{target}"
                self._check_http_security(url, vulns, target)
                
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Web vulnerability check failed: {e}{Style.RESET_ALL}")
        
        return vulns
    
    def _check_http_security(self, url, vulns, target):
        """Check HTTP security headers and configurations"""
        try:
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulns.append({
                        'host': target,
                        'port': 443 if url.startswith('https') else 80,
                        'description': description,
                        'severity': 'Low'
                    })
            
            # Check server banner
            server = headers.get('Server', '')
            if server:
                vulns.append({
                    'host': target,
                    'port': 443 if url.startswith('https') else 80,
                    'description': f'Server banner disclosure: {server}',
                    'severity': 'Low'
                })
                
        except Exception:
            pass
    
    def _is_port_open(self, host, port, timeout=3):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def generate_report(self, scan_data, output_file=None):
        """Generate scan report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"           NETWORK SECURITY SCAN REPORT")
        print(f"           Generated: {timestamp}")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        # Host Discovery Report
        if 'hosts' in scan_data:
            print(f"{Fore.CYAN}[DISCOVERED HOSTS]{Style.RESET_ALL}")
            host_table = []
            for host in scan_data['hosts']:
                host_table.append([
                    host['ip'],
                    host['hostname'],
                    host['status']
                ])
            
            if host_table:
                print(tabulate(host_table, headers=['IP Address', 'Hostname', 'Status'], tablefmt='grid'))
            print()
        
        # Port Scan Report
        if 'ports' in scan_data:
            print(f"{Fore.CYAN}[PORT SCAN RESULTS]{Style.RESET_ALL}")
            for host, data in scan_data['ports'].items():
                print(f"\n{Fore.WHITE}Host: {host} ({data.get('hostname', 'Unknown')}){Style.RESET_ALL}")
                
                if 'ports' in data and data['ports']:
                    port_table = []
                    for port_info in data['ports']:
                        port_table.append([
                            port_info['port'],
                            port_info['state'],
                            port_info['service']
                        ])
                    
                    if port_table:
                        print(tabulate(port_table, headers=['Port', 'State', 'Service'], tablefmt='grid'))
                else:
                    print("No open ports found")
        
        # Vulnerability Report
        if 'vulnerabilities' in scan_data and scan_data['vulnerabilities']:
            print(f"\n{Fore.RED}[VULNERABILITY ASSESSMENT]{Style.RESET_ALL}")
            vuln_table = []
            for vuln in scan_data['vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                color = Fore.RED if severity == 'High' else Fore.YELLOW if severity == 'Medium' else Fore.GREEN
                vuln_table.append([
                    vuln['host'],
                    vuln.get('port', 'N/A'),
                    vuln.get('description', vuln.get('script', 'Unknown')),
                    f"{color}{severity}{Style.RESET_ALL}"
                ])
            
            if vuln_table:
                print(tabulate(vuln_table, headers=['Host', 'Port', 'Description', 'Severity'], tablefmt='grid'))
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(scan_data, f, indent=2)
                print(f"\n{Fore.GREEN}[INFO] Detailed report saved to {output_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Could not save report: {e}{Style.RESET_ALL}")
    
    def full_network_scan(self, network=None, port_range='1-1000'):
        """Perform complete network security scan"""
        scan_data = {}
        
        # Auto-detect network if not provided
        if not network:
            networks = self.get_local_networks()
            if networks:
                network = networks[0]
                print(f"{Fore.BLUE}[INFO] Auto-detected network: {network}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[ERROR] Could not detect network. Please specify manually.{Style.RESET_ALL}")
                return
        
        # Step 1: Host Discovery
        hosts = self.ping_sweep(network)
        scan_data['hosts'] = hosts
        
        if not hosts:
            print(f"{Fore.YELLOW}[WARNING] No live hosts found{Style.RESET_ALL}")
            return scan_data
        
        print(f"{Fore.GREEN}[INFO] Found {len(hosts)} live hosts{Style.RESET_ALL}")
        
        # Step 2: Port Scanning
        scan_data['ports'] = {}
        scan_data['vulnerabilities'] = []
        
        for host in hosts[:5]:  # Limit to first 5 hosts to avoid long scans
            ip = host['ip']
            print(f"\n{Fore.BLUE}[INFO] Scanning {ip}...{Style.RESET_ALL}")
            
            # Port scan
            port_results = self.port_scan(ip, port_range)
            if port_results:
                scan_data['ports'].update(port_results)
            
            # Vulnerability scan
            vulns = self.vulnerability_scan(ip)
            scan_data['vulnerabilities'].extend(vulns)
            
            # Small delay to be respectful
            time.sleep(1)
        
        return scan_data

def main():
    parser = argparse.ArgumentParser(description='Network Security Scanner')
    parser.add_argument('--discover', action='store_true', help='Discover live hosts only')
    parser.add_argument('--target', help='Target IP or network (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('--ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    parser.add_argument('--vuln-scan', action='store_true', help='Perform vulnerability scan')
    parser.add_argument('--full-scan', action='store_true', help='Perform complete network audit')
    parser.add_argument('--log-analysis', action='store_true', help='Perform security log analysis')
    parser.add_argument('--output', help='Save report to file')
    
    args = parser.parse_args()
    
    # Check if running with sufficient privileges
    try:
        # Test if we can create raw sockets (requires admin/root)
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_socket.close()
    except (PermissionError, OSError):
        print(f"{Fore.YELLOW}[WARNING] Some features may require administrator privileges{Style.RESET_ALL}")
    
    scanner = NetworkScanner()
    scanner.print_banner()
    
    scan_data = {}
    
    if args.discover:
        network = args.target or scanner.get_local_networks()[0]
        hosts = scanner.ping_sweep(network)
        scan_data['hosts'] = hosts
        
    elif args.target and args.vuln_scan:
        vulns = scanner.vulnerability_scan(args.target)
        scan_data['vulnerabilities'] = vulns
        
    elif args.target:
        port_results = scanner.port_scan(args.target, args.ports)
        scan_data['ports'] = port_results
        
    elif args.full_scan:
        scan_data = scanner.full_network_scan(args.target, args.ports)
        
    else:
        # Interactive mode
        print(f"{Fore.CYAN}Starting interactive network scan...{Style.RESET_ALL}")
        scan_data = scanner.full_network_scan(port_range='1-100')  # Quick scan for demo
    
    # Generate report
    if scan_data:
        scanner.generate_report(scan_data, args.output)
    else:
        print(f"{Fore.YELLOW}[INFO] No scan performed. Use --help for options.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
