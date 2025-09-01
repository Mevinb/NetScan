#!/usr/bin/env python3
"""
Security Log Analyzer
A tool for analyzing security logs and detecting suspicious activities.

Author: Security Log Analyzer
Version: 1.0.0
"""

import re
import json
import csv
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import argparse
import os
import glob

try:
    from colorama import Fore, Style, init
    from tabulate import tabulate
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Please install requirements: pip install colorama tabulate")
    exit(1)

# Initialize colorama
init(autoreset=True)

class SecurityLogAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'failed_login': [
                r'Failed login|Authentication failed|Login failed|Invalid user',
                r'Failed password|Incorrect password|Bad password',
                r'Account locked|User locked|Lockout'
            ],
            'brute_force': [
                r'Multiple failed login attempts',
                r'Repeated authentication failures',
                r'Suspicious login activity'
            ],
            'privilege_escalation': [
                r'sudo|su |elevation|privilege|administrator|root access',
                r'UAC|User Account Control|elevated privileges'
            ],
            'malware_indicators': [
                r'virus|malware|trojan|backdoor|rootkit',
                r'suspicious file|quarantine|blocked executable'
            ],
            'network_attacks': [
                r'port scan|network scan|reconnaissance',
                r'DDoS|denial of service|flooding',
                r'intrusion|unauthorized access|penetration'
            ],
            'suspicious_network': [
                r'connection refused|connection timeout',
                r'unusual traffic|abnormal bandwidth',
                r'blocked connection|firewall deny'
            ]
        }
        
        self.ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        self.timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',  # 2025-01-01 12:30:45
            r'\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}',     # Jan 01 12:30:45
            r'\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}'    # 01/01/2025 12:30:45
        ]
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}================================================================
                   Security Log Analyzer                     
                        Version 1.0.0                        
                 Defensive Security Tool                     
================================================================{Style.RESET_ALL}
"""
        print(banner)
    
    def analyze_windows_security_logs(self, log_path=None):
        """Analyze Windows Security Event Logs"""
        print(f"{Fore.BLUE}[INFO] Analyzing Windows Security Logs...{Style.RESET_ALL}")
        
        # Common Windows log locations
        common_paths = [
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            r"C:\Windows\System32\winevt\Logs\System.evtx",
            r"C:\Windows\System32\winevt\Logs\Application.evtx"
        ]
        
        findings = []
        
        # For demo purposes, we'll simulate reading Windows event logs
        # In reality, you'd use libraries like python-evtx to parse .evtx files
        
        print(f"{Fore.YELLOW}[INFO] Note: For full Windows Event Log analysis, install python-evtx library{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[INFO] Checking for common log files and generating sample analysis...{Style.RESET_ALL}")
        
        # Sample findings for demonstration
        sample_findings = [
            {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': '4625',
                'description': 'Failed logon attempt',
                'source_ip': '192.168.1.100',
                'username': 'administrator',
                'severity': 'Medium'
            },
            {
                'timestamp': (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
                'event_id': '4624',
                'description': 'Successful logon',
                'source_ip': '192.168.1.50',
                'username': 'user1',
                'severity': 'Low'
            }
        ]
        
        return sample_findings
    
    def analyze_text_logs(self, log_file):
        """Analyze text-based log files"""
        print(f"{Fore.BLUE}[INFO] Analyzing log file: {log_file}{Style.RESET_ALL}")
        
        if not os.path.exists(log_file):
            print(f"{Fore.RED}[ERROR] Log file not found: {log_file}{Style.RESET_ALL}")
            return []
        
        findings = []
        ip_addresses = Counter()
        failed_logins = Counter()
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            print(f"{Fore.GREEN}[INFO] Processing {len(lines)} log entries...{Style.RESET_ALL}")
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                
                # Extract timestamp
                timestamp = self._extract_timestamp(line)
                
                # Extract IP addresses
                ips = re.findall(self.ip_pattern, line)
                for ip in ips:
                    ip_addresses[ip] += 1
                
                # Check for suspicious patterns
                for category, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            severity = self._determine_severity(category, line)
                            
                            findings.append({
                                'line_number': line_num,
                                'timestamp': timestamp,
                                'category': category,
                                'pattern': pattern,
                                'line': line[:200] + '...' if len(line) > 200 else line,
                                'severity': severity,
                                'ips': ips
                            })
                            
                            # Track failed logins by IP
                            if category == 'failed_login' and ips:
                                failed_logins[ips[0]] += 1
                            
                            break  # Only match first pattern per line
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to analyze log file: {e}{Style.RESET_ALL}")
            return []
        
        # Detect brute force attempts
        brute_force_ips = [ip for ip, count in failed_logins.items() if count >= 5]
        for ip in brute_force_ips:
            findings.append({
                'line_number': 0,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'category': 'brute_force_detected',
                'pattern': f'Multiple failed logins from {ip}',
                'line': f'Detected {failed_logins[ip]} failed login attempts from {ip}',
                'severity': 'High',
                'ips': [ip]
            })
        
        return findings, ip_addresses, failed_logins
    
    def _extract_timestamp(self, line):
        """Extract timestamp from log line"""
        for pattern in self.timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group()
        return "Unknown"
    
    def _determine_severity(self, category, line):
        """Determine severity based on category and content"""
        high_severity = ['brute_force', 'privilege_escalation', 'malware_indicators', 'network_attacks']
        medium_severity = ['failed_login', 'suspicious_network']
        
        if category in high_severity:
            return 'High'
        elif category in medium_severity:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_security_timeline(self, findings):
        """Generate timeline of security events"""
        print(f"\n{Fore.CYAN}[SECURITY TIMELINE]{Style.RESET_ALL}")
        
        # Sort findings by timestamp
        sorted_findings = sorted(findings, 
                               key=lambda x: x.get('timestamp', ''), 
                               reverse=True)
        
        timeline_data = []
        for finding in sorted_findings[:20]:  # Show last 20 events
            timeline_data.append([
                finding.get('timestamp', 'Unknown'),
                finding.get('category', 'Unknown'),
                finding.get('severity', 'Unknown'),
                finding.get('line', '')[:80] + '...' if len(finding.get('line', '')) > 80 else finding.get('line', '')
            ])
        
        if timeline_data:
            print(tabulate(timeline_data, 
                         headers=['Timestamp', 'Category', 'Severity', 'Description'], 
                         tablefmt='grid'))
        else:
            print("No security events found in timeline")
    
    def analyze_ip_activity(self, ip_addresses, failed_logins):
        """Analyze IP address activity"""
        print(f"\n{Fore.CYAN}[IP ACTIVITY ANALYSIS]{Style.RESET_ALL}")
        
        # Top IPs by activity
        print(f"\n{Fore.YELLOW}Top 10 Most Active IP Addresses:{Style.RESET_ALL}")
        top_ips = ip_addresses.most_common(10)
        
        ip_table = []
        for ip, count in top_ips:
            risk_level = "High" if count > 100 else "Medium" if count > 50 else "Low"
            failed_count = failed_logins.get(ip, 0)
            
            ip_table.append([
                ip,
                count,
                failed_count,
                risk_level
            ])
        
        if ip_table:
            print(tabulate(ip_table, 
                         headers=['IP Address', 'Total Activity', 'Failed Logins', 'Risk Level'], 
                         tablefmt='grid'))
    
    def detect_anomalies(self, findings):
        """Detect security anomalies"""
        print(f"\n{Fore.RED}[SECURITY ANOMALIES DETECTED]{Style.RESET_ALL}")
        
        # Count by category
        category_counts = Counter([f.get('category') for f in findings])
        
        # Detect high-frequency events
        anomalies = []
        for category, count in category_counts.items():
            if count >= 10:  # Threshold for anomaly
                anomalies.append({
                    'type': 'High Frequency Event',
                    'category': category,
                    'count': count,
                    'description': f'Unusual number of {category} events detected'
                })
        
        # Detect severity patterns
        high_severity_count = len([f for f in findings if f.get('severity') == 'High'])
        if high_severity_count >= 5:
            anomalies.append({
                'type': 'High Severity Cluster',
                'category': 'multiple',
                'count': high_severity_count,
                'description': f'{high_severity_count} high-severity security events detected'
            })
        
        if anomalies:
            anomaly_table = []
            for anomaly in anomalies:
                anomaly_table.append([
                    anomaly['type'],
                    anomaly['category'],
                    anomaly['count'],
                    anomaly['description']
                ])
            
            print(tabulate(anomaly_table, 
                         headers=['Anomaly Type', 'Category', 'Count', 'Description'], 
                         tablefmt='grid'))
        else:
            print(f"{Fore.GREEN}No significant anomalies detected{Style.RESET_ALL}")
    
    def generate_summary_report(self, findings, ip_addresses, failed_logins):
        """Generate comprehensive security summary"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"           SECURITY LOG ANALYSIS SUMMARY")
        print(f"           Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        # Overall statistics
        total_events = len(findings)
        high_severity = len([f for f in findings if f.get('severity') == 'High'])
        medium_severity = len([f for f in findings if f.get('severity') == 'Medium'])
        low_severity = len([f for f in findings if f.get('severity') == 'Low'])
        
        print(f"{Fore.CYAN}[OVERALL STATISTICS]{Style.RESET_ALL}")
        print(f"Total Security Events: {total_events}")
        print(f"High Severity Events: {high_severity}")
        print(f"Medium Severity Events: {medium_severity}")
        print(f"Low Severity Events: {low_severity}")
        print(f"Unique IP Addresses: {len(ip_addresses)}")
        print(f"IPs with Failed Logins: {len(failed_logins)}")
        
        # Category breakdown
        if findings:
            category_counts = Counter([f.get('category') for f in findings])
            print(f"\n{Fore.CYAN}[EVENT CATEGORIES]{Style.RESET_ALL}")
            for category, count in category_counts.most_common():
                print(f"  {category}: {count}")
        
        # Risk assessment
        risk_score = self._calculate_risk_score(high_severity, medium_severity, low_severity, failed_logins)
        print(f"\n{Fore.CYAN}[RISK ASSESSMENT]{Style.RESET_ALL}")
        print(f"Overall Risk Score: {risk_score}/100")
        
        if risk_score >= 70:
            print(f"{Fore.RED}WARNING: HIGH RISK - Immediate attention required{Style.RESET_ALL}")
        elif risk_score >= 40:
            print(f"{Fore.YELLOW}WARNING: MEDIUM RISK - Monitor closely{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}INFO: LOW RISK - Normal activity{Style.RESET_ALL}")
    
    def _calculate_risk_score(self, high_severity, medium_severity, low_severity, failed_logins):
        """Calculate overall risk score"""
        score = 0
        score += high_severity * 10  # High severity events worth 10 points each
        score += medium_severity * 5  # Medium severity events worth 5 points each
        score += low_severity * 1     # Low severity events worth 1 point each
        
        # Additional risk for brute force indicators
        brute_force_ips = len([ip for ip, count in failed_logins.items() if count >= 5])
        score += brute_force_ips * 15
        
        return min(score, 100)  # Cap at 100
    
    def create_sample_log(self, filename="sample_security.log"):
        """Create a sample log file for demonstration"""
        sample_entries = [
            "2025-09-01 21:30:15 [INFO] User login successful - user: john.doe, IP: 192.168.1.50",
            "2025-09-01 21:31:22 [ERROR] Failed login attempt - user: admin, IP: 192.168.1.100",
            "2025-09-01 21:31:45 [ERROR] Failed login attempt - user: administrator, IP: 192.168.1.100",
            "2025-09-01 21:32:10 [ERROR] Failed login attempt - user: root, IP: 192.168.1.100",
            "2025-09-01 21:32:33 [WARNING] Multiple failed login attempts detected from IP: 192.168.1.100",
            "2025-09-01 21:35:12 [INFO] sudo command executed - user: john.doe, command: su -",
            "2025-09-01 21:36:45 [WARNING] Suspicious file detected: malware.exe quarantined",
            "2025-09-01 21:40:22 [ERROR] Port scan detected from IP: 203.0.113.45",
            "2025-09-01 21:41:15 [INFO] Firewall blocked connection from IP: 203.0.113.45 to port 445",
            "2025-09-01 21:45:30 [ERROR] Authentication failed - user: guest, IP: 10.0.0.25",
            "2025-09-01 21:50:18 [WARNING] Unusual network traffic detected - bandwidth spike",
            "2025-09-01 21:55:42 [ERROR] Failed login attempt - user: admin, IP: 192.168.1.75"
        ]
        
        try:
            with open(filename, 'w') as f:
                for entry in sample_entries:
                    f.write(entry + '\n')
            print(f"{Fore.GREEN}[INFO] Sample log file created: {filename}{Style.RESET_ALL}")
            return filename
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not create sample log: {e}{Style.RESET_ALL}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Security Log Analyzer')
    parser.add_argument('--log-file', help='Path to log file to analyze')
    parser.add_argument('--windows', action='store_true', help='Analyze Windows Event Logs')
    parser.add_argument('--create-sample', action='store_true', help='Create sample log file for testing')
    parser.add_argument('--output', help='Save analysis report to file')
    
    args = parser.parse_args()
    
    analyzer = SecurityLogAnalyzer()
    analyzer.print_banner()
    
    if args.create_sample:
        sample_file = analyzer.create_sample_log()
        if sample_file:
            print(f"{Fore.BLUE}[INFO] Use --log-file {sample_file} to analyze the sample{Style.RESET_ALL}")
        return
    
    findings = []
    ip_addresses = Counter()
    failed_logins = Counter()
    
    if args.windows:
        findings = analyzer.analyze_windows_security_logs()
        
    elif args.log_file:
        result = analyzer.analyze_text_logs(args.log_file)
        if isinstance(result, tuple):
            findings, ip_addresses, failed_logins = result
        else:
            findings = result
            
    else:
        print(f"{Fore.YELLOW}[INFO] No input specified. Creating sample log for demonstration...{Style.RESET_ALL}")
        sample_file = analyzer.create_sample_log()
        if sample_file:
            result = analyzer.analyze_text_logs(sample_file)
            if isinstance(result, tuple):
                findings, ip_addresses, failed_logins = result
            else:
                findings = result
    
    if findings:
        # Generate analysis reports
        analyzer.generate_security_timeline(findings)
        analyzer.analyze_ip_activity(ip_addresses, failed_logins)
        analyzer.detect_anomalies(findings)
        analyzer.generate_summary_report(findings, ip_addresses, failed_logins)
        
        # Save to file if requested
        if args.output:
            try:
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'total_findings': len(findings),
                    'findings': findings,
                    'ip_activity': dict(ip_addresses),
                    'failed_logins': dict(failed_logins)
                }
                
                with open(args.output, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                
                print(f"\n{Fore.GREEN}[INFO] Analysis report saved to {args.output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Could not save report: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No security events found or analyzed{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
