#!/usr/bin/env python3
"""
Comprehensive Security Analysis Tool
Combines network scanning and log analysis for complete security assessment.

Author: Security Analysis Tool
Version: 1.0.0
"""

import subprocess
import sys
import os
from datetime import datetime
import json

try:
    from colorama import Fore, Style, init
    from tabulate import tabulate
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Please install requirements: pip install colorama tabulate")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

class ComprehensiveSecurityAnalyzer:
    def __init__(self):
        self.network_scanner = "network_scanner.py"
        self.log_analyzer = "log_analyzer.py"
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}================================================================
              Comprehensive Security Analysis Tool           
                        Version 1.0.0                        
            Network Scanning + Log Analysis                  
================================================================{Style.RESET_ALL}
"""
        print(banner)
    
    def run_network_scan(self, target=None, scan_type="full"):
        """Run network security scan"""
        print(f"{Fore.BLUE}[INFO] Running network security scan...{Style.RESET_ALL}")
        
        cmd = ["python", self.network_scanner]
        
        if scan_type == "discover":
            cmd.append("--discover")
        elif scan_type == "full":
            cmd.append("--full-scan")
        elif scan_type == "vuln":
            cmd.append("--vuln-scan")
        
        if target:
            cmd.extend(["--target", target])
        
        # Save network scan results
        cmd.extend(["--output", "network_scan_results.json"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[INFO] Network scan completed successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[ERROR] Network scan failed: {result.stderr}{Style.RESET_ALL}")
                return False
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[WARNING] Network scan timed out{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Network scan error: {e}{Style.RESET_ALL}")
            return False
    
    def run_log_analysis(self, log_file=None):
        """Run log analysis"""
        print(f"{Fore.BLUE}[INFO] Running security log analysis...{Style.RESET_ALL}")
        
        cmd = ["python", self.log_analyzer]
        
        if log_file and os.path.exists(log_file):
            cmd.extend(["--log-file", log_file])
        else:
            # Create and analyze sample log if no log file provided
            print(f"{Fore.YELLOW}[INFO] No log file provided, creating sample for demonstration{Style.RESET_ALL}")
            cmd.append("--create-sample")
            
            # Run create sample first
            try:
                subprocess.run(cmd, timeout=30)
                # Then analyze the sample
                cmd = ["python", self.log_analyzer, "--log-file", "sample_security.log"]
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to create sample log: {e}{Style.RESET_ALL}")
                return False
        
        # Save log analysis results
        cmd.extend(["--output", "log_analysis_results.json"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[INFO] Log analysis completed successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[ERROR] Log analysis failed: {result.stderr}{Style.RESET_ALL}")
                return False
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[WARNING] Log analysis timed out{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Log analysis error: {e}{Style.RESET_ALL}")
            return False
    
    def generate_comprehensive_report(self):
        """Generate comprehensive security assessment report"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"              COMPREHENSIVE SECURITY ASSESSMENT")
        print(f"                 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        # Load network scan results
        network_data = None
        if os.path.exists("network_scan_results.json"):
            try:
                with open("network_scan_results.json", 'r') as f:
                    network_data = json.load(f)
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Could not load network scan results: {e}{Style.RESET_ALL}")
        
        # Load log analysis results
        log_data = None
        if os.path.exists("log_analysis_results.json"):
            try:
                with open("log_analysis_results.json", 'r') as f:
                    log_data = json.load(f)
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Could not load log analysis results: {e}{Style.RESET_ALL}")
        
        # Network Security Summary
        print(f"{Fore.CYAN}[NETWORK SECURITY SUMMARY]{Style.RESET_ALL}")
        if network_data:
            hosts_found = len(network_data.get('hosts', []))
            vulns_found = len(network_data.get('vulnerabilities', []))
            
            print(f"Hosts Discovered: {hosts_found}")
            print(f"Vulnerabilities Found: {vulns_found}")
            
            if vulns_found > 0:
                high_vulns = len([v for v in network_data.get('vulnerabilities', []) if v.get('severity') == 'High'])
                print(f"High-Risk Vulnerabilities: {high_vulns}")
        else:
            print("Network scan data not available")
        
        # Log Analysis Summary
        print(f"\n{Fore.CYAN}[LOG ANALYSIS SUMMARY]{Style.RESET_ALL}")
        if log_data:
            total_findings = log_data.get('total_findings', 0)
            print(f"Security Events Analyzed: {total_findings}")
            
            if 'findings' in log_data:
                high_severity = len([f for f in log_data['findings'] if f.get('severity') == 'High'])
                print(f"High-Severity Events: {high_severity}")
                
                # Most active IPs from logs
                ip_activity = log_data.get('ip_activity', {})
                if ip_activity:
                    top_ip = max(ip_activity.items(), key=lambda x: x[1])
                    print(f"Most Active IP: {top_ip[0]} ({top_ip[1]} events)")
        else:
            print("Log analysis data not available")
        
        # Combined Risk Assessment
        print(f"\n{Fore.CYAN}[COMBINED RISK ASSESSMENT]{Style.RESET_ALL}")
        overall_risk = self._calculate_combined_risk(network_data, log_data)
        
        print(f"Overall Security Score: {overall_risk}/100")
        
        if overall_risk >= 70:
            print(f"{Fore.RED}WARNING: HIGH RISK - Multiple security issues detected{Style.RESET_ALL}")
            self._provide_recommendations("high")
        elif overall_risk >= 40:
            print(f"{Fore.YELLOW}WARNING: MEDIUM RISK - Some security concerns{Style.RESET_ALL}")
            self._provide_recommendations("medium")
        else:
            print(f"{Fore.GREEN}INFO: LOW RISK - Good security posture{Style.RESET_ALL}")
            self._provide_recommendations("low")
    
    def _calculate_combined_risk(self, network_data, log_data):
        """Calculate combined risk score from network and log data"""
        risk_score = 0
        
        # Network-based risk factors
        if network_data:
            vulns = network_data.get('vulnerabilities', [])
            high_network_vulns = len([v for v in vulns if v.get('severity') == 'High'])
            medium_network_vulns = len([v for v in vulns if v.get('severity') == 'Medium'])
            
            risk_score += high_network_vulns * 15
            risk_score += medium_network_vulns * 8
        
        # Log-based risk factors
        if log_data:
            findings = log_data.get('findings', [])
            high_log_events = len([f for f in findings if f.get('severity') == 'High'])
            medium_log_events = len([f for f in findings if f.get('severity') == 'Medium'])
            
            risk_score += high_log_events * 10
            risk_score += medium_log_events * 5
            
            # Additional risk for failed logins
            failed_logins = log_data.get('failed_logins', {})
            brute_force_attempts = len([ip for ip, count in failed_logins.items() if count >= 3])
            risk_score += brute_force_attempts * 20
        
        return min(risk_score, 100)  # Cap at 100
    
    def _provide_recommendations(self, risk_level):
        """Provide security recommendations based on risk level"""
        print(f"\n{Fore.CYAN}[SECURITY RECOMMENDATIONS]{Style.RESET_ALL}")
        
        if risk_level == "high":
            recommendations = [
                "CRITICAL: Immediately patch high-severity vulnerabilities",
                "URGENT: Implement network segmentation",
                "MONITOR: Enable comprehensive logging and monitoring",
                "INVESTIGATE: Review suspicious login patterns",
                "BLOCK: Add malicious IP addresses to firewall blocklist",
                "ENFORCE: Implement strong password policies and MFA"
            ]
        elif risk_level == "medium":
            recommendations = [
                "PATCH: Review and patch medium-severity vulnerabilities",
                "ENHANCE: Improve security monitoring",
                "INVESTIGATE: Review unusual network activity",
                "UPDATE: Review and update firewall rules",
                "AUDIT: Review access logs regularly"
            ]
        else:
            recommendations = [
                "MAINTAIN: Continue current security practices",
                "ASSESS: Schedule regular security assessments",
                "LEARN: Stay updated on security best practices",
                "TEST: Consider penetration testing",
                "MONITOR: Continue tracking security metrics"
            ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    
    def run_comprehensive_analysis(self, target=None, log_file=None):
        """Run complete security analysis"""
        print(f"{Fore.BLUE}[INFO] Starting comprehensive security analysis...{Style.RESET_ALL}")
        
        # Step 1: Network Scanning
        network_success = self.run_network_scan(target, "full")
        
        # Step 2: Log Analysis
        log_success = self.run_log_analysis(log_file)
        
        # Step 3: Generate Comprehensive Report
        if network_success or log_success:
            self.generate_comprehensive_report()
        else:
            print(f"{Fore.RED}[ERROR] Both network scan and log analysis failed{Style.RESET_ALL}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Comprehensive Security Analysis Tool')
    parser.add_argument('--target', help='Network target for scanning')
    parser.add_argument('--log-file', help='Log file for analysis')
    parser.add_argument('--network-only', action='store_true', help='Run network scan only')
    parser.add_argument('--logs-only', action='store_true', help='Run log analysis only')
    
    args = parser.parse_args()
    
    analyzer = ComprehensiveSecurityAnalyzer()
    analyzer.print_banner()
    
    if args.network_only:
        analyzer.run_network_scan(args.target, "full")
    elif args.logs_only:
        analyzer.run_log_analysis(args.log_file)
    else:
        analyzer.run_comprehensive_analysis(args.target, args.log_file)

if __name__ == "__main__":
    main()
