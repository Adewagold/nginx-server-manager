#!/usr/bin/env python3
"""
Security Audit Script for Nginx Site Manager
Performs comprehensive security checks and generates a security report.
"""

import os
import sys
import json
import hashlib
import subprocess
import stat
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

try:
    from app.config import get_config
    from app.security import SecurityConfig
except ImportError as e:
    print(f"Error importing application modules: {e}")
    print("Please ensure you're running this script from the application root directory")
    sys.exit(1)


class SecurityAudit:
    """Performs security audit of the Nginx Site Manager installation."""
    
    def __init__(self):
        self.report = {
            "audit_date": datetime.utcnow().isoformat(),
            "version": "1.0",
            "findings": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            },
            "summary": {}
        }
        
        try:
            self.config = get_config()
        except Exception as e:
            print(f"Warning: Could not load configuration: {e}")
            self.config = None
    
    def add_finding(self, severity: str, title: str, description: str, 
                   recommendation: str = None, details: Dict = None):
        """Add a security finding to the report."""
        finding = {
            "title": title,
            "description": description,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if recommendation:
            finding["recommendation"] = recommendation
        
        if details:
            finding["details"] = details
        
        self.report["findings"][severity].append(finding)
    
    def check_configuration_security(self):
        """Check configuration security settings."""
        print("🔍 Checking configuration security...")
        
        if not self.config:
            self.add_finding(
                "high",
                "Configuration Not Loaded",
                "Could not load application configuration for security audit",
                "Ensure config.yaml exists and is valid"
            )
            return
        
        # Check secret key security
        secret_key = self.config.app.secret_key
        if len(secret_key) < 32:
            self.add_finding(
                "critical",
                "Weak Secret Key",
                f"Secret key is only {len(secret_key)} characters long",
                "Generate a secure secret key with at least 32 characters using: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        elif secret_key in [
            "your-secret-key-here-minimum-32-characters-long",
            "CHANGE-THIS-TO-A-SECURE-32-PLUS-CHARACTER-SECRET-KEY-WITH-SPECIAL-CHARS!"
        ]:
            self.add_finding(
                "critical",
                "Default Secret Key",
                "Using default secret key from configuration template",
                "Generate and set a unique secret key immediately"
            )
        elif secret_key.isalnum():
            self.add_finding(
                "medium",
                "Secret Key Lacks Complexity",
                "Secret key contains only alphanumeric characters",
                "Include special characters in the secret key for better security"
            )
        
        # Check admin credentials
        admin_username = self.config.admin.username
        admin_password = self.config.admin.password
        
        if admin_username == "admin":
            self.add_finding(
                "medium",
                "Default Admin Username",
                "Using default admin username 'admin'",
                "Change admin username to something unique and non-obvious"
            )
        
        if admin_password in ["admin123", "admin", "password", "CHANGE-THIS-TO-A-STRONG-PASSWORD!"]:
            self.add_finding(
                "critical",
                "Default/Weak Admin Password",
                "Using default or weak admin password",
                "Set a strong password with 12+ characters, mixed case, numbers, and special characters"
            )
        elif not admin_password.startswith('$2b$') and len(admin_password) < 12:
            self.add_finding(
                "high",
                "Weak Admin Password",
                f"Admin password is only {len(admin_password)} characters long",
                "Use a password with at least 12 characters"
            )
        
        # Check debug mode
        if self.config.app.debug:
            self.add_finding(
                "high",
                "Debug Mode Enabled",
                "Application debug mode is enabled",
                "Disable debug mode in production environments"
            )
        
        # Check session timeout
        if hasattr(self.config, 'security') and self.config.security.session_timeout > 120:
            self.add_finding(
                "low",
                "Long Session Timeout",
                f"Session timeout is {self.config.security.session_timeout} minutes",
                "Consider reducing session timeout to 30-60 minutes for better security"
            )
        
        # Check CORS settings
        if hasattr(self.config, 'security') and '*' in self.config.security.cors_origins:
            self.add_finding(
                "high",
                "Permissive CORS Configuration",
                "CORS allows requests from any origin (*)",
                "Restrict CORS to specific trusted domains only"
            )
    
    def check_file_permissions(self):
        """Check file and directory permissions."""
        print("🔍 Checking file permissions...")
        
        # Check critical files
        files_to_check = [
            ("config.yaml", 0o600, "Configuration file should be readable only by owner"),
            ("data/sites.db", 0o660, "Database should be readable/writable by owner and group only"),
            ("install.sh", 0o755, "Install script should be executable"),
            ("uninstall.sh", 0o755, "Uninstall script should be executable")
        ]
        
        for file_path, expected_mode, description in files_to_check:
            if os.path.exists(file_path):
                current_mode = stat.S_IMODE(os.stat(file_path).st_mode)
                if current_mode != expected_mode:
                    self.add_finding(
                        "medium",
                        f"Incorrect File Permissions: {file_path}",
                        f"File has permissions {oct(current_mode)} but should have {oct(expected_mode)}",
                        f"Fix with: chmod {oct(expected_mode)} {file_path}",
                        {"file": file_path, "current": oct(current_mode), "expected": oct(expected_mode)}
                    )
        
        # Check directory permissions
        directories_to_check = [
            ("data", 0o755, "Data directory"),
            ("static", 0o755, "Static files directory"),
            ("app", 0o755, "Application directory")
        ]
        
        for dir_path, expected_mode, description in directories_to_check:
            if os.path.exists(dir_path):
                current_mode = stat.S_IMODE(os.stat(dir_path).st_mode)
                if current_mode & 0o002:  # World writable
                    self.add_finding(
                        "medium",
                        f"World-Writable Directory: {dir_path}",
                        f"{description} is world-writable",
                        f"Fix with: chmod 755 {dir_path}"
                    )
    
    def check_ssl_configuration(self):
        """Check SSL/TLS security configuration."""
        print("🔍 Checking SSL configuration...")
        
        # Check for SSL directories
        ssl_dirs = [
            os.path.expanduser("~/.letsencrypt"),
            "/etc/letsencrypt",
            "/etc/ssl"
        ]
        
        for ssl_dir in ssl_dirs:
            if os.path.exists(ssl_dir):
                # Check permissions
                current_mode = stat.S_IMODE(os.stat(ssl_dir).st_mode)
                if current_mode & 0o044:  # Readable by group or others
                    self.add_finding(
                        "high",
                        f"SSL Directory Permissions: {ssl_dir}",
                        "SSL directory is readable by group or others",
                        f"Fix with: chmod 700 {ssl_dir}"
                    )
        
        # Check for certificate files with weak permissions
        for root, dirs, files in os.walk(os.path.expanduser("~/.letsencrypt")):
            for file in files:
                if file.endswith(('.pem', '.key')):
                    file_path = os.path.join(root, file)
                    current_mode = stat.S_IMODE(os.stat(file_path).st_mode)
                    if current_mode & 0o044:  # Readable by group or others
                        self.add_finding(
                            "high",
                            f"SSL Certificate Permissions: {file}",
                            "SSL certificate/key file is readable by group or others",
                            f"Fix with: chmod 600 {file_path}"
                        )
    
    def check_system_security(self):
        """Check system-level security."""
        print("🔍 Checking system security...")
        
        # Check if running as root
        if os.geteuid() == 0:
            self.add_finding(
                "high",
                "Running as Root",
                "Application appears to be running as root user",
                "Run the application as a dedicated non-root user"
            )
        
        # Check firewall status
        try:
            # Check UFW
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                if 'Status: inactive' in result.stdout:
                    self.add_finding(
                        "medium",
                        "Firewall Inactive",
                        "UFW firewall is inactive",
                        "Enable firewall with: sudo ufw enable"
                    )
                else:
                    self.add_finding(
                        "info",
                        "Firewall Active",
                        "UFW firewall is active",
                        None,
                        {"status": result.stdout.strip()}
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Check iptables
            try:
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'Chain INPUT (policy ACCEPT)' in result.stdout:
                    self.add_finding(
                        "medium",
                        "No Firewall Rules",
                        "No restrictive iptables rules found",
                        "Configure firewall rules to restrict access"
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.add_finding(
                    "low",
                    "Cannot Check Firewall",
                    "Unable to determine firewall status",
                    "Manually verify firewall configuration"
                )
        
        # Check for fail2ban
        try:
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                self.add_finding(
                    "medium",
                    "Fail2ban Not Active",
                    "Fail2ban intrusion prevention system is not active",
                    "Install and configure fail2ban for brute-force protection"
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_dependencies(self):
        """Check for security issues in dependencies."""
        print("🔍 Checking dependencies...")
        
        # Check for requirements.txt
        if os.path.exists('requirements.txt'):
            try:
                # Try to use safety to check for known vulnerabilities
                result = subprocess.run(['safety', 'check', '-r', 'requirements.txt'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    if 'No known security vulnerabilities found' in result.stdout:
                        self.add_finding(
                            "info",
                            "Dependencies Clean",
                            "No known security vulnerabilities in dependencies"
                        )
                    else:
                        self.add_finding(
                            "high",
                            "Vulnerable Dependencies",
                            "Security vulnerabilities found in dependencies",
                            "Update vulnerable packages",
                            {"safety_output": result.stdout}
                        )
                else:
                    self.add_finding(
                        "medium",
                        "Dependency Vulnerabilities",
                        "Found potential security issues in dependencies",
                        "Review and update packages",
                        {"safety_output": result.stderr}
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.add_finding(
                    "low",
                    "Cannot Check Dependencies",
                    "Safety tool not available to check for vulnerable dependencies",
                    "Install safety tool: pip install safety"
                )
    
    def check_nginx_security(self):
        """Check nginx security configuration."""
        print("🔍 Checking nginx security...")
        
        # Check nginx configuration files
        nginx_config_paths = [
            "/etc/nginx/nginx.conf",
            "/usr/local/nginx/conf/nginx.conf"
        ]
        
        for config_path in nginx_config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        config_content = f.read()
                    
                    # Check for security headers
                    security_checks = [
                        ("server_tokens off", "Server tokens not disabled", 
                         "Add 'server_tokens off;' to hide nginx version"),
                        ("add_header X-Frame-Options", "Missing X-Frame-Options header",
                         "Add 'add_header X-Frame-Options DENY;' to prevent clickjacking"),
                        ("add_header X-Content-Type-Options", "Missing X-Content-Type-Options header",
                         "Add 'add_header X-Content-Type-Options nosniff;' to prevent MIME sniffing"),
                    ]
                    
                    for check, issue, recommendation in security_checks:
                        if check not in config_content:
                            self.add_finding(
                                "low",
                                f"Nginx Security: {issue}",
                                f"Nginx configuration missing security setting: {check}",
                                recommendation
                            )
                break
    
    def check_application_security(self):
        """Check application-specific security issues."""
        print("🔍 Checking application security...")
        
        # Check for hardcoded secrets
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{3,}["\']', "Hardcoded password found"),
            (r'secret\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded secret found"),
            (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded API key found"),
            (r'token\s*=\s*["\'][^"\']{20,}["\']', "Hardcoded token found"),
        ]
        
        python_files = []
        for root, dirs, files in os.walk('app'):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        for file_path in python_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern, description in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        # Skip if it's in a comment or example
                        lines = content.split('\n')
                        for line_num, line in enumerate(lines, 1):
                            if any(match in line for match in matches):
                                if not (line.strip().startswith('#') or 'example' in line.lower()):
                                    self.add_finding(
                                        "high",
                                        f"Hardcoded Secret: {file_path}",
                                        f"{description} in {file_path}:{line_num}",
                                        "Use environment variables or secure configuration files",
                                        {"file": file_path, "line": line_num, "pattern": pattern}
                                    )
            except Exception as e:
                print(f"Warning: Could not scan {file_path}: {e}")
    
    def generate_summary(self):
        """Generate audit summary."""
        findings = self.report["findings"]
        total_findings = sum(len(findings[level]) for level in findings)
        
        self.report["summary"] = {
            "total_findings": total_findings,
            "critical": len(findings["critical"]),
            "high": len(findings["high"]),
            "medium": len(findings["medium"]),
            "low": len(findings["low"]),
            "info": len(findings["info"]),
            "risk_score": self.calculate_risk_score()
        }
    
    def calculate_risk_score(self):
        """Calculate overall risk score."""
        findings = self.report["findings"]
        score = 0
        score += len(findings["critical"]) * 10
        score += len(findings["high"]) * 7
        score += len(findings["medium"]) * 4
        score += len(findings["low"]) * 1
        
        # Normalize to 0-100 scale
        max_possible = 100
        return min(score, max_possible)
    
    def run_audit(self):
        """Run complete security audit."""
        print("🔐 Starting Security Audit for Nginx Site Manager")
        print("=" * 60)
        
        self.check_configuration_security()
        self.check_file_permissions()
        self.check_ssl_configuration()
        self.check_system_security()
        self.check_dependencies()
        self.check_nginx_security()
        self.check_application_security()
        
        self.generate_summary()
        
        return self.report
    
    def print_report(self):
        """Print human-readable audit report."""
        summary = self.report["summary"]
        findings = self.report["findings"]
        
        print("\n" + "=" * 60)
        print("🔐 SECURITY AUDIT REPORT")
        print("=" * 60)
        print(f"Audit Date: {self.report['audit_date']}")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Risk Score: {summary['risk_score']}/100")
        print()
        
        # Print summary by severity
        severity_colors = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🔵",
            "info": "🟢"
        }
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = summary[severity]
            if count > 0:
                print(f"{severity_colors[severity]} {severity.upper()}: {count} findings")
        
        print()
        
        # Print findings by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            if findings[severity]:
                print(f"\n{severity_colors[severity]} {severity.upper()} FINDINGS:")
                print("-" * 40)
                
                for i, finding in enumerate(findings[severity], 1):
                    print(f"{i}. {finding['title']}")
                    print(f"   Description: {finding['description']}")
                    if finding.get('recommendation'):
                        print(f"   Recommendation: {finding['recommendation']}")
                    print()
        
        # Print recommendations
        if summary['critical'] > 0 or summary['high'] > 0:
            print("\n🚨 IMMEDIATE ACTIONS REQUIRED:")
            print("-" * 40)
            
            for finding in findings["critical"] + findings["high"]:
                if finding.get('recommendation'):
                    print(f"• {finding['recommendation']}")
            print()
        
        print("💡 For detailed remediation steps, see the security documentation.")
        print("🔗 https://github.com/your-repo/nginx-manager/blob/main/docs/security.md")
    
    def save_report(self, filename: str = None):
        """Save audit report to JSON file."""
        if not filename:
            filename = f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.report, f, indent=2)
        
        print(f"📄 Full report saved to: {filename}")


def main():
    """Main function to run security audit."""
    audit = SecurityAudit()
    
    # Run the audit
    report = audit.run_audit()
    
    # Print the report
    audit.print_report()
    
    # Save detailed report
    audit.save_report()
    
    # Exit with appropriate code based on findings
    summary = report["summary"]
    if summary["critical"] > 0:
        sys.exit(2)  # Critical issues found
    elif summary["high"] > 0:
        sys.exit(1)  # High priority issues found
    else:
        sys.exit(0)  # No critical/high issues


if __name__ == "__main__":
    main()