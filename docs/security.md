# Security Guide

Comprehensive security guide for hardening and securing your Nginx Site Manager deployment, including best practices, threat mitigation, and security configurations.

## Table of Contents

- [Security Overview](#security-overview)
- [Initial Security Setup](#initial-security-setup)
- [Authentication & Authorization](#authentication--authorization)
- [Network Security](#network-security)
- [File System Security](#file-system-security)
- [SSL/TLS Configuration](#ssltls-configuration)
- [Input Validation & Sanitization](#input-validation--sanitization)
- [Logging & Monitoring](#logging--monitoring)
- [Security Hardening](#security-hardening)
- [Incident Response](#incident-response)

## Security Overview

Nginx Site Manager implements multiple layers of security controls to protect against common web application vulnerabilities and system-level attacks.

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Layers                          │
├─────────────────────────────────────────────────────────────┤
│ 1. Network Layer       │ Firewall, Rate Limiting, HTTPS    │
│ 2. Application Layer   │ Authentication, Authorization      │
│ 3. Input Validation    │ Sanitization, Type Checking       │
│ 4. File System Layer  │ Permissions, Path Validation       │
│ 5. Database Layer     │ SQL Injection Prevention           │
│ 6. Infrastructure     │ System Hardening, Updates          │
└─────────────────────────────────────────────────────────────┘
```

### Threat Model

**Primary Threats Addressed**:
- Unauthorized access to admin interface
- File upload vulnerabilities
- Directory traversal attacks
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- SQL injection attacks
- SSL/TLS vulnerabilities
- Privilege escalation
- Information disclosure

## Initial Security Setup

### Change Default Credentials

**Critical**: Change admin credentials immediately after installation.

```bash
# Edit configuration file
nano config.yaml

# Update admin section
admin:
  username: "secure-admin-name"  # Don't use "admin"
  password: "complex-secure-password"
  email: "admin@yourdomain.com"
```

**Password Requirements**:
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- No dictionary words
- No personal information

**Generate Secure Password**:
```bash
# Method 1: Using OpenSSL
openssl rand -base64 32

# Method 2: Using Python
python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16)))"

# Method 3: Using pwgen
pwgen -s 16 1
```

### Generate Secure Secret Key

**Critical**: Use a cryptographically secure secret key.

```bash
# Generate secure secret key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Update config.yaml
app:
  secret_key: "your-generated-secret-key"
```

### Configure SSL/HTTPS

**Critical**: Always use HTTPS in production.

```yaml
# Force HTTPS redirects
security:
  force_https: true
  hsts_max_age: 31536000  # 1 year
  hsts_include_subdomains: true
```

## Authentication & Authorization

### JWT Token Security

Configure secure JWT token settings:

```yaml
security:
  access_token_expire_minutes: 30  # Short expiration
  refresh_token_expire_days: 7     # Limited refresh period
  password_hash_rounds: 12         # Strong bcrypt rounds
  max_login_attempts: 3            # Limit brute force
  lockout_duration: 15             # Account lockout (minutes)
```

### Session Management

```yaml
security:
  session_timeout: 30              # Auto-logout (minutes)
  concurrent_sessions: 1           # Limit concurrent logins
  require_reauth_for_critical: true # Re-auth for critical operations
```

### Multi-Factor Authentication (Planned)

Future versions will support 2FA/MFA:
```yaml
security:
  mfa:
    enabled: true
    type: "totp"  # Time-based OTP
    backup_codes: true
```

## Network Security

### Firewall Configuration

**Ubuntu/Debian (UFW)**:
```bash
# Reset firewall rules
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH access (change port if non-standard)
sudo ufw allow 22/tcp

# HTTP/HTTPS for SSL verification and sites
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Application port (consider restricting to specific IPs)
sudo ufw allow 8080/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status numbered
```

**CentOS/RHEL (firewalld)**:
```bash
# Check current zones
sudo firewall-cmd --get-active-zones

# Configure public zone
sudo firewall-cmd --permanent --zone=public --add-service=ssh
sudo firewall-cmd --permanent --zone=public --add-service=http
sudo firewall-cmd --permanent --zone=public --add-service=https
sudo firewall-cmd --permanent --zone=public --add-port=8080/tcp

# Reload configuration
sudo firewall-cmd --reload
```

### Rate Limiting

Configure rate limiting to prevent abuse:

```yaml
security:
  rate_limit: 5                    # Requests per minute
  burst_limit: 10                  # Burst capacity
  rate_limit_by: "ip"             # Rate limit by IP
  whitelist_ips:                   # Exempt specific IPs
    - "127.0.0.1"
    - "your-admin-ip"
```

### Reverse Proxy Security

If running behind nginx or another reverse proxy:

```nginx
# /etc/nginx/sites-available/nginx-manager
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL configuration
    ssl_certificate /path/to/certificate.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req zone=api burst=10 nodelay;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### IP Whitelisting

Restrict access to specific IP addresses:

```yaml
security:
  ip_whitelist:
    enabled: true
    allowed_ips:
      - "192.168.1.0/24"    # Local network
      - "10.0.0.0/8"        # VPN network
      - "your.public.ip"    # Admin IP
    block_mode: "deny"      # deny or redirect
```

## File System Security

### File Upload Security

Configure secure file upload restrictions:

```yaml
security:
  file_uploads:
    max_file_size: 50MB             # Maximum file size
    max_files_per_upload: 10        # Batch upload limit
    allowed_extensions:             # Whitelist approach
      - "html"
      - "css"
      - "js"
      - "png"
      - "jpg"
      - "jpeg"
      - "gif"
      - "svg"
      - "ico"
      - "txt"
      - "md"
      - "json"
      - "xml"
      - "pdf"
      - "zip"
    
    blocked_extensions:             # Blacklist dangerous types
      - "php"
      - "asp"
      - "jsp"
      - "exe"
      - "bat"
      - "sh"
      - "py"
      - "rb"
      - "pl"
      - "cgi"
    
    scan_for_malware: true          # Enable virus scanning
    quarantine_suspicious: true     # Quarantine suspicious files
```

### Directory Permissions

Set secure file system permissions:

```bash
# Application directory
sudo chown -R nginx-manager:www-data /path/to/nginx-manager
sudo chmod 755 /path/to/nginx-manager
sudo chmod 644 /path/to/nginx-manager/config.yaml

# Web directories
sudo chown -R nginx-manager:www-data /var/www
sudo find /var/www -type d -exec chmod 755 {} \;
sudo find /var/www -type f -exec chmod 644 {} \;

# SSL directories
sudo chown -R nginx-manager:www-data ~/.letsencrypt
sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
sudo find ~/.letsencrypt -type f -exec chmod 644 {} \;

# Database file
sudo chown nginx-manager:www-data data/sites.db
sudo chmod 660 data/sites.db

# Logs directory
sudo chown -R nginx-manager:www-data /var/log/nginx-manager
sudo chmod 755 /var/log/nginx-manager
sudo find /var/log/nginx-manager -type f -exec chmod 644 {} \;
```

### Path Traversal Prevention

The application includes built-in path traversal protection:

```python
# Automatic validation in file operations
def validate_path(base_path, user_path):
    """Prevent directory traversal attacks"""
    # Normalize paths
    base = os.path.abspath(base_path)
    target = os.path.abspath(os.path.join(base, user_path))
    
    # Ensure target is within base directory
    if not target.startswith(base + os.sep):
        raise SecurityError("Path traversal attempt detected")
    
    return target
```

### File Content Scanning

Enable content-based security scanning:

```yaml
security:
  file_scanning:
    enabled: true
    scan_uploads: true
    scan_existing: false            # Periodic scan of existing files
    
    # Content patterns to detect
    dangerous_patterns:
      - "<?php"                     # PHP code
      - "<script"                   # JavaScript (in uploads)
      - "eval("                     # Code evaluation
      - "system("                   # System commands
      - "exec("                     # Command execution
    
    # Actions for detected threats
    on_threat_detected: "quarantine"  # quarantine, block, log
```

## SSL/TLS Configuration

### Certificate Security

Configure secure SSL certificate handling:

```yaml
ssl:
  security:
    min_key_size: 2048              # Minimum key size
    preferred_key_size: 4096        # Preferred key size
    allowed_ca: ["letsencrypt"]     # Allowed certificate authorities
    
    # Certificate validation
    verify_chain: true              # Verify certificate chain
    check_revocation: true          # Check certificate revocation
    
    # Auto-renewal security
    renewal_days_before: 30         # Renew 30 days before expiry
    backup_before_renewal: true     # Backup before renewal
```

### TLS Configuration

Secure TLS settings for nginx:

```nginx
# Strong SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/ca-cert.pem;
```

### Certificate Monitoring

Monitor certificate security:

```bash
#!/bin/bash
# Certificate monitoring script

check_cert_expiry() {
    domain=$1
    expiry_date=$(openssl x509 -in ~/.letsencrypt/live/$domain/cert.pem -noout -enddate | cut -d= -f2)
    expiry_epoch=$(date -d "$expiry_date" +%s)
    current_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    if [ $days_left -lt 30 ]; then
        echo "WARNING: Certificate for $domain expires in $days_left days"
    fi
}

# Check all certificates
for cert_dir in ~/.letsencrypt/live/*/; do
    domain=$(basename "$cert_dir")
    check_cert_expiry "$domain"
done
```

## Input Validation & Sanitization

### API Input Validation

All API inputs are validated using Pydantic models:

```python
from pydantic import BaseModel, validator, Field
from typing import Optional, List
import re

class SiteCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50, regex="^[a-zA-Z0-9-_]+$")
    domain: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., regex="^(static|proxy|load_balancer)$")
    
    @validator('domain')
    def validate_domain(cls, v):
        # Domain validation regex
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.?[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @validator('name')
    def validate_name(cls, v):
        # Prevent reserved names
        reserved = ['admin', 'api', 'www', 'mail', 'ftp']
        if v.lower() in reserved:
            raise ValueError('Reserved name not allowed')
        return v
```

### File Path Validation

Strict file path validation:

```python
def validate_file_path(path: str) -> str:
    """Validate and sanitize file paths"""
    
    # Remove null bytes
    path = path.replace('\x00', '')
    
    # Normalize path separators
    path = path.replace('\\', '/')
    
    # Remove dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
    for char in dangerous_chars:
        path = path.replace(char, '')
    
    # Prevent directory traversal
    if '..' in path or path.startswith('/'):
        raise ValueError("Invalid path: directory traversal detected")
    
    # Limit path length
    if len(path) > 255:
        raise ValueError("Path too long")
    
    return path
```

### Content Sanitization

HTML/JavaScript sanitization for file content:

```python
import html
import re

def sanitize_content(content: str, file_type: str) -> str:
    """Sanitize file content based on type"""
    
    if file_type in ['html', 'htm']:
        # Allow only safe HTML tags
        safe_tags = ['p', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
                    'a', 'img', 'ul', 'ol', 'li', 'br', 'strong', 'em']
        
        # Remove dangerous script tags
        content = re.sub(r'<script.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
        content = re.sub(r'on\w+="[^"]*"', '', content, flags=re.IGNORECASE)
        
    elif file_type in ['js', 'javascript']:
        # Scan for dangerous JavaScript patterns
        dangerous_patterns = [
            r'eval\s*\(',
            r'Function\s*\(',
            r'document\.write',
            r'document\.cookie',
            r'localStorage\.',
            r'sessionStorage\.'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                raise ValueError(f"Dangerous JavaScript pattern detected: {pattern}")
    
    return content
```

## Logging & Monitoring

### Security Event Logging

Configure comprehensive security logging:

```yaml
logging:
  security:
    enabled: true
    level: "INFO"
    format: "json"                  # Structured logging
    include_request_id: true
    
    # Security events to log
    events:
      - "login_attempt"
      - "login_success"
      - "login_failure"
      - "logout"
      - "password_change"
      - "file_upload"
      - "file_access"
      - "config_change"
      - "ssl_operation"
      - "rate_limit_exceeded"
      - "security_violation"
    
    # Log sensitive data handling
    mask_sensitive_data: true
    sensitive_fields:
      - "password"
      - "token"
      - "secret_key"
      - "private_key"
```

### Intrusion Detection

Basic intrusion detection patterns:

```python
# Security monitoring patterns
SECURITY_PATTERNS = {
    'sql_injection': [
        r"(?i)(union.*select)",
        r"(?i)(drop.*table)",
        r"(?i)(insert.*into)",
        r"(?i)('.*or.*'.*=.*')"
    ],
    'xss_attempt': [
        r"<script.*?>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe.*?>"
    ],
    'path_traversal': [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c"
    ],
    'command_injection': [
        r"[;&|`]",
        r"\$\(",
        r"`.*`"
    ]
}
```

### Log Analysis

Monitor security logs:

```bash
#!/bin/bash
# Security log monitoring script

LOG_FILE="/var/log/nginx-manager/security.log"

# Monitor for failed login attempts
echo "Failed login attempts in last hour:"
grep "login_failure" "$LOG_FILE" | grep "$(date -d '1 hour ago' +'%Y-%m-%d %H')" | wc -l

# Monitor for suspicious file uploads
echo "File uploads in last hour:"
grep "file_upload" "$LOG_FILE" | grep "$(date -d '1 hour ago' +'%Y-%m-%d %H')" | wc -l

# Monitor for rate limiting
echo "Rate limit violations:"
grep "rate_limit_exceeded" "$LOG_FILE" | tail -10

# Monitor for security violations
echo "Security violations:"
grep "security_violation" "$LOG_FILE" | tail -10
```

### SIEM Integration

Export logs to Security Information and Event Management (SIEM) systems:

```yaml
logging:
  siem:
    enabled: true
    format: "syslog"               # syslog, json, csv
    destination: "rsyslog"         # rsyslog, tcp, udp, file
    
    # For remote SIEM
    remote_host: "siem.company.com"
    remote_port: 514
    protocol: "tcp"
    
    # Include additional context
    include_system_info: true
    include_geo_location: true
```

## Security Hardening

### System-Level Hardening

**Disable unused services**:
```bash
# List running services
systemctl list-units --type=service --state=running

# Disable unused services
sudo systemctl disable apache2   # If using nginx
sudo systemctl disable sendmail  # If not needed
sudo systemctl disable telnet    # Insecure protocol
```

**Configure fail2ban**:
```bash
# Install fail2ban
sudo apt install fail2ban -y

# Create nginx-manager jail
sudo tee /etc/fail2ban/jail.d/nginx-manager.conf > /dev/null <<EOF
[nginx-manager]
enabled = true
port = 8080
logpath = /var/log/nginx-manager/access.log
maxretry = 3
bantime = 3600
findtime = 600
filter = nginx-manager

[nginx-manager-auth]
enabled = true
port = 8080
logpath = /var/log/nginx-manager/auth.log
maxretry = 3
bantime = 86400
findtime = 600
filter = nginx-manager-auth
EOF

# Create filters
sudo tee /etc/fail2ban/filter.d/nginx-manager.conf > /dev/null <<EOF
[Definition]
failregex = ^<HOST>.*"(GET|POST).*" (404|403|401) 
ignoreregex =
EOF

sudo tee /etc/fail2ban/filter.d/nginx-manager-auth.conf > /dev/null <<EOF
[Definition]
failregex = ^.*login_failure.*ip=<HOST>
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

**Configure automatic updates**:
```bash
# Ubuntu/Debian
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure unattended-upgrades

# CentOS/RHEL
sudo yum install yum-cron -y
sudo systemctl enable yum-cron
```

### Application Hardening

**Security headers middleware**:
```python
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        
        # Remove server information
        response.headers.pop("Server", None)
        
        return response

app = FastAPI()
app.add_middleware(SecurityHeadersMiddleware)
```

**Input length limits**:
```yaml
security:
  input_limits:
    max_site_name: 50
    max_domain_length: 255
    max_file_size: 100MB
    max_request_size: 10MB
    max_header_size: 8KB
    max_url_length: 2048
```

### Database Security

**SQLite security configuration**:
```python
import sqlite3

def create_secure_connection(db_path):
    conn = sqlite3.connect(
        db_path,
        timeout=30,
        check_same_thread=False
    )
    
    # Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Enable WAL mode for better concurrency
    conn.execute("PRAGMA journal_mode = WAL")
    
    # Set secure permissions
    conn.execute("PRAGMA secure_delete = ON")
    
    return conn
```

## Incident Response

### Security Incident Response Plan

**Phase 1: Detection**
1. Monitor logs for security events
2. Set up alerting for critical events
3. Regular security scans

**Phase 2: Analysis**
1. Identify nature and scope of incident
2. Preserve evidence
3. Assess impact

**Phase 3: Containment**
1. Isolate affected systems
2. Block malicious IPs
3. Revoke compromised credentials

**Phase 4: Eradication**
1. Remove malware/backdoors
2. Fix vulnerabilities
3. Update systems

**Phase 5: Recovery**
1. Restore from clean backups
2. Monitor for recurring issues
3. Gradually restore services

**Phase 6: Lessons Learned**
1. Document incident
2. Update procedures
3. Improve defenses

### Emergency Procedures

**Compromise Response Script**:
```bash
#!/bin/bash
# Emergency response script

echo "SECURITY INCIDENT RESPONSE"
echo "========================="

# 1. Stop services
echo "Stopping services..."
sudo systemctl stop nginx-manager
sudo systemctl stop nginx

# 2. Block suspicious IPs
echo "Blocking suspicious IPs..."
# Add IPs to block list
for ip in "$@"; do
    sudo ufw insert 1 deny from $ip
done

# 3. Backup current state
echo "Creating incident backup..."
timestamp=$(date +%Y%m%d_%H%M%S)
tar -czf "/tmp/incident-backup-$timestamp.tar.gz" \
    /var/log/nginx-manager/ \
    ~/.letsencrypt/ \
    data/ \
    config.yaml

# 4. Reset admin credentials
echo "Resetting admin credentials..."
python3 -c "
import secrets, string
password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$%^&*') for _ in range(16))
print(f'New admin password: {password}')
"

# 5. Generate incident report
echo "Generating incident report..."
cat > "/tmp/incident-report-$timestamp.txt" << EOF
Incident Report - $timestamp
=============================

System Information:
- Hostname: $(hostname)
- OS: $(lsb_release -d | cut -f2)
- Uptime: $(uptime)

Recent Logins:
$(last -n 10)

Active Connections:
$(ss -tuln)

Process List:
$(ps aux)

File System Changes (last 24h):
$(find /var/www -mtime -1 -type f)

EOF

echo "Incident response completed."
echo "Backup: /tmp/incident-backup-$timestamp.tar.gz"
echo "Report: /tmp/incident-report-$timestamp.txt"
```

### Recovery Procedures

**System Recovery Checklist**:
1. [ ] Verify system integrity
2. [ ] Update all packages
3. [ ] Change all passwords
4. [ ] Regenerate SSL certificates
5. [ ] Review and update security configuration
6. [ ] Restore from clean backup if needed
7. [ ] Monitor for continued compromise
8. [ ] Update security procedures

## Security Maintenance

### Regular Security Tasks

**Daily**:
- Review security logs
- Monitor failed login attempts
- Check SSL certificate status
- Verify backup integrity

**Weekly**:
- Update system packages
- Review user access
- Scan for unusual file changes
- Test backup restoration

**Monthly**:
- Security configuration review
- Penetration testing
- Update security documentation
- Security awareness training

**Quarterly**:
- Full security audit
- Update incident response procedures
- Review and test disaster recovery
- Security architecture review

### Security Monitoring Script

```bash
#!/bin/bash
# Daily security monitoring script

REPORT_FILE="/tmp/security-report-$(date +%Y%m%d).txt"

{
    echo "Daily Security Report - $(date)"
    echo "================================"
    echo
    
    echo "Failed Login Attempts:"
    journalctl -u nginx-manager --since="24 hours ago" | grep "login_failure" | wc -l
    echo
    
    echo "File Upload Activity:"
    journalctl -u nginx-manager --since="24 hours ago" | grep "file_upload" | wc -l
    echo
    
    echo "SSL Certificate Status:"
    for cert in ~/.letsencrypt/live/*/cert.pem; do
        domain=$(basename $(dirname "$cert"))
        expiry=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
        echo "  $domain: $expiry"
    done
    echo
    
    echo "System Updates Available:"
    apt list --upgradable 2>/dev/null | wc -l
    echo
    
    echo "Disk Usage:"
    df -h | grep -E '(/$|/var|/home)' | awk '{print "  " $6 ": " $5 " used"}'
    echo
    
    echo "Active Network Connections:"
    ss -tuln | grep -E ':(80|443|8080)\s' | wc -l
    echo
    
} > "$REPORT_FILE"

echo "Security report generated: $REPORT_FILE"

# Optional: Email report
# mail -s "Daily Security Report" admin@yourdomain.com < "$REPORT_FILE"
```

---

For additional security information:
- [Configuration Guide](configuration.md) - Secure configuration options
- [Troubleshooting](troubleshooting.md) - Security-related troubleshooting
- [Installation Guide](installation.md) - Secure installation procedures