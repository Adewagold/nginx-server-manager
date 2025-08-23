# Troubleshooting Guide

Comprehensive troubleshooting guide for common issues with Nginx Site Manager, including diagnostics, solutions, and prevention tips.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Installation Issues](#installation-issues)
- [Application Startup Problems](#application-startup-problems)
- [Nginx Configuration Issues](#nginx-configuration-issues)
- [SSL Certificate Problems](#ssl-certificate-problems)
- [File Management Issues](#file-management-issues)
- [Performance Problems](#performance-problems)
- [Authentication and Security](#authentication-and-security)
- [System Resource Issues](#system-resource-issues)
- [Log Analysis](#log-analysis)

## Quick Diagnostics

### System Status Check

Run this comprehensive diagnostic script to check system health:

```bash
#!/bin/bash
echo "=== Nginx Site Manager Diagnostics ==="
echo "Date: $(date)"
echo

# Check application status
echo "--- Application Status ---"
systemctl is-active nginx-manager 2>/dev/null || echo "nginx-manager service not running"
systemctl is-enabled nginx-manager 2>/dev/null || echo "nginx-manager service not enabled"

# Check nginx status
echo "--- Nginx Status ---"
systemctl is-active nginx 2>/dev/null || echo "nginx service not running"
nginx -t 2>/dev/null && echo "nginx configuration: OK" || echo "nginx configuration: ERROR"

# Check ports
echo "--- Port Status ---"
ss -tuln | grep -E ':(80|443|8080)\s'

# Check disk space
echo "--- Disk Space ---"
df -h | head -1
df -h | grep -E '(/$|/var|/home)'

# Check memory
echo "--- Memory Usage ---"
free -h

# Check SSL directories
echo "--- SSL Directory Status ---"
[ -d ~/.letsencrypt ] && echo "SSL directory exists" || echo "SSL directory missing"
[ -r ~/.letsencrypt/test_file ] && echo "SSL permissions: OK" || echo "SSL permissions: ERROR"

# Check logs
echo "--- Recent Errors ---"
journalctl -u nginx-manager --since="1 hour ago" | grep -i error | tail -5
```

### Quick Health Check

```bash
# Check if application is responding
curl -f http://localhost:8080/api/health || echo "Application not responding"

# Check nginx configuration
sudo nginx -t

# Check SSL certificate status
certbot certificates --config-dir ~/.letsencrypt
```

## Installation Issues

### Permission Denied Errors

**Issue**: Installation script fails with permission errors
```
Permission denied: /etc/nginx/sites-available
```

**Solutions**:
1. **Check sudo access**:
   ```bash
   sudo -l
   ```

2. **Run installer with proper permissions**:
   ```bash
   # Ensure script is executable
   chmod +x install.sh
   
   # Run as regular user (not root)
   ./install.sh
   ```

3. **Fix ownership issues**:
   ```bash
   # Fix nginx directory permissions
   sudo chown -R root:root /etc/nginx
   sudo chmod -R 644 /etc/nginx/sites-available
   sudo chmod 755 /etc/nginx/sites-available
   ```

### Package Installation Failures

**Issue**: System packages fail to install
```
E: Unable to locate package python3-certbot-nginx
```

**Solutions**:
1. **Update package lists**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt upgrade -y
   
   # CentOS/RHEL
   sudo yum update -y
   ```

2. **Enable required repositories**:
   ```bash
   # Ubuntu - Enable universe repository
   sudo add-apt-repository universe
   
   # CentOS/RHEL - Enable EPEL
   sudo yum install epel-release -y
   ```

3. **Manual package installation**:
   ```bash
   # Install packages individually
   sudo apt install nginx -y
   sudo apt install python3-pip -y
   sudo apt install certbot -y
   ```

### Python Environment Issues

**Issue**: Virtual environment creation fails
```
Error: No module named venv
```

**Solutions**:
1. **Install Python venv module**:
   ```bash
   # Ubuntu/Debian
   sudo apt install python3-venv -y
   
   # CentOS/RHEL
   sudo yum install python3-venv -y
   ```

2. **Use alternative Python versions**:
   ```bash
   # Try specific Python version
   python3.8 -m venv venv
   python3.9 -m venv venv
   ```

3. **Check Python installation**:
   ```bash
   python3 --version
   which python3
   python3 -m pip --version
   ```

## Application Startup Problems

### Service Won't Start

**Issue**: nginx-manager service fails to start
```
systemctl status nginx-manager
● nginx-manager.service - Nginx Site Manager
   Loaded: loaded
   Active: failed
```

**Diagnostic Steps**:
1. **Check detailed logs**:
   ```bash
   sudo journalctl -u nginx-manager -n 50
   sudo journalctl -u nginx-manager --since="1 hour ago"
   ```

2. **Test manual startup**:
   ```bash
   cd /path/to/nginx-manager
   source venv/bin/activate
   uvicorn app.main:app --host 0.0.0.0 --port 8080
   ```

3. **Check configuration**:
   ```bash
   # Validate config file
   python -c "from app.config import load_config; load_config()"
   ```

**Common Solutions**:

1. **Missing configuration file**:
   ```bash
   cp config.yaml.example config.yaml
   # Edit config.yaml with proper settings
   ```

2. **Database initialization**:
   ```bash
   cd /path/to/nginx-manager
   source venv/bin/activate
   python -c "from app.models import init_database; init_database()"
   ```

3. **Port already in use**:
   ```bash
   # Find what's using port 8080
   sudo lsof -i :8080
   
   # Kill conflicting process or change port in config.yaml
   ```

4. **Python dependencies missing**:
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Configuration Validation Errors

**Issue**: Application fails to start due to configuration errors
```
ValidationError: Invalid configuration
```

**Solutions**:
1. **Check configuration syntax**:
   ```bash
   # Validate YAML syntax
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```

2. **Compare with template**:
   ```bash
   # Check differences
   diff config.yaml.example config.yaml
   ```

3. **Reset to defaults**:
   ```bash
   # Backup current config
   cp config.yaml config.yaml.backup
   
   # Reset to template
   cp config.yaml.example config.yaml
   ```

### Database Connection Issues

**Issue**: SQLite database errors
```
sqlite3.OperationalError: database is locked
```

**Solutions**:
1. **Check database file permissions**:
   ```bash
   ls -la data/sites.db
   chmod 664 data/sites.db
   chown $(whoami):www-data data/sites.db
   ```

2. **Stop conflicting processes**:
   ```bash
   # Find processes using database
   lsof data/sites.db
   
   # Stop application
   sudo systemctl stop nginx-manager
   ```

3. **Rebuild database**:
   ```bash
   # Backup existing database
   cp data/sites.db data/sites.db.backup
   
   # Recreate database
   rm data/sites.db
   python -c "from app.models import init_database; init_database()"
   ```

## Nginx Configuration Issues

### Configuration Test Failures

**Issue**: nginx -t fails after site creation
```
nginx: [emerg] duplicate location "/" in /etc/nginx/sites-enabled/example.com
```

**Diagnostic Steps**:
1. **Test nginx configuration**:
   ```bash
   sudo nginx -t
   ```

2. **Check for conflicts**:
   ```bash
   # Look for duplicate configurations
   grep -r "server_name.*example.com" /etc/nginx/sites-enabled/
   
   # Check for duplicate locations
   grep -r "location /" /etc/nginx/sites-enabled/
   ```

3. **Validate generated configs**:
   ```bash
   # Check generated configuration
   cat /etc/nginx/sites-available/example.com
   ```

**Solutions**:
1. **Remove duplicate configurations**:
   ```bash
   # Disable conflicting site
   sudo rm /etc/nginx/sites-enabled/conflicting-site
   
   # Test configuration
   sudo nginx -t
   ```

2. **Fix configuration template**:
   ```bash
   # Edit site in web interface or manually fix config
   sudo nano /etc/nginx/sites-available/example.com
   ```

3. **Regenerate configuration**:
   ```bash
   # Delete and recreate site through web interface
   # Or manually remove and recreate config
   ```

### Nginx Won't Reload

**Issue**: nginx reload fails
```
nginx: [error] invalid PID number "" in "/var/run/nginx.pid"
```

**Solutions**:
1. **Restart nginx service**:
   ```bash
   sudo systemctl restart nginx
   ```

2. **Check nginx process**:
   ```bash
   ps aux | grep nginx
   sudo pkill nginx
   sudo systemctl start nginx
   ```

3. **Fix PID file issues**:
   ```bash
   # Remove stale PID file
   sudo rm -f /var/run/nginx.pid
   sudo systemctl restart nginx
   ```

### Site Not Accessible

**Issue**: Site returns 502 Bad Gateway or 404 errors

**Diagnostic Steps**:
1. **Check nginx error logs**:
   ```bash
   sudo tail -f /var/log/nginx/error.log
   ```

2. **Verify site is enabled**:
   ```bash
   ls -la /etc/nginx/sites-enabled/
   ```

3. **Test site configuration**:
   ```bash
   # Check if site config exists
   cat /etc/nginx/sites-available/example.com
   
   # Check if site is enabled
   ls -la /etc/nginx/sites-enabled/example.com
   ```

**Solutions**:
1. **Enable site**:
   ```bash
   # Create symlink
   sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```

2. **Check document root**:
   ```bash
   # Verify directory exists and has content
   ls -la /var/www/example.com/
   
   # Create index file if missing
   echo "<h1>It works!</h1>" | sudo tee /var/www/example.com/index.html
   ```

3. **Fix permissions**:
   ```bash
   # Fix web directory permissions
   sudo chown -R www-data:www-data /var/www/example.com
   sudo chmod -R 755 /var/www/example.com
   sudo chmod -R 644 /var/www/example.com/*
   ```

## SSL Certificate Problems

### Let's Encrypt Authentication Failure

**Issue**: SSL certificate generation fails
```
Detail: Invalid response from http://example.com/.well-known/acme-challenge/
```

**Diagnostic Steps**:
1. **Check domain DNS**:
   ```bash
   dig example.com
   nslookup example.com
   ```

2. **Test HTTP access**:
   ```bash
   curl -I http://example.com/
   wget --spider http://example.com/
   ```

3. **Check firewall**:
   ```bash
   sudo ufw status
   sudo iptables -L
   ```

**Solutions**:
1. **Verify domain points to server**:
   ```bash
   # Check if domain resolves to correct IP
   dig +short example.com
   curl -H "Host: example.com" http://YOUR_SERVER_IP/
   ```

2. **Fix firewall rules**:
   ```bash
   # Allow HTTP and HTTPS
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```

3. **Check nginx configuration**:
   ```bash
   # Ensure HTTP site exists for challenge
   sudo nginx -t
   curl http://example.com/.well-known/acme-challenge/test
   ```

4. **Manual certificate generation**:
   ```bash
   # Test with staging environment first
   certbot --staging --work-dir ~/.letsencrypt/work \
           --config-dir ~/.letsencrypt \
           --logs-dir ~/.letsencrypt/logs \
           certonly --webroot -w /var/www/example.com \
           -d example.com
   ```

### SSL Permission Issues

**Issue**: nginx can't read SSL certificates
```
nginx: [emerg] SSL_CTX_use_certificate_chain_file() failed
```

**Solutions**:
1. **Check certificate permissions**:
   ```bash
   ls -la ~/.letsencrypt/live/example.com/
   sudo -u www-data test -r ~/.letsencrypt/live/example.com/fullchain.pem
   ```

2. **Fix SSL directory permissions**:
   ```bash
   sudo chown -R $(whoami):www-data ~/.letsencrypt
   sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
   sudo find ~/.letsencrypt -type f -exec chmod 644 {} \;
   ```

3. **Test permission access**:
   ```bash
   # Create test file
   touch ~/.letsencrypt/test_file
   sudo chown $(whoami):www-data ~/.letsencrypt/test_file
   
   # Test www-data can read it
   sudo -u www-data cat ~/.letsencrypt/test_file
   ```

### Certificate Auto-Renewal Failures

**Issue**: SSL certificates not renewing automatically

**Diagnostic Steps**:
1. **Check renewal configuration**:
   ```bash
   ls -la ~/.letsencrypt/renewal/
   cat ~/.letsencrypt/renewal/example.com.conf
   ```

2. **Test manual renewal**:
   ```bash
   certbot renew --work-dir ~/.letsencrypt/work \
                --config-dir ~/.letsencrypt \
                --logs-dir ~/.letsencrypt/logs \
                --dry-run
   ```

3. **Check systemd timers**:
   ```bash
   systemctl list-timers | grep certbot
   systemctl status certbot.timer
   ```

**Solutions**:
1. **Setup renewal cron job**:
   ```bash
   # Add to crontab
   crontab -e
   
   # Add this line
   0 2 * * * certbot renew --work-dir ~/.letsencrypt/work --config-dir ~/.letsencrypt --logs-dir ~/.letsencrypt/logs --post-hook "systemctl reload nginx"
   ```

2. **Fix renewal configuration**:
   ```bash
   # Edit renewal config
   nano ~/.letsencrypt/renewal/example.com.conf
   
   # Ensure correct paths and permissions
   ```

## File Management Issues

### Upload Failures

**Issue**: File uploads fail with permission errors
```
PermissionError: [Errno 13] Permission denied: '/var/www/example.com/index.html'
```

**Solutions**:
1. **Fix web directory permissions**:
   ```bash
   sudo chown -R $(whoami):www-data /var/www/example.com
   sudo chmod -R 755 /var/www/example.com
   ```

2. **Check disk space**:
   ```bash
   df -h /var/www
   ```

3. **Verify file size limits**:
   ```bash
   # Check nginx client_max_body_size
   grep client_max_body_size /etc/nginx/sites-available/example.com
   ```

### File Editor Issues

**Issue**: Can't save files through web editor
```
Error: Failed to save file
```

**Solutions**:
1. **Check file permissions**:
   ```bash
   ls -la /var/www/example.com/index.html
   sudo chown $(whoami):www-data /var/www/example.com/index.html
   ```

2. **Verify file is writable**:
   ```bash
   test -w /var/www/example.com/index.html && echo "Writable" || echo "Not writable"
   ```

3. **Check file locks**:
   ```bash
   lsof /var/www/example.com/index.html
   ```

### Directory Access Issues

**Issue**: Can't access or list directories
```
Error: Permission denied
```

**Solutions**:
1. **Fix directory permissions**:
   ```bash
   sudo find /var/www -type d -exec chmod 755 {} \;
   sudo find /var/www -type f -exec chmod 644 {} \;
   ```

2. **Check ownership**:
   ```bash
   sudo chown -R $(whoami):www-data /var/www
   ```

## Performance Problems

### Slow Application Response

**Issue**: Web interface loads slowly or times out

**Diagnostic Steps**:
1. **Check system resources**:
   ```bash
   top
   htop
   free -m
   iostat -x 1 5
   ```

2. **Check application logs**:
   ```bash
   journalctl -u nginx-manager --since="1 hour ago" | grep -i slow
   ```

3. **Monitor database performance**:
   ```bash
   # Check database file
   ls -la data/sites.db
   
   # Monitor database locks
   sqlite3 data/sites.db "PRAGMA compile_options;"
   ```

**Solutions**:
1. **Increase system resources**:
   ```bash
   # Check memory usage
   free -h
   
   # Add swap if needed
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

2. **Optimize application configuration**:
   ```yaml
   # In config.yaml
   app:
     workers: 2  # Increase worker processes
     timeout: 60  # Increase timeout
   ```

3. **Database optimization**:
   ```bash
   # Vacuum database
   sqlite3 data/sites.db "VACUUM;"
   
   # Analyze database
   sqlite3 data/sites.db "ANALYZE;"
   ```

### High CPU Usage

**Issue**: Application consuming excessive CPU

**Solutions**:
1. **Check process tree**:
   ```bash
   ps aux --forest | grep -A5 -B5 nginx-manager
   ```

2. **Monitor with profiling**:
   ```bash
   # Use py-spy for Python profiling
   pip install py-spy
   sudo py-spy top --pid $(pgrep -f "uvicorn.*nginx-manager")
   ```

3. **Adjust worker settings**:
   ```bash
   # Edit systemd service
   sudo systemctl edit nginx-manager
   
   # Add resource limits
   [Service]
   CPUQuota=50%
   MemoryLimit=512M
   ```

## Authentication and Security

### Login Issues

**Issue**: Can't login with correct credentials
```
Error: Invalid credentials
```

**Solutions**:
1. **Verify credentials in config**:
   ```bash
   grep -A5 "admin:" config.yaml
   ```

2. **Check password encoding**:
   ```python
   # Test password verification
   python3 -c "
   from app.auth import verify_password
   print(verify_password('your-password', 'stored-hash'))
   "
   ```

3. **Reset admin credentials**:
   ```bash
   # Edit config.yaml
   nano config.yaml
   
   # Update admin section
   admin:
     username: "admin"
     password: "newpassword"
   
   # Restart service
   sudo systemctl restart nginx-manager
   ```

### Session/Token Issues

**Issue**: Frequently logged out or invalid token errors

**Solutions**:
1. **Check token configuration**:
   ```yaml
   # In config.yaml
   app:
     access_token_expire_minutes: 60  # Increase if too short
     secret_key: "your-secret-key"    # Ensure this is set
   ```

2. **Verify system time**:
   ```bash
   date
   timedatectl status
   
   # Sync time if needed
   sudo timedatectl set-ntp true
   ```

3. **Clear browser cache**:
   - Clear cookies and local storage
   - Try incognito/private browsing mode

## System Resource Issues

### Disk Space Problems

**Issue**: Out of disk space errors
```
OSError: [Errno 28] No space left on device
```

**Solutions**:
1. **Check disk usage**:
   ```bash
   df -h
   du -sh /var/www/*
   du -sh ~/.letsencrypt/*
   du -sh data/*
   ```

2. **Clean up files**:
   ```bash
   # Clean old backups
   find data/backups -name "*.tar.gz" -mtime +30 -delete
   
   # Clean logs
   journalctl --vacuum-time=7d
   
   # Clean nginx logs
   sudo find /var/log/nginx -name "*.log" -mtime +7 -delete
   ```

3. **Move large directories**:
   ```bash
   # Move web files to larger partition
   sudo mkdir /opt/www
   sudo mv /var/www/* /opt/www/
   sudo ln -s /opt/www /var/www
   ```

### Memory Issues

**Issue**: Out of memory errors or system freezing

**Solutions**:
1. **Add swap space**:
   ```bash
   # Create swap file
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   
   # Make permanent
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

2. **Limit application memory**:
   ```bash
   sudo systemctl edit nginx-manager
   
   # Add:
   [Service]
   MemoryLimit=512M
   MemoryAccounting=true
   ```

3. **Optimize database**:
   ```bash
   # Reduce database size
   sqlite3 data/sites.db "VACUUM;"
   
   # Clean old records if any
   ```

## Log Analysis

### Application Logs

**Location**: `sudo journalctl -u nginx-manager`

**Common Error Patterns**:

1. **Configuration errors**:
   ```
   ERROR: Failed to load configuration
   ```

2. **Database errors**:
   ```
   ERROR: database is locked
   ```

3. **Permission errors**:
   ```
   ERROR: Permission denied
   ```

### Nginx Logs

**Locations**: 
- `/var/log/nginx/error.log`
- `/var/log/nginx/access.log`

**Analysis commands**:
```bash
# Check for 5xx errors
grep " 5[0-9][0-9] " /var/log/nginx/access.log

# Check for SSL errors
grep -i ssl /var/log/nginx/error.log

# Monitor real-time
tail -f /var/log/nginx/error.log
```

### SSL Certificate Logs

**Location**: `~/.letsencrypt/logs/letsencrypt.log`

**Common issues**:
```bash
# Check renewal failures
grep -i "renewal.*failed" ~/.letsencrypt/logs/letsencrypt.log

# Check authentication failures
grep -i "challenge.*failed" ~/.letsencrypt/logs/letsencrypt.log
```

### System Logs

**Useful commands**:
```bash
# Check system errors
dmesg | tail -20

# Check service failures
systemctl --failed

# Check system resources
journalctl -p err --since="24 hours ago"
```

---

## Getting Help

If you're still experiencing issues after following this guide:

1. **Gather diagnostic information**:
   ```bash
   # Create a diagnostic report
   ./install.sh --diagnose > diagnostic-report.txt
   ```

2. **Check application logs**:
   ```bash
   sudo journalctl -u nginx-manager --since="1 hour ago" > app-logs.txt
   ```

3. **Document your issue**:
   - What you were trying to do
   - What happened instead
   - Error messages (exact text)
   - System information (OS, version)
   - Configuration details

4. **Submit an issue** with all diagnostic information

For more help:
- [Configuration Guide](configuration.md)
- [User Guide](user-guide.md)
- [Security Guide](security.md)
- [API Documentation](api-documentation.md)