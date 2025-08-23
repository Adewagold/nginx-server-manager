# Installation Guide

This guide provides detailed instructions for installing Nginx Site Manager on various Linux distributions.

## Table of Contents

- [System Requirements](#system-requirements)
- [Supported Operating Systems](#supported-operating-systems)
- [Pre-Installation Checklist](#pre-installation-checklist)
- [Automated Installation](#automated-installation)
- [Manual Installation](#manual-installation)
- [Post-Installation Configuration](#post-installation-configuration)
- [Troubleshooting Installation Issues](#troubleshooting-installation-issues)
- [Uninstallation](#uninstallation)

## System Requirements

### Hardware Requirements
- **CPU**: 1+ cores (2+ recommended for production)
- **RAM**: 512MB minimum (1GB+ recommended)
- **Disk Space**: 2GB minimum (5GB+ recommended)
- **Network**: Internet connection for package installation and SSL certificates

### Software Requirements
- **Operating System**: Linux (64-bit)
- **Python**: Version 3.8 or higher
- **Nginx**: Version 1.18 or higher (will be installed if not present)
- **Sudo Access**: Required for initial installation only

### Network Requirements
- **Ports**: 
  - Port 80 (HTTP) - Required for Let's Encrypt verification
  - Port 443 (HTTPS) - Required for SSL-enabled sites
  - Port 8080 (default) - Application web interface
- **DNS**: Proper DNS configuration for domains you plan to manage
- **Firewall**: Configure to allow required ports

## Supported Operating Systems

The installer supports the following Linux distributions:

### Ubuntu/Debian Family
- **Ubuntu**: 18.04 LTS, 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Debian**: 10 (Buster), 11 (Bullseye), 12 (Bookworm)
- **Linux Mint**: 19+, 20+, 21+

### Red Hat Family
- **CentOS**: 7, 8, 9 (Stream)
- **RHEL**: 7, 8, 9
- **Rocky Linux**: 8, 9
- **AlmaLinux**: 8, 9
- **Fedora**: 35, 36, 37, 38, 39

### SUSE Family
- **openSUSE**: Leap 15.3+, Tumbleweed
- **SLES**: 15 SP3+

## Pre-Installation Checklist

Before running the installer, ensure:

1. **System is up to date**:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt upgrade -y
   
   # CentOS/RHEL/Rocky/Alma
   sudo yum update -y
   # or for newer versions
   sudo dnf update -y
   ```

2. **Sufficient disk space**:
   ```bash
   df -h
   ```

3. **Network connectivity**:
   ```bash
   ping -c 3 google.com
   ```

4. **User has sudo privileges**:
   ```bash
   sudo -l
   ```

5. **No existing nginx conflicts**:
   ```bash
   # Check if nginx is running and note current config
   systemctl status nginx
   nginx -V 2>&1 | grep -o with-[a-z_-]*
   ```

## Automated Installation

The automated installer is the recommended installation method.

### Quick Installation

1. **Download the project**:
   ```bash
   git clone https://github.com/your-username/nginx-manager.git
   cd nginx-manager
   ```

2. **Make installer executable**:
   ```bash
   chmod +x install.sh
   ```

3. **Run the installer**:
   ```bash
   ./install.sh
   ```

4. **Follow the interactive prompts**:
   - Choose installation type (Standard/Custom)
   - Configure application settings
   - Set admin credentials
   - Configure SSL directories

### Installation Options

The installer supports several installation modes:

#### Standard Installation (Recommended)
```bash
./install.sh --standard
```
- Installs all dependencies
- Uses default configuration
- Sets up systemd service
- Configures SSL directories

#### Custom Installation
```bash
./install.sh --custom
```
- Interactive configuration
- Custom paths and settings
- Advanced nginx configuration
- Custom SSL setup

#### Development Installation
```bash
./install.sh --dev
```
- Development-friendly setup
- Debug logging enabled
- No systemd service
- Manual startup

### Command Line Options

```bash
./install.sh [OPTIONS]

Options:
  --standard          Standard installation with defaults
  --custom            Custom installation with prompts
  --dev               Development installation
  --config FILE       Use custom config file
  --port PORT         Set application port (default: 8080)
  --no-ssl           Skip SSL directory setup
  --no-service       Don't create systemd service
  --backup           Create backup before installation
  --dry-run          Show what would be installed
  --help             Show this help message
```

### Installation Logs

The installer creates detailed logs for troubleshooting:
- **Installation log**: `/tmp/nginx-manager-install-YYYYMMDD_HHMMSS.log`
- **System changes log**: `/tmp/nginx-manager-system-changes.log`

## Manual Installation

For advanced users or custom deployments:

### Step 1: Install System Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y nginx python3 python3-pip python3-venv \
                    certbot python3-certbot-nginx sqlite3 \
                    curl wget git
```

#### CentOS/RHEL/Rocky/Alma:
```bash
# Enable EPEL repository
sudo yum install -y epel-release
# Install packages
sudo yum install -y nginx python3 python3-pip python3-venv \
                   certbot python3-certbot-nginx sqlite \
                   curl wget git
```

#### Fedora:
```bash
sudo dnf install -y nginx python3 python3-pip python3-venv \
                    python3-certbot python3-certbot-nginx \
                    sqlite curl wget git
```

### Step 2: Download and Setup Application

```bash
# Clone repository
git clone https://github.com/your-username/nginx-manager.git
cd nginx-manager

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure SSL Directories

```bash
# Create SSL directories
mkdir -p ~/.letsencrypt/{live,work,logs,renewal}

# Set proper permissions
sudo chown -R $(whoami):www-data ~/.letsencrypt
sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;

# Create test file for permission validation
touch ~/.letsencrypt/test_file
sudo chown $(whoami):www-data ~/.letsencrypt/test_file
sudo chmod 644 ~/.letsencrypt/test_file
```

### Step 4: Configure Application

```bash
# Copy configuration template
cp config.yaml.example config.yaml

# Edit configuration
nano config.yaml
```

### Step 5: Initialize Database

```bash
# Initialize SQLite database
python -c "from app.models import init_database; init_database()"
```

### Step 6: Configure System Service (Optional)

```bash
# Create systemd service
sudo tee /etc/systemd/system/nginx-manager.service > /dev/null <<EOF
[Unit]
Description=Nginx Site Manager
After=network.target nginx.service

[Service]
Type=simple
User=$(whoami)
Group=www-data
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable nginx-manager
sudo systemctl start nginx-manager
```

### Step 7: Configure Nginx

```bash
# Ensure nginx is running
sudo systemctl enable nginx
sudo systemctl start nginx

# Test nginx configuration
sudo nginx -t
```

## Post-Installation Configuration

### Initial Setup

1. **Access the web interface**:
   ```
   http://your-server-ip:8080
   ```

2. **Login with admin credentials**:
   - Username: `admin`
   - Password: `admin123` (change immediately)

3. **Change admin password**:
   - Go to Settings → Admin Settings
   - Set a strong password

### Security Configuration

1. **Generate secure secret key**:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Update config.yaml**:
   ```yaml
   app:
     secret_key: "your-generated-secret-key"
   
   admin:
     username: "your-username"
     password: "your-secure-password"
   ```

3. **Restart the service**:
   ```bash
   sudo systemctl restart nginx-manager
   ```

### Firewall Configuration

#### UFW (Ubuntu/Debian):
```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8080/tcp  # Application
sudo ufw enable
```

#### Firewalld (CentOS/RHEL/Rocky/Alma):
```bash
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### SSL Certificate Setup

1. **Verify SSL directories**:
   ```bash
   ls -la ~/.letsencrypt/
   sudo -u www-data test -r ~/.letsencrypt/test_file && echo "Permissions OK" || echo "Permissions Error"
   ```

2. **Test Let's Encrypt**:
   ```bash
   # Dry run to test configuration
   certbot --staging --work-dir ~/.letsencrypt/work \
           --config-dir ~/.letsencrypt \
           --logs-dir ~/.letsencrypt/logs \
           certonly --webroot -w /var/www/html \
           -d yourdomain.com --dry-run
   ```

## Troubleshooting Installation Issues

### Common Issues and Solutions

#### Installation Script Fails

**Issue**: Permission denied or script won't run
```bash
# Solution: Check permissions and make executable
ls -la install.sh
chmod +x install.sh
```

**Issue**: Package installation fails
```bash
# Solution: Update package lists and retry
sudo apt update  # Ubuntu/Debian
sudo yum update   # CentOS/RHEL
```

#### Python/Pip Issues

**Issue**: Python 3.8+ not found
```bash
# Ubuntu/Debian - Install Python 3.8+
sudo apt install python3.8 python3.8-pip python3.8-venv

# CentOS/RHEL - Enable Software Collections
sudo yum install centos-release-scl
sudo yum install rh-python38
scl enable rh-python38 bash
```

**Issue**: Virtual environment creation fails
```bash
# Install venv module
sudo apt install python3-venv  # Ubuntu/Debian
sudo yum install python3-venv  # CentOS/RHEL
```

#### Nginx Issues

**Issue**: Nginx fails to start
```bash
# Check nginx status and logs
sudo systemctl status nginx
sudo journalctl -u nginx -n 20

# Common fixes:
sudo nginx -t                    # Test configuration
sudo systemctl restart nginx    # Restart service
```

**Issue**: Port 80/443 already in use
```bash
# Find what's using the ports
sudo lsof -i :80
sudo lsof -i :443

# Stop conflicting services if necessary
sudo systemctl stop apache2  # If Apache is running
```

#### SSL Permission Issues

**Issue**: SSL certificates can't be read
```bash
# Fix permissions
sudo chown -R $(whoami):www-data ~/.letsencrypt
sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;

# Test permissions
sudo -u www-data test -r ~/.letsencrypt/test_file
```

#### Database Issues

**Issue**: Database initialization fails
```bash
# Create data directory
mkdir -p data

# Set permissions
chmod 755 data

# Reinitialize database
rm -f data/sites.db
python -c "from app.models import init_database; init_database()"
```

### Getting Help

If installation issues persist:

1. **Check logs**:
   ```bash
   # Installation log
   cat /tmp/nginx-manager-install-*.log
   
   # System journal
   sudo journalctl -u nginx-manager -n 50
   ```

2. **Run diagnostic script**:
   ```bash
   # Create a diagnostic report
   ./install.sh --diagnose
   ```

3. **Manual verification**:
   ```bash
   # Check all components
   python3 --version
   nginx -v
   systemctl status nginx
   systemctl status nginx-manager
   ```

## Uninstallation

To completely remove Nginx Site Manager:

```bash
# Run the uninstall script
chmod +x uninstall.sh
./uninstall.sh
```

The uninstaller provides three options:
1. **Application only** - Remove just the app, keep configs
2. **Application + configs** - Remove app and generated configs  
3. **Full uninstall** - Remove everything including system packages

Backups are automatically created during uninstallation in `/tmp/nginx-manager-uninstall-backup-TIMESTAMP/`.

---

For additional help, see the [Troubleshooting Guide](troubleshooting.md) or [User Guide](user-guide.md).