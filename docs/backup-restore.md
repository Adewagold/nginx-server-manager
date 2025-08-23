# Backup and Restore Guide

Comprehensive guide for backing up, restoring, and managing data in Nginx Site Manager, including automated backups, disaster recovery, and migration procedures.

## Table of Contents

- [Overview](#overview)
- [Backup Types](#backup-types)
- [Automated Backups](#automated-backups)
- [Manual Backups](#manual-backups)
- [Restore Procedures](#restore-procedures)
- [Migration Guide](#migration-guide)
- [Disaster Recovery](#disaster-recovery)
- [Backup Security](#backup-security)
- [Troubleshooting](#troubleshooting)

## Overview

Nginx Site Manager supports multiple backup strategies to protect your configuration, website files, SSL certificates, and database from data loss.

### What Gets Backed Up

**Core Data**:
- Site configurations and settings
- SQLite database with site metadata
- Nginx configuration files
- Website files and directories
- SSL certificates and keys
- Application configuration

**Optional Data**:
- System logs
- Application logs
- Backup history
- Temporary files

### Backup Storage Locations

```
Backups Directory Structure:
├── data/backups/
│   ├── automatic/           # Automated backups
│   ├── manual/             # Manual backups
│   ├── migration/          # Migration exports
│   └── disaster-recovery/  # DR backups
└── /tmp/nginx-manager-backups/  # Temporary backups
```

## Backup Types

### 1. Configuration Backup

Backs up application configuration and site settings:

```bash
# Manual configuration backup
python3 -c "
from app.services.backup_service import BackupService
backup = BackupService()
result = backup.create_config_backup()
print(f'Backup created: {result[\"backup_path\"]}')
"
```

**Contents**:
- `config.yaml` - Application configuration
- `data/sites.db` - Site database
- Generated nginx configs
- SSL certificate configurations

### 2. Full System Backup

Complete backup of all application data:

```bash
# Full backup via web interface
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/backup/create \
  -d '{"type": "full", "include_files": true}'
```

**Contents**:
- All configuration backup items
- Website files and directories
- SSL certificates and private keys
- Application logs (optional)

### 3. Site-Specific Backup

Backup individual sites:

```bash
# Site-specific backup
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/backup/sites/1/create
```

**Contents**:
- Site configuration
- Website files for the specific site
- Site-specific nginx configuration
- SSL certificate for the domain

### 4. Migration Backup

Special backup format for migrating between servers:

```bash
# Migration export
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/backup/export \
  -d '{"format": "migration", "encrypt": true}'
```

**Contents**:
- All data in portable format
- Migration scripts
- Dependency information
- Configuration mapping

## Automated Backups

### Configuration

Configure automated backups in `config.yaml`:

```yaml
backup:
  enabled: true
  schedule: "0 2 * * *"           # Daily at 2 AM (cron format)
  retention_days: 30              # Keep backups for 30 days
  max_backups: 50                 # Maximum number of backups to keep
  
  # Backup content options
  include_files: true             # Include website files
  include_ssl: false              # Include SSL certificates (security risk)
  include_logs: false             # Include log files
  compress: true                  # Compress backup files
  
  # Storage options
  local_storage: true
  storage_path: "./data/backups/automatic"
  
  # Remote storage (optional)
  remote_storage:
    enabled: false
    type: "s3"                    # s3, ftp, rsync
    config:
      bucket: "nginx-manager-backups"
      region: "us-east-1"
      access_key: "your-access-key"
      secret_key: "your-secret-key"
      path: "backups/"
  
  # Notification options
  notifications:
    email: "admin@yourdomain.com"
    on_success: false             # Notify on successful backup
    on_failure: true              # Notify on backup failure
```

### Setting Up Automated Backups

**Method 1: Using systemd timer** (recommended)

```bash
# Create backup service
sudo tee /etc/systemd/system/nginx-manager-backup.service > /dev/null <<EOF
[Unit]
Description=Nginx Site Manager Backup
After=nginx-manager.service

[Service]
Type=oneshot
User=$(whoami)
Group=www-data
WorkingDirectory=/path/to/nginx-manager
Environment=PATH=/path/to/nginx-manager/venv/bin
ExecStart=/path/to/nginx-manager/venv/bin/python -c "from app.services.backup_service import BackupService; BackupService().create_scheduled_backup()"
EOF

# Create backup timer
sudo tee /etc/systemd/system/nginx-manager-backup.timer > /dev/null <<EOF
[Unit]
Description=Nginx Site Manager Backup Timer
Requires=nginx-manager-backup.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start timer
sudo systemctl daemon-reload
sudo systemctl enable nginx-manager-backup.timer
sudo systemctl start nginx-manager-backup.timer

# Check timer status
sudo systemctl list-timers nginx-manager-backup.timer
```

**Method 2: Using crontab**

```bash
# Edit crontab
crontab -e

# Add backup job (daily at 2 AM)
0 2 * * * cd /path/to/nginx-manager && ./venv/bin/python -c "from app.services.backup_service import BackupService; BackupService().create_scheduled_backup()" >> /var/log/nginx-manager/backup.log 2>&1
```

### Backup Monitoring

Monitor backup status and health:

```bash
#!/bin/bash
# Backup monitoring script

BACKUP_DIR="/path/to/nginx-manager/data/backups/automatic"
LOG_FILE="/var/log/nginx-manager/backup.log"

# Check if backup ran in last 25 hours
LAST_BACKUP=$(find "$BACKUP_DIR" -name "*.tar.gz" -mtime -1 | head -1)

if [ -z "$LAST_BACKUP" ]; then
    echo "WARNING: No backup found in last 24 hours"
    exit 1
fi

# Check backup size (should be reasonable)
BACKUP_SIZE=$(stat -c%s "$LAST_BACKUP")
if [ "$BACKUP_SIZE" -lt 1000 ]; then
    echo "WARNING: Backup file suspiciously small: $BACKUP_SIZE bytes"
    exit 1
fi

# Check for errors in log
if tail -100 "$LOG_FILE" | grep -i error; then
    echo "WARNING: Errors found in backup log"
    exit 1
fi

echo "Backup status: OK"
echo "Last backup: $(basename "$LAST_BACKUP")"
echo "Size: $(du -h "$LAST_BACKUP" | cut -f1)"
```

## Manual Backups

### Web Interface

Create backups through the web interface:

1. **Navigate to Settings** → **Backup & Restore**
2. **Choose backup type**:
   - Configuration only
   - Full backup
   - Site-specific backup
3. **Configure options**:
   - Include website files
   - Include SSL certificates
   - Compression
4. **Click "Create Backup"**
5. **Download backup file**

### Command Line

Create backups via CLI:

```bash
#!/bin/bash
# Manual backup script

BACKUP_DIR="./data/backups/manual"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="nginx-manager-backup-$TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Configuration backup
echo "Creating configuration backup..."
tar -czf "$BACKUP_DIR/$BACKUP_NAME-config.tar.gz" \
    config.yaml \
    data/sites.db \
    app/templates/nginx/

# Website files backup
echo "Creating website files backup..."
if [ -d "/var/www" ]; then
    tar -czf "$BACKUP_DIR/$BACKUP_NAME-files.tar.gz" -C /var/www .
fi

# SSL certificates backup (optional - security risk)
read -p "Include SSL certificates? (y/N): " include_ssl
if [[ $include_ssl =~ ^[Yy]$ ]]; then
    echo "Creating SSL backup..."
    tar -czf "$BACKUP_DIR/$BACKUP_NAME-ssl.tar.gz" -C "$HOME" .letsencrypt/
fi

# Combined backup
echo "Creating combined backup..."
tar -czf "$BACKUP_DIR/$BACKUP_NAME-full.tar.gz" \
    config.yaml \
    data/ \
    app/templates/nginx/ \
    /var/www/ \
    --exclude="data/backups" \
    --exclude="*.log"

echo "Backup completed: $BACKUP_DIR/$BACKUP_NAME-full.tar.gz"
echo "Size: $(du -h "$BACKUP_DIR/$BACKUP_NAME-full.tar.gz" | cut -f1)"
```

### API Backup

Create backups programmatically:

```python
#!/usr/bin/env python3
import requests
import json
from datetime import datetime

class BackupManager:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}"}
    
    def create_full_backup(self, include_files=True, include_ssl=False):
        """Create a full system backup"""
        data = {
            "type": "full",
            "include_files": include_files,
            "include_ssl": include_ssl,
            "compress": True
        }
        
        response = requests.post(
            f"{self.base_url}/api/backup/create",
            headers=self.headers,
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['data']['backup_path']
        else:
            raise Exception(f"Backup failed: {response.text}")
    
    def create_site_backup(self, site_id):
        """Create backup for specific site"""
        response = requests.post(
            f"{self.base_url}/api/backup/sites/{site_id}/create",
            headers=self.headers
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['data']['backup_path']
        else:
            raise Exception(f"Site backup failed: {response.text}")
    
    def list_backups(self):
        """List all available backups"""
        response = requests.get(
            f"{self.base_url}/api/backup/list",
            headers=self.headers
        )
        
        if response.status_code == 200:
            return response.json()['data']['backups']
        else:
            raise Exception(f"Failed to list backups: {response.text}")

# Usage example
if __name__ == "__main__":
    # Login first to get token
    login_response = requests.post(
        "http://localhost:8080/auth/login",
        data={"username": "admin", "password": "your-password"}
    )
    token = login_response.json()["access_token"]
    
    # Create backup manager
    backup_manager = BackupManager("http://localhost:8080", token)
    
    # Create full backup
    backup_path = backup_manager.create_full_backup(
        include_files=True,
        include_ssl=False
    )
    
    print(f"Backup created: {backup_path}")
    
    # List all backups
    backups = backup_manager.list_backups()
    print(f"Total backups: {len(backups)}")
```

## Restore Procedures

### Pre-Restore Checklist

Before restoring from backup:

1. **Stop services**:
   ```bash
   sudo systemctl stop nginx-manager
   sudo systemctl stop nginx
   ```

2. **Create current state backup**:
   ```bash
   tar -czf "current-state-$(date +%Y%m%d_%H%M%S).tar.gz" \
       config.yaml data/ /var/www/
   ```

3. **Verify backup integrity**:
   ```bash
   # Test backup file
   tar -tzf backup-file.tar.gz > /dev/null && echo "Backup OK" || echo "Backup corrupted"
   ```

### Configuration Restore

Restore application configuration:

```bash
#!/bin/bash
# Configuration restore script

BACKUP_FILE="$1"
RESTORE_DIR="/tmp/restore-$(date +%Y%m%d_%H%M%S)"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

# Extract backup
echo "Extracting backup..."
mkdir -p "$RESTORE_DIR"
tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

# Stop services
echo "Stopping services..."
sudo systemctl stop nginx-manager nginx

# Backup current configuration
echo "Backing up current configuration..."
cp config.yaml config.yaml.backup.$(date +%Y%m%d_%H%M%S)
cp data/sites.db data/sites.db.backup.$(date +%Y%m%d_%H%M%S)

# Restore configuration
echo "Restoring configuration..."
if [ -f "$RESTORE_DIR/config.yaml" ]; then
    cp "$RESTORE_DIR/config.yaml" ./
    echo "Configuration restored"
fi

# Restore database
if [ -f "$RESTORE_DIR/data/sites.db" ]; then
    cp "$RESTORE_DIR/data/sites.db" data/
    chown $(whoami):www-data data/sites.db
    chmod 660 data/sites.db
    echo "Database restored"
fi

# Restore nginx templates
if [ -d "$RESTORE_DIR/app/templates/nginx" ]; then
    cp -r "$RESTORE_DIR/app/templates/nginx/"* app/templates/nginx/
    echo "Nginx templates restored"
fi

# Start services
echo "Starting services..."
sudo systemctl start nginx
sudo systemctl start nginx-manager

# Verify restoration
sleep 5
if systemctl is-active --quiet nginx-manager; then
    echo "✓ Restoration completed successfully"
else
    echo "✗ Service failed to start, check logs"
    journalctl -u nginx-manager --since="5 minutes ago"
fi
```

### Full System Restore

Complete system restoration:

```bash
#!/bin/bash
# Full system restore script

BACKUP_FILE="$1"
RESTORE_DIR="/tmp/restore-$(date +%Y%m%d_%H%M%S)"

# Validation
if [ -z "$BACKUP_FILE" ] || [ ! -f "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

# Extract and validate backup
echo "Extracting backup..."
mkdir -p "$RESTORE_DIR"
tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

# Stop all services
echo "Stopping services..."
sudo systemctl stop nginx-manager nginx

# Create recovery backup
echo "Creating recovery backup..."
RECOVERY_BACKUP="recovery-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf "$RECOVERY_BACKUP" config.yaml data/ /var/www/ ~/.letsencrypt/

# Restore configuration
echo "Restoring configuration files..."
[ -f "$RESTORE_DIR/config.yaml" ] && cp "$RESTORE_DIR/config.yaml" ./
[ -f "$RESTORE_DIR/data/sites.db" ] && cp "$RESTORE_DIR/data/sites.db" data/

# Restore website files
echo "Restoring website files..."
if [ -d "$RESTORE_DIR/var/www" ]; then
    sudo rm -rf /var/www/*
    sudo cp -r "$RESTORE_DIR/var/www/"* /var/www/
    sudo chown -R $(whoami):www-data /var/www
    sudo find /var/www -type d -exec chmod 755 {} \;
    sudo find /var/www -type f -exec chmod 644 {} \;
fi

# Restore SSL certificates (if included)
if [ -d "$RESTORE_DIR/.letsencrypt" ]; then
    echo "Restoring SSL certificates..."
    rm -rf ~/.letsencrypt/*
    cp -r "$RESTORE_DIR/.letsencrypt/"* ~/.letsencrypt/
    chown -R $(whoami):www-data ~/.letsencrypt
    find ~/.letsencrypt -type d -exec chmod 755 {} \;
    find ~/.letsencrypt -type f -exec chmod 644 {} \;
fi

# Restore nginx configurations
if [ -d "$RESTORE_DIR/etc/nginx/sites-available" ]; then
    echo "Restoring nginx configurations..."
    sudo cp -r "$RESTORE_DIR/etc/nginx/sites-available/"* /etc/nginx/sites-available/
    
    # Recreate enabled site links
    sudo rm -f /etc/nginx/sites-enabled/*
    for site in /etc/nginx/sites-available/*; do
        if [ -f "$site" ]; then
            site_name=$(basename "$site")
            sudo ln -s "/etc/nginx/sites-available/$site_name" "/etc/nginx/sites-enabled/$site_name"
        fi
    done
fi

# Test nginx configuration
echo "Testing nginx configuration..."
if sudo nginx -t; then
    echo "✓ Nginx configuration valid"
else
    echo "✗ Nginx configuration invalid"
    echo "Attempting to fix..."
    # Remove problematic configs and retry
    sudo rm /etc/nginx/sites-enabled/*
    if sudo nginx -t; then
        echo "✓ Fixed by disabling site configs"
    else
        echo "✗ Nginx configuration still invalid"
    fi
fi

# Start services
echo "Starting services..."
sudo systemctl start nginx
sudo systemctl start nginx-manager

# Verify restoration
sleep 10
if systemctl is-active --quiet nginx-manager && systemctl is-active --quiet nginx; then
    echo "✓ Full restoration completed successfully"
    echo "Recovery backup saved as: $RECOVERY_BACKUP"
else
    echo "✗ Services failed to start properly"
    echo "Check logs: journalctl -u nginx-manager -u nginx --since='10 minutes ago'"
    echo "Recovery backup available: $RECOVERY_BACKUP"
fi

# Cleanup
rm -rf "$RESTORE_DIR"
```

### Site-Specific Restore

Restore individual sites:

```bash
#!/bin/bash
# Site-specific restore

BACKUP_FILE="$1"
SITE_NAME="$2"

if [ -z "$BACKUP_FILE" ] || [ -z "$SITE_NAME" ]; then
    echo "Usage: $0 <backup-file.tar.gz> <site-name>"
    exit 1
fi

RESTORE_DIR="/tmp/restore-site-$(date +%Y%m%d_%H%M%S)"

# Extract backup
mkdir -p "$RESTORE_DIR"
tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

# Restore site files
if [ -d "$RESTORE_DIR/var/www/$SITE_NAME" ]; then
    echo "Restoring files for site: $SITE_NAME"
    sudo mkdir -p "/var/www/$SITE_NAME"
    sudo cp -r "$RESTORE_DIR/var/www/$SITE_NAME/"* "/var/www/$SITE_NAME/"
    sudo chown -R $(whoami):www-data "/var/www/$SITE_NAME"
    sudo find "/var/www/$SITE_NAME" -type d -exec chmod 755 {} \;
    sudo find "/var/www/$SITE_NAME" -type f -exec chmod 644 {} \;
fi

# Restore nginx configuration
if [ -f "$RESTORE_DIR/etc/nginx/sites-available/$SITE_NAME" ]; then
    echo "Restoring nginx configuration for: $SITE_NAME"
    sudo cp "$RESTORE_DIR/etc/nginx/sites-available/$SITE_NAME" "/etc/nginx/sites-available/"
    
    # Enable site
    sudo ln -sf "/etc/nginx/sites-available/$SITE_NAME" "/etc/nginx/sites-enabled/$SITE_NAME"
    
    # Test and reload nginx
    if sudo nginx -t; then
        sudo systemctl reload nginx
        echo "✓ Site $SITE_NAME restored successfully"
    else
        echo "✗ Nginx configuration error, site not enabled"
        sudo rm "/etc/nginx/sites-enabled/$SITE_NAME"
    fi
fi

# Cleanup
rm -rf "$RESTORE_DIR"
```

## Migration Guide

### Preparing for Migration

**Pre-migration checklist**:

1. **Document current setup**:
   ```bash
   # System information
   uname -a > migration-info.txt
   lsb_release -a >> migration-info.txt
   nginx -V >> migration-info.txt
   python3 --version >> migration-info.txt
   
   # Network configuration
   ip addr show >> migration-info.txt
   ```

2. **Create migration backup**:
   ```bash
   # Special migration backup
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/backup/export \
     -d '{"format": "migration", "encrypt": false}'
   ```

3. **Export configuration**:
   ```bash
   # Export site configurations
   curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/sites/export > sites-export.json
   ```

### Server-to-Server Migration

**On source server**:

```bash
#!/bin/bash
# Migration export script

MIGRATION_DIR="migration-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$MIGRATION_DIR"

# Export application data
echo "Exporting application data..."
tar -czf "$MIGRATION_DIR/app-data.tar.gz" \
    config.yaml \
    data/ \
    app/templates/nginx/ \
    --exclude="data/backups" \
    --exclude="*.log"

# Export website files
echo "Exporting website files..."
if [ -d "/var/www" ]; then
    tar -czf "$MIGRATION_DIR/web-files.tar.gz" -C /var/www .
fi

# Export SSL certificates
echo "Exporting SSL certificates..."
if [ -d "$HOME/.letsencrypt" ]; then
    tar -czf "$MIGRATION_DIR/ssl-certs.tar.gz" -C "$HOME" .letsencrypt/
fi

# Export nginx configurations
echo "Exporting nginx configurations..."
sudo tar -czf "$MIGRATION_DIR/nginx-configs.tar.gz" \
    -C /etc/nginx sites-available/ sites-enabled/

# Create migration script
cat > "$MIGRATION_DIR/migrate.sh" << 'EOF'
#!/bin/bash
# Migration import script

echo "Starting migration import..."

# Extract files
tar -xzf app-data.tar.gz
tar -xzf web-files.tar.gz -C /var/www/
tar -xzf ssl-certs.tar.gz -C "$HOME"/
sudo tar -xzf nginx-configs.tar.gz -C /etc/nginx/

# Fix permissions
sudo chown -R $(whoami):www-data /var/www
sudo chown -R $(whoami):www-data ~/.letsencrypt
sudo chown -R root:root /etc/nginx/sites-available
sudo chown -R root:root /etc/nginx/sites-enabled

# Set permissions
sudo find /var/www -type d -exec chmod 755 {} \;
sudo find /var/www -type f -exec chmod 644 {} \;
sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
sudo find ~/.letsencrypt -type f -exec chmod 644 {} \;

# Test nginx
sudo nginx -t && sudo systemctl reload nginx

echo "Migration import completed"
EOF

chmod +x "$MIGRATION_DIR/migrate.sh"

# Create migration package
tar -czf "migration-package-$(date +%Y%m%d_%H%M%S).tar.gz" "$MIGRATION_DIR/"

echo "Migration package created: migration-package-*.tar.gz"
```

**On destination server**:

```bash
#!/bin/bash
# Migration import

MIGRATION_PACKAGE="$1"

if [ -z "$MIGRATION_PACKAGE" ]; then
    echo "Usage: $0 <migration-package.tar.gz>"
    exit 1
fi

# Stop services
sudo systemctl stop nginx-manager nginx

# Extract migration package
tar -xzf "$MIGRATION_PACKAGE"
cd migration-*/

# Run migration script
./migrate.sh

# Start services
sudo systemctl start nginx nginx-manager

# Verify migration
sleep 5
if systemctl is-active --quiet nginx-manager; then
    echo "✓ Migration completed successfully"
else
    echo "✗ Migration failed, check logs"
    journalctl -u nginx-manager --since="5 minutes ago"
fi
```

### Cloud Migration

**AWS S3 Migration**:

```bash
#!/bin/bash
# Cloud migration using AWS S3

S3_BUCKET="nginx-manager-migration"
MIGRATION_ID="migration-$(date +%Y%m%d_%H%M%S)"

# Create migration backup
echo "Creating migration backup..."
tar -czf "$MIGRATION_ID.tar.gz" \
    config.yaml data/ /var/www/ ~/.letsencrypt/ \
    --exclude="data/backups"

# Upload to S3
echo "Uploading to S3..."
aws s3 cp "$MIGRATION_ID.tar.gz" "s3://$S3_BUCKET/"

# Create download script for destination
cat > download-migration.sh << EOF
#!/bin/bash
# Download migration from S3
aws s3 cp "s3://$S3_BUCKET/$MIGRATION_ID.tar.gz" ./
echo "Migration downloaded: $MIGRATION_ID.tar.gz"
EOF

echo "Migration uploaded to S3: $MIGRATION_ID.tar.gz"
echo "Use download-migration.sh on destination server"
```

## Disaster Recovery

### Disaster Recovery Plan

**RTO (Recovery Time Objective)**: 4 hours
**RPO (Recovery Point Objective)**: 24 hours

### DR Procedures

**Phase 1: Assessment**
1. Assess damage and determine recovery scope
2. Identify available backups
3. Set up temporary infrastructure if needed

**Phase 2: Infrastructure Recovery**
```bash
#!/bin/bash
# Disaster recovery - Infrastructure setup

# Install base system requirements
sudo apt update
sudo apt install -y nginx python3 python3-pip python3-venv git

# Create application user
sudo useradd -m -s /bin/bash nginx-manager
sudo usermod -a -G www-data nginx-manager

# Setup directories
sudo mkdir -p /var/www /var/log/nginx-manager
sudo chown nginx-manager:www-data /var/www /var/log/nginx-manager
```

**Phase 3: Application Recovery**
```bash
#!/bin/bash
# Disaster recovery - Application restoration

BACKUP_FILE="$1"
RESTORE_DIR="/tmp/dr-restore"

# Extract latest backup
mkdir -p "$RESTORE_DIR"
tar -xzf "$BACKUP_FILE" -C "$RESTORE_DIR"

# Install application
git clone https://github.com/your-repo/nginx-manager.git /opt/nginx-manager
cd /opt/nginx-manager

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Restore configuration and data
cp "$RESTORE_DIR/config.yaml" ./
cp -r "$RESTORE_DIR/data/" ./
cp -r "$RESTORE_DIR/var/www/"* /var/www/
cp -r "$RESTORE_DIR/.letsencrypt" "$HOME"/

# Fix permissions
sudo chown -R nginx-manager:www-data /var/www ~/.letsencrypt ./data
sudo find /var/www -type d -exec chmod 755 {} \;
sudo find /var/www -type f -exec chmod 644 {} \;

# Setup systemd service
sudo cp nginx-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nginx-manager
sudo systemctl start nginx-manager

# Restore nginx configurations
sudo cp -r "$RESTORE_DIR/etc/nginx/sites-available/"* /etc/nginx/sites-available/
sudo cp -r "$RESTORE_DIR/etc/nginx/sites-enabled/"* /etc/nginx/sites-enabled/

# Test and start nginx
sudo nginx -t && sudo systemctl start nginx

echo "Disaster recovery completed"
```

### DR Testing

**Monthly DR Test**:
```bash
#!/bin/bash
# Disaster recovery test script

echo "Starting DR test..."

# Create test environment
TEST_DIR="/tmp/dr-test-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TEST_DIR"

# Get latest backup
LATEST_BACKUP=$(ls -t data/backups/automatic/*.tar.gz | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    echo "ERROR: No backup found for testing"
    exit 1
fi

echo "Testing backup: $LATEST_BACKUP"

# Test backup integrity
if ! tar -tzf "$LATEST_BACKUP" > /dev/null; then
    echo "ERROR: Backup file is corrupted"
    exit 1
fi

# Extract backup
tar -xzf "$LATEST_BACKUP" -C "$TEST_DIR"

# Validate backup contents
REQUIRED_FILES=(
    "config.yaml"
    "data/sites.db"
    "app/templates/nginx"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -e "$TEST_DIR/$file" ]; then
        echo "ERROR: Required file missing from backup: $file"
        exit 1
    fi
done

echo "✓ DR test passed - backup is valid"
echo "Backup size: $(du -h "$LATEST_BACKUP" | cut -f1)"
echo "Backup contents:"
tar -tzf "$LATEST_BACKUP" | head -20

# Cleanup
rm -rf "$TEST_DIR"
```

## Backup Security

### Encryption

Encrypt sensitive backups:

```bash
#!/bin/bash
# Encrypted backup creation

BACKUP_FILE="backup-$(date +%Y%m%d_%H%M%S).tar.gz"
ENCRYPTED_FILE="$BACKUP_FILE.enc"
ENCRYPTION_KEY="your-encryption-key"

# Create backup
tar -czf "$BACKUP_FILE" config.yaml data/ /var/www/

# Encrypt backup
openssl enc -aes-256-cbc -salt -in "$BACKUP_FILE" -out "$ENCRYPTED_FILE" -k "$ENCRYPTION_KEY"

# Remove unencrypted backup
rm "$BACKUP_FILE"

echo "Encrypted backup created: $ENCRYPTED_FILE"
```

**Decrypt backup**:
```bash
#!/bin/bash
# Decrypt backup

ENCRYPTED_FILE="$1"
ENCRYPTION_KEY="your-encryption-key"
DECRYPTED_FILE="${ENCRYPTED_FILE%.enc}"

openssl enc -aes-256-cbc -d -in "$ENCRYPTED_FILE" -out "$DECRYPTED_FILE" -k "$ENCRYPTION_KEY"

echo "Backup decrypted: $DECRYPTED_FILE"
```

### Backup Verification

Verify backup integrity:

```bash
#!/bin/bash
# Backup verification script

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

echo "Verifying backup: $BACKUP_FILE"

# Check file exists and is readable
if [ ! -r "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found or not readable"
    exit 1
fi

# Check file is not empty
if [ ! -s "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file is empty"
    exit 1
fi

# Test archive integrity
if ! tar -tzf "$BACKUP_FILE" > /dev/null 2>&1; then
    echo "ERROR: Backup archive is corrupted"
    exit 1
fi

# Check required files exist in backup
REQUIRED_FILES=(
    "./config.yaml"
    "./data/sites.db"
)

for file in "${REQUIRED_FILES[@]}"; do
    if ! tar -tzf "$BACKUP_FILE" | grep -q "^$file$"; then
        echo "WARNING: Required file not found in backup: $file"
    fi
done

# Check backup size is reasonable
SIZE=$(stat -c%s "$BACKUP_FILE")
if [ "$SIZE" -lt 1000 ]; then
    echo "WARNING: Backup size suspiciously small: $SIZE bytes"
elif [ "$SIZE" -gt 1000000000 ]; then
    echo "WARNING: Backup size suspiciously large: $SIZE bytes"
fi

echo "✓ Backup verification completed"
echo "Archive size: $(du -h "$BACKUP_FILE" | cut -f1)"
echo "File count: $(tar -tzf "$BACKUP_FILE" | wc -l)"
```

## Troubleshooting

### Common Backup Issues

**Backup fails with permission error**:
```bash
# Fix backup directory permissions
sudo chown -R $(whoami):www-data ./data/backups
chmod 755 ./data/backups
```

**Backup is too large**:
```bash
# Exclude large directories
tar --exclude='*.log' --exclude='data/backups' --exclude='node_modules' \
    -czf backup.tar.gz config.yaml data/ /var/www/
```

**Backup fails to complete**:
```bash
# Check disk space
df -h ./data/backups

# Check for file locks
lsof +D ./data/

# Check system resources
free -m
top
```

### Common Restore Issues

**Restore fails with permission errors**:
```bash
# Fix ownership and permissions
sudo chown -R $(whoami):www-data /var/www ./data
sudo find /var/www -type d -exec chmod 755 {} \;
sudo find /var/www -type f -exec chmod 644 {} \;
chmod 660 data/sites.db
```

**Services won't start after restore**:
```bash
# Check configuration
python3 -c "from app.config import load_config; load_config()"

# Check database
sqlite3 data/sites.db ".schema"

# Check nginx configuration
sudo nginx -t

# Check logs
journalctl -u nginx-manager --since="10 minutes ago"
```

**SSL certificates don't work after restore**:
```bash
# Check SSL directory permissions
sudo -u www-data test -r ~/.letsencrypt/live/example.com/fullchain.pem

# Fix SSL permissions
sudo chown -R $(whoami):www-data ~/.letsencrypt
sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
sudo find ~/.letsencrypt -type f -exec chmod 644 {} \;

# Test certificate validity
openssl x509 -in ~/.letsencrypt/live/example.com/cert.pem -text -noout
```

---

For additional information:
- [User Guide](user-guide.md) - Using backup features through web interface
- [API Documentation](api-documentation.md) - Programmatic backup/restore
- [Security Guide](security.md) - Backup security best practices
- [Troubleshooting](troubleshooting.md) - General troubleshooting guide