# Configuration Guide

This guide covers all configuration options for Nginx Site Manager, from basic setup to advanced customization.

## Table of Contents

- [Configuration Overview](#configuration-overview)
- [Application Configuration](#application-configuration)
- [Admin Settings](#admin-settings)
- [Path Configuration](#path-configuration)
- [Security Settings](#security-settings)
- [Logging Configuration](#logging-configuration)
- [Nginx Integration](#nginx-integration)
- [SSL Configuration](#ssl-configuration)
- [Environment Variables](#environment-variables)
- [Advanced Configuration](#advanced-configuration)

## Configuration Overview

Nginx Site Manager uses a YAML configuration file (`config.yaml`) for all settings. The configuration is structured into logical sections for easy management.

### Configuration File Location
- **Primary**: `./config.yaml` (in application directory)
- **Template**: `./config.yaml.example`
- **Validation**: Configuration is validated on startup

### Configuration Structure
```yaml
app:           # Application core settings
admin:         # Administrator credentials
paths:         # File system paths
security:      # Security and authentication
logging:       # Logging configuration
nginx:         # Nginx integration settings
ssl:           # SSL/TLS configuration
```

## Application Configuration

### Basic Application Settings

```yaml
app:
  host: "0.0.0.0"                    # Bind address (0.0.0.0 for all interfaces)
  port: 8080                         # Application port
  secret_key: "your-secret-key"      # JWT signing key (REQUIRED)
  access_token_expire_minutes: 60    # JWT token expiry time
  debug: false                       # Debug mode (DO NOT use in production)
  reload: false                      # Auto-reload on code changes
  workers: 1                         # Number of worker processes
```

#### Host Configuration
- `0.0.0.0` - Listen on all interfaces (recommended for server deployment)
- `127.0.0.1` - Listen on localhost only (development/secure environments)
- Specific IP - Listen on specific interface only

#### Port Configuration
- Default: `8080`
- Choose non-privileged port (1024+)
- Ensure port is not used by other services
- Configure firewall to allow chosen port

#### Secret Key Generation
**CRITICAL**: Always use a strong, unique secret key in production:

```bash
# Generate secure secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Example output
nK8-9xQJmBvNzH4F2wGpE8rL6uYtRe3sA7cKjPmX1nQ
```

#### Debug Mode
```yaml
app:
  debug: false  # ALWAYS false in production
```
- **Development**: `true` - Enables detailed error messages, auto-reload
- **Production**: `false` - Minimal error exposure, better performance

### Performance Settings

```yaml
app:
  workers: 1                    # Number of worker processes
  max_connections: 1000         # Maximum concurrent connections
  timeout: 30                   # Request timeout in seconds
  keepalive_timeout: 65         # Keep-alive timeout
```

## Admin Settings

### Administrator Credentials

```yaml
admin:
  username: "admin"                  # Admin username
  password: "your-secure-password"   # Admin password (plain text in config)
  email: "admin@example.com"         # Admin email (for SSL certificates)
  require_password_change: true     # Force password change on first login
```

#### Security Best Practices
1. **Change default credentials immediately**
2. **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
3. **Consider using environment variables** for sensitive data
4. **Regularly update passwords**

#### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one number
- Special characters recommended

### Multi-Admin Support (Future)
```yaml
admin:
  multiple_admins: false        # Enable multiple admin accounts
  admins:
    - username: "admin1"
      password: "password1"
      email: "admin1@example.com"
      role: "super_admin"
    - username: "admin2"
      password: "password2"
      email: "admin2@example.com"
      role: "site_manager"
```

## Path Configuration

### System Paths

```yaml
paths:
  nginx_config_dir: "/etc/nginx/sites-available"    # Nginx config directory
  nginx_enabled_dir: "/etc/nginx/sites-enabled"     # Nginx enabled sites
  web_root: "/var/www"                               # Web files root directory
  backup_dir: "./data/backups"                      # Backup storage
  temp_dir: "/tmp"                                   # Temporary files
  log_dir: "/var/log/nginx-manager"                  # Application logs
```

#### Custom Path Configuration
```yaml
paths:
  # Custom nginx installation
  nginx_config_dir: "/usr/local/nginx/sites-available"
  nginx_enabled_dir: "/usr/local/nginx/sites-enabled"
  
  # Custom web root (must be writable)
  web_root: "/home/user/websites"
  
  # Custom backup location
  backup_dir: "/backup/nginx-manager"
```

### Path Validation
- All paths must exist or be creatable
- Application user must have appropriate permissions
- Relative paths resolved from application directory

## Security Settings

### Authentication Configuration

```yaml
security:
  access_token_expire_minutes: 60      # JWT token lifetime
  refresh_token_expire_days: 7         # Refresh token lifetime
  password_hash_rounds: 12             # bcrypt hash rounds
  session_timeout: 30                  # Session timeout (minutes)
  max_login_attempts: 5                # Max failed login attempts
  lockout_duration: 15                 # Account lockout time (minutes)
```

### Request Security

```yaml
security:
  rate_limit: 5                        # Requests per minute per IP
  max_file_size: 100                   # Max upload size (MB)
  allowed_file_types:                  # Allowed upload file types
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
  
  blocked_file_types:                  # Explicitly blocked types
    - "php"
    - "asp"
    - "jsp"
    - "exe"
    - "bat"
    - "sh"
    - "py"
    - "rb"
    - "pl"
```

### CORS Configuration

```yaml
security:
  cors_origins:                        # Allowed CORS origins
    - "http://localhost:3000"          # Development frontend
    - "https://yourdomain.com"         # Production domain
  cors_methods:                        # Allowed methods
    - "GET"
    - "POST"
    - "PUT"
    - "DELETE"
  cors_headers:                        # Allowed headers
    - "Content-Type"
    - "Authorization"
```

### Security Headers

```yaml
security:
  security_headers:
    X-Content-Type-Options: "nosniff"
    X-Frame-Options: "DENY"
    X-XSS-Protection: "1; mode=block"
    Strict-Transport-Security: "max-age=31536000; includeSubDomains"
    Content-Security-Policy: "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

## Logging Configuration

### Basic Logging

```yaml
logging:
  level: "INFO"                        # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "/var/log/nginx-manager/app.log"
  max_size: "10MB"                     # Max log file size
  backup_count: 5                      # Number of backup log files
  console: true                        # Also log to console
```

### Advanced Logging

```yaml
logging:
  structured: true                     # Enable structured JSON logging
  include_request_id: true             # Include request ID in logs
  log_requests: true                   # Log all HTTP requests
  log_sql: false                       # Log SQL queries (development only)
  sensitive_fields:                    # Fields to redact in logs
    - "password"
    - "secret_key"
    - "token"
```

### Log Rotation

```yaml
logging:
  rotation:
    enabled: true                      # Enable log rotation
    when: "midnight"                   # Rotation time
    interval: 1                        # Rotation interval
    backup_count: 30                   # Keep 30 days of logs
    compress: true                     # Compress old logs
```

## Nginx Integration

### Nginx Commands

```yaml
nginx:
  config_test_cmd: "nginx -t"          # Test configuration command
  reload_cmd: "systemctl reload nginx" # Reload nginx command
  restart_cmd: "systemctl restart nginx"
  status_cmd: "systemctl is-active nginx"
  version_cmd: "nginx -v"
```

### Custom Nginx Installation

```yaml
nginx:
  # Custom nginx binary location
  nginx_binary: "/usr/local/bin/nginx"
  
  # Custom commands for non-systemd systems
  config_test_cmd: "/usr/local/bin/nginx -t"
  reload_cmd: "/usr/local/bin/nginx -s reload"
  restart_cmd: "service nginx restart"
  status_cmd: "service nginx status"
```

### Configuration Templates

```yaml
nginx:
  templates:
    static: "app/templates/nginx/static.conf"
    proxy: "app/templates/nginx/proxy.conf"
    load_balancer: "app/templates/nginx/load_balancer.conf"
  
  # Template variables
  template_vars:
    server_tokens: "off"
    client_max_body_size: "100M"
    proxy_timeout: "60s"
```

## SSL Configuration

### Let's Encrypt Settings

```yaml
ssl:
  enabled: true                        # Enable SSL management
  email: "admin@example.com"           # Let's Encrypt email
  staging: false                       # Use staging server (for testing)
  key_size: 4096                       # Private key size
  work_dir: "~/.letsencrypt/work"      # Certbot work directory
  config_dir: "~/.letsencrypt"         # Certbot config directory
  logs_dir: "~/.letsencrypt/logs"      # Certbot logs directory
```

### Certificate Management

```yaml
ssl:
  auto_renew: true                     # Enable automatic renewal
  renew_days_before: 30                # Renew X days before expiry
  renewal_hour: 2                      # Renewal time (24-hour format)
  renewal_minute: 30                   # Renewal minute
  post_renewal_hook: "systemctl reload nginx"  # Command after renewal
```

### Advanced SSL Settings

```yaml
ssl:
  # Certificate authority settings
  ca_server: "https://acme-v02.api.letsencrypt.org/directory"  # Production
  # ca_server: "https://acme-staging-v02.api.letsencrypt.org/directory"  # Staging
  
  # Challenge settings
  challenge_type: "http-01"            # Challenge type (http-01, dns-01)
  webroot_path: "/var/www/html"        # Webroot for http-01 challenge
  
  # Certificate settings
  certificate_name_template: "{domain}"  # Certificate naming
  force_renewal: false                 # Force certificate renewal
```

## Environment Variables

Environment variables can override configuration file settings:

### Application Variables
```bash
# Application settings
NGINX_MANAGER_HOST="0.0.0.0"
NGINX_MANAGER_PORT="8080"
NGINX_MANAGER_SECRET_KEY="your-secret-key"
NGINX_MANAGER_DEBUG="false"

# Admin settings
NGINX_MANAGER_ADMIN_USERNAME="admin"
NGINX_MANAGER_ADMIN_PASSWORD="secure-password"
NGINX_MANAGER_ADMIN_EMAIL="admin@example.com"

# Database
NGINX_MANAGER_DATABASE_URL="sqlite:///data/sites.db"

# Logging
NGINX_MANAGER_LOG_LEVEL="INFO"
NGINX_MANAGER_LOG_FILE="/var/log/nginx-manager/app.log"
```

### SSL Variables
```bash
# SSL settings
NGINX_MANAGER_SSL_EMAIL="ssl@example.com"
NGINX_MANAGER_SSL_STAGING="false"
NGINX_MANAGER_SSL_WORK_DIR="/home/user/.letsencrypt/work"
NGINX_MANAGER_SSL_CONFIG_DIR="/home/user/.letsencrypt"
```

### Usage in Docker
```bash
# Docker environment file (.env)
cat > .env << EOF
NGINX_MANAGER_HOST=0.0.0.0
NGINX_MANAGER_PORT=8080
NGINX_MANAGER_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
NGINX_MANAGER_ADMIN_USERNAME=admin
NGINX_MANAGER_ADMIN_PASSWORD=your-secure-password
EOF

# Use with docker-compose
docker-compose --env-file .env up -d
```

## Advanced Configuration

### Database Configuration

```yaml
database:
  url: "sqlite:///data/sites.db"      # Database connection URL
  pool_size: 5                        # Connection pool size
  max_overflow: 10                    # Max overflow connections
  pool_timeout: 30                    # Pool timeout seconds
  pool_recycle: 3600                  # Recycle connections after X seconds
  echo: false                         # Log SQL queries
```

### Backup Configuration

```yaml
backup:
  enabled: true                       # Enable automatic backups
  schedule: "0 2 * * *"               # Backup schedule (cron format)
  retention_days: 30                  # Keep backups for X days
  include_files: true                 # Include website files in backup
  include_configs: true               # Include nginx configs in backup
  include_ssl: false                  # Include SSL certificates (not recommended)
  compression: true                   # Compress backup files
  remote_backup:
    enabled: false                    # Enable remote backup
    type: "s3"                        # Remote backup type
    config:
      bucket: "nginx-manager-backups"
      region: "us-east-1"
      access_key: "your-access-key"
      secret_key: "your-secret-key"
```

### Monitoring Configuration

```yaml
monitoring:
  enabled: true                       # Enable monitoring endpoints
  health_check_interval: 30           # Health check interval (seconds)
  metrics_enabled: true               # Enable metrics collection
  metrics_endpoint: "/metrics"        # Prometheus metrics endpoint
  
  # Health check settings
  checks:
    database: true                    # Check database connectivity
    nginx: true                       # Check nginx status
    ssl_expiry: true                  # Check SSL certificate expiry
    disk_space: true                  # Check disk space
    memory_usage: true                # Check memory usage
  
  # Alerting (future feature)
  alerts:
    enabled: false
    email_notifications: true
    webhook_url: "https://hooks.slack.com/..."
```

### Integration Configuration

```yaml
integrations:
  # Cloudflare integration
  cloudflare:
    enabled: false
    api_token: "your-api-token"
    zone_id: "your-zone-id"
    
  # Webhook notifications
  webhooks:
    site_created: "https://your-webhook-url/site-created"
    ssl_renewed: "https://your-webhook-url/ssl-renewed"
    
  # External monitoring
  uptime_monitoring:
    enabled: false
    service: "uptimerobot"  # uptimerobot, pingdom, etc.
    api_key: "your-api-key"
```

## Configuration Validation

### Validation on Startup
The application validates all configuration settings on startup:

```bash
# Test configuration without starting
python -c "from app.config import load_config; load_config()"
```

### Configuration Schema
Configuration follows a strict schema with:
- **Required fields**: Must be present
- **Optional fields**: Have default values
- **Type validation**: Ensures correct data types
- **Value validation**: Checks valid ranges/formats

### Common Validation Errors

1. **Missing secret key**:
   ```
   Error: app.secret_key is required
   Solution: Generate and set a secret key
   ```

2. **Invalid path**:
   ```
   Error: paths.nginx_config_dir does not exist
   Solution: Create directory or fix path
   ```

3. **Invalid port**:
   ```
   Error: app.port must be between 1024-65535
   Solution: Use valid port number
   ```

### Configuration Backup

Always backup your configuration before making changes:

```bash
# Backup current configuration
cp config.yaml config.yaml.backup.$(date +%Y%m%d_%H%M%S)

# Validate new configuration
python -c "from app.config import load_config; load_config()"

# Restore if needed
cp config.yaml.backup.YYYYMMDD_HHMMSS config.yaml
```

---

For more information, see:
- [Installation Guide](installation.md)
- [User Guide](user-guide.md)
- [Security Guide](security.md)
- [Troubleshooting](troubleshooting.md)