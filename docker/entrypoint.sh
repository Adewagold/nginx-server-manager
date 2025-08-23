#!/bin/bash
set -e

# Nginx Site Manager Docker Entrypoint
# Initializes the container environment and starts services

echo "🐳 Starting Nginx Site Manager Container"
echo "========================================"

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if a service is running
check_service() {
    local service=$1
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if pgrep -f "$service" > /dev/null; then
            log "$service is running"
            return 0
        fi
        log "Waiting for $service to start... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    log "ERROR: $service failed to start after $max_attempts attempts"
    return 1
}

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    log "ERROR: Entrypoint must run as root to initialize services"
    exit 1
fi

# Set timezone if provided
if [ -n "$TZ" ]; then
    log "Setting timezone to $TZ"
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime
    echo $TZ > /etc/timezone
fi

# Create required directories
log "Creating required directories..."
mkdir -p /var/run/nginx \
         /var/log/nginx \
         /var/log/nginx-manager \
         /var/log/supervisor \
         /app/data/backups \
         /home/nginx-manager/.letsencrypt/{live,work,logs,renewal}

# Set up permissions
log "Setting up permissions..."
chown -R nginx-manager:www-data /app/data /var/www /var/log/nginx-manager
chown -R nginx-manager:www-data /home/nginx-manager/.letsencrypt
chown -R www-data:www-data /var/log/nginx
chmod 755 /home/nginx-manager/.letsencrypt
find /home/nginx-manager/.letsencrypt -type d -exec chmod 755 {} \;

# Generate secret key if using default
if [ -f /app/config.yaml ]; then
    if grep -q "CHANGE-THIS-TO-A-SECURE-32-PLUS-CHARACTER-SECRET-KEY" /app/config.yaml; then
        log "Generating secure secret key..."
        NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        sed -i "s/CHANGE-THIS-TO-A-SECURE-32-PLUS-CHARACTER-SECRET-KEY-WITH-SPECIAL-CHARS!/$NEW_SECRET/" /app/config.yaml
        log "Secret key generated and updated in config.yaml"
    fi
    
    # Warn about default admin credentials
    if grep -q "CHANGE-THIS-TO-A-STRONG-PASSWORD!" /app/config.yaml; then
        log "WARNING: Default admin password detected!"
        log "Please change the admin password in config.yaml or via environment variables"
        log "Use: NGINX_MANAGER_ADMIN_PASSWORD environment variable"
    fi
else
    log "Creating default configuration from template..."
    cp /app/config.yaml.example /app/config.yaml
    chown nginx-manager:www-data /app/config.yaml
    chmod 600 /app/config.yaml
fi

# Apply environment variable overrides
log "Applying environment variable configuration overrides..."

# App settings
if [ -n "$NGINX_MANAGER_HOST" ]; then
    log "Setting host to: $NGINX_MANAGER_HOST"
    sed -i "s/host: \".*\"/host: \"$NGINX_MANAGER_HOST\"/" /app/config.yaml
fi

if [ -n "$NGINX_MANAGER_PORT" ]; then
    log "Setting port to: $NGINX_MANAGER_PORT"
    sed -i "s/port: .*/port: $NGINX_MANAGER_PORT/" /app/config.yaml
fi

if [ -n "$NGINX_MANAGER_SECRET_KEY" ]; then
    log "Updating secret key from environment variable"
    sed -i "s/secret_key: \".*\"/secret_key: \"$NGINX_MANAGER_SECRET_KEY\"/" /app/config.yaml
fi

if [ -n "$NGINX_MANAGER_DEBUG" ]; then
    log "Setting debug mode to: $NGINX_MANAGER_DEBUG"
    sed -i "s/debug: .*/debug: $NGINX_MANAGER_DEBUG/" /app/config.yaml
fi

# Admin settings
if [ -n "$NGINX_MANAGER_ADMIN_USERNAME" ]; then
    log "Setting admin username to: $NGINX_MANAGER_ADMIN_USERNAME"
    sed -i "s/username: \".*\"/username: \"$NGINX_MANAGER_ADMIN_USERNAME\"/" /app/config.yaml
fi

if [ -n "$NGINX_MANAGER_ADMIN_PASSWORD" ]; then
    log "Updating admin password from environment variable"
    sed -i "s/password: \".*\"/password: \"$NGINX_MANAGER_ADMIN_PASSWORD\"/" /app/config.yaml
fi

if [ -n "$NGINX_MANAGER_ADMIN_EMAIL" ]; then
    log "Setting admin email to: $NGINX_MANAGER_ADMIN_EMAIL"
    sed -i "s/email: \".*\"/email: \"$NGINX_MANAGER_ADMIN_EMAIL\"/" /app/config.yaml
fi

# SSL settings
if [ -n "$NGINX_MANAGER_SSL_EMAIL" ]; then
    log "Setting SSL email to: $NGINX_MANAGER_SSL_EMAIL"
    sed -i "/ssl:/,/auto_renew:/ s/email: \".*\"/email: \"$NGINX_MANAGER_SSL_EMAIL\"/" /app/config.yaml
fi

if [ -n "$NGINX_MANAGER_SSL_STAGING" ]; then
    log "Setting SSL staging to: $NGINX_MANAGER_SSL_STAGING"
    sed -i "/ssl:/,/auto_renew:/ s/staging: .*/staging: $NGINX_MANAGER_SSL_STAGING/" /app/config.yaml
fi

# Initialize database
log "Initializing database..."
cd /app
sudo -u nginx-manager python -c "
try:
    from app.models import init_database
    init_database()
    print('Database initialized successfully')
except Exception as e:
    print(f'Database initialization error: {e}')
    # Continue anyway - database might already exist
"

# Test nginx configuration
log "Testing nginx configuration..."
nginx -t || {
    log "ERROR: nginx configuration test failed"
    log "Check nginx configuration files"
    exit 1
}

# Set up cron for SSL renewal and cleanup
log "Setting up cron jobs..."
cat > /etc/cron.d/nginx-manager << EOF
# SSL certificate renewal (daily at 2 AM)
0 2 * * * nginx-manager /usr/bin/certbot renew --work-dir /home/nginx-manager/.letsencrypt/work --config-dir /home/nginx-manager/.letsencrypt --logs-dir /home/nginx-manager/.letsencrypt/logs --post-hook "nginx -s reload" >> /var/log/nginx-manager/ssl-renewal.log 2>&1

# Log cleanup (weekly)
0 0 * * 0 root find /var/log/nginx-manager -name "*.log" -mtime +7 -delete

# Backup cleanup (monthly)  
0 0 1 * * nginx-manager find /app/data/backups -name "*.tar.gz" -mtime +30 -delete
EOF

chmod 644 /etc/cron.d/nginx-manager

# Start cron service
service cron start

log "Container initialization completed successfully"

# Handle different run modes
case "$1" in
    "bash"|"sh")
        log "Starting interactive shell..."
        exec /bin/bash
        ;;
    "supervisord")
        log "Starting supervisor to manage services..."
        exec supervisord -c /etc/supervisor/conf.d/supervisord.conf
        ;;
    "app")
        log "Starting application directly..."
        cd /app
        exec sudo -u nginx-manager python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
        ;;
    "security-audit")
        log "Running security audit..."
        cd /app
        exec sudo -u nginx-manager python security_audit.py
        ;;
    *)
        log "Starting with custom command: $*"
        exec "$@"
        ;;
esac