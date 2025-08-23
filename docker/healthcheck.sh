#!/bin/bash
# Health check script for Nginx Site Manager Docker container

set -e

# Configuration
APP_PORT=${NGINX_MANAGER_PORT:-8080}
HEALTH_URL="http://localhost:${APP_PORT}/api/health"
NGINX_URL="http://localhost:80"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check HTTP endpoint
check_http() {
    local url=$1
    local name=$2
    local timeout=${3:-5}
    
    if curl -f -s --max-time $timeout "$url" > /dev/null 2>&1; then
        log "${GREEN}✓ $name is healthy${NC}"
        return 0
    else
        log "${RED}✗ $name is unhealthy${NC}"
        return 1
    fi
}

# Function to check process
check_process() {
    local process_name=$1
    local friendly_name=$2
    
    if pgrep -f "$process_name" > /dev/null; then
        log "${GREEN}✓ $friendly_name is running${NC}"
        return 0
    else
        log "${RED}✗ $friendly_name is not running${NC}"
        return 1
    fi
}

# Function to check file system
check_filesystem() {
    local path=$1
    local name=$2
    
    if [ -w "$path" ]; then
        log "${GREEN}✓ $name is writable${NC}"
        return 0
    else
        log "${YELLOW}⚠ $name is not writable${NC}"
        return 1
    fi
}

# Function to check database
check_database() {
    local db_path="/app/data/sites.db"
    
    if [ -f "$db_path" ]; then
        # Try to query the database
        if echo "SELECT 1;" | sqlite3 "$db_path" > /dev/null 2>&1; then
            log "${GREEN}✓ Database is accessible${NC}"
            return 0
        else
            log "${RED}✗ Database is corrupted or inaccessible${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠ Database file does not exist${NC}"
        return 1
    fi
}

# Main health check function
main() {
    log "🏥 Starting health check..."
    
    local exit_code=0
    
    # Check critical services
    if ! check_process "supervisord" "Supervisor"; then
        exit_code=1
    fi
    
    if ! check_process "nginx" "Nginx"; then
        exit_code=1
    fi
    
    if ! check_process "uvicorn" "Application Server"; then
        exit_code=1
    fi
    
    # Check HTTP endpoints
    if ! check_http "$NGINX_URL" "Nginx HTTP"; then
        exit_code=1
    fi
    
    if ! check_http "$HEALTH_URL" "Application Health"; then
        exit_code=1
    fi
    
    # Check file system
    check_filesystem "/app/data" "Data directory"
    check_filesystem "/var/www" "Web root directory"
    check_filesystem "/home/nginx-manager/.letsencrypt" "SSL directory"
    
    # Check database
    check_database
    
    # Check disk space
    local disk_usage=$(df /app | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        log "${RED}✗ Disk usage is critical: ${disk_usage}%${NC}"
        exit_code=1
    elif [ "$disk_usage" -gt 80 ]; then
        log "${YELLOW}⚠ Disk usage is high: ${disk_usage}%${NC}"
    else
        log "${GREEN}✓ Disk usage is normal: ${disk_usage}%${NC}"
    fi
    
    # Check memory usage
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
    if [ "$mem_usage" -gt 95 ]; then
        log "${RED}✗ Memory usage is critical: ${mem_usage}%${NC}"
        exit_code=1
    elif [ "$mem_usage" -gt 85 ]; then
        log "${YELLOW}⚠ Memory usage is high: ${mem_usage}%${NC}"
    else
        log "${GREEN}✓ Memory usage is normal: ${mem_usage}%${NC}"
    fi
    
    # Final result
    if [ $exit_code -eq 0 ]; then
        log "${GREEN}🎉 All health checks passed${NC}"
    else
        log "${RED}💥 Some health checks failed${NC}"
    fi
    
    return $exit_code
}

# Run health check based on mode
case "${1:-full}" in
    "quick")
        # Quick check - just the application endpoint
        check_http "$HEALTH_URL" "Application"
        ;;
    "nginx")
        # Just nginx check
        check_http "$NGINX_URL" "Nginx"
        ;;
    "app")
        # Just application check  
        check_http "$HEALTH_URL" "Application"
        ;;
    "full"|*)
        # Full health check (default)
        main
        ;;
esac