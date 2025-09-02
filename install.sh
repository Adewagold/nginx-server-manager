#!/bin/bash

# Nginx Site Manager Installation Script
# Professional installation with comprehensive OS support and error handling
# Version: 2.0

set -e
set -o pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation variables
SCRIPT_VERSION="2.0"
INSTALL_LOG="/tmp/nginx-manager-install.log"
CURRENT_USER=$(whoami)
INSTALL_DIR=$(pwd)
BACKUP_DIR="/tmp/nginx-manager-backup-$(date +%Y%m%d_%H%M%S)"

# Function to print colored output
print_header() {
    echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_status() {
    echo -e "${GREEN}✓${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$INSTALL_LOG"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >> "$INSTALL_LOG"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$INSTALL_LOG"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$INSTALL_LOG"
}

print_step() {
    echo -e "\n${CYAN}▶${NC} ${CYAN}$1${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [STEP] $1" >> "$INSTALL_LOG"
}

# Function to handle errors and cleanup
cleanup_on_error() {
    local exit_code=$?
    print_error "Installation failed with exit code $exit_code"
    print_info "Installation log saved to: $INSTALL_LOG"
    
    if [[ -d "$BACKUP_DIR" ]]; then
        print_info "Backup directory: $BACKUP_DIR"
        print_warning "You may need to manually restore any backed up files"
    fi
    
    print_error "Please check the logs and try again"
    print_info "For support, please visit: https://github.com/your-username/nginx-manager/issues"
    
    exit $exit_code
}

# Set up error handling
trap cleanup_on_error ERR

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if service is running
service_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

# Function to backup file if it exists
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file" "$BACKUP_DIR/"
        print_info "Backed up $file to $BACKUP_DIR/"
    fi
}

# Function to detect OS and version
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    elif command_exists lsb_release; then
        OS_ID=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(lsb_release -sr)
        OS_NAME=$(lsb_release -sd | tr -d '"')
    else
        print_error "Cannot detect OS. This script requires a supported Linux distribution."
        exit 1
    fi
    
    # Normalize OS names
    case "$OS_ID" in
        ubuntu)
            OS_TYPE="debian"
            PACKAGE_MANAGER="apt"
            ;;
        debian)
            OS_TYPE="debian"
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|rocky|almalinux|fedora)
            OS_TYPE="redhat"
            if command_exists dnf; then
                PACKAGE_MANAGER="dnf"
            else
                PACKAGE_MANAGER="yum"
            fi
            ;;
        *)
            print_warning "Unsupported OS detected: $OS_ID"
            print_warning "This script officially supports Ubuntu, Debian, CentOS, Rocky Linux, AlmaLinux, and Fedora"
            print_warning "Attempting to continue with best-guess package manager..."
            
            if command_exists apt; then
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
            elif command_exists dnf; then
                OS_TYPE="redhat"
                PACKAGE_MANAGER="dnf"
            elif command_exists yum; then
                OS_TYPE="redhat"
                PACKAGE_MANAGER="yum"
            else
                print_error "No supported package manager found (apt, dnf, yum)"
                exit 1
            fi
            ;;
    esac
}

# Function to check system requirements
check_requirements() {
    local errors=0
    
    print_step "Checking system requirements"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons"
        print_info "Please run as a regular user with sudo privileges"
        ((errors++))
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "requirements.txt" ]] || [[ ! -d "app" ]]; then
        print_error "This script must be run from the nginx-manager directory"
        print_info "Please cd to the nginx-manager directory and run: ./install.sh"
        ((errors++))
    fi
    
    # Check Python version
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 8 ]]; then
            print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
            ((errors++))
        else
            print_status "Python $PYTHON_VERSION detected"
        fi
    else
        print_warning "Python 3 not found - will be installed"
    fi
    
    # Check sudo privileges
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges"
        print_info "Please ensure your user is in the sudo group and try again"
        ((errors++))
    fi
    
    # Check available disk space (require at least 500MB)
    AVAILABLE_SPACE=$(df . | tail -1 | awk '{print $4}')
    if [[ $AVAILABLE_SPACE -lt 512000 ]]; then
        print_warning "Low disk space detected. At least 500MB recommended."
    fi
    
    # Check if ports are available
    if command_exists netstat; then
        if netstat -tuln | grep -q ":8080 "; then
            print_warning "Port 8080 appears to be in use. The application may fail to start."
        fi
    fi
    
    if [[ $errors -gt 0 ]]; then
        print_error "$errors requirement check(s) failed"
        exit 1
    fi
    
    print_status "All system requirements met"
}

# Main installation function
main() {
    print_header "Nginx Site Manager Installation Script v$SCRIPT_VERSION"
    
    print_info "Starting installation process..."
    print_info "Installation log: $INSTALL_LOG"
    
    # Initialize log file
    echo "=== Nginx Site Manager Installation Log ===" > "$INSTALL_LOG"
    echo "Date: $(date)" >> "$INSTALL_LOG"
    echo "User: $CURRENT_USER" >> "$INSTALL_LOG"
    echo "Directory: $INSTALL_DIR" >> "$INSTALL_LOG"
    echo "Script Version: $SCRIPT_VERSION" >> "$INSTALL_LOG"
    echo "========================================" >> "$INSTALL_LOG"
    
    # Run installation steps
    detect_os
    check_requirements
    install_system_packages
    setup_python_environment
    setup_directories_and_permissions
    setup_ssl_directories
    setup_sudo_permissions
    setup_nginx_wrapper
    setup_privileged_service
    initialize_application
    setup_systemd_service
    final_configuration
    
    print_header "🎉 Installation Complete!"
    show_completion_message
}

# Enhanced OS detection and package installation
install_system_packages() {
    print_step "Installing system packages"
    
    print_info "Detected OS: $OS_NAME"
    print_info "Package Manager: $PACKAGE_MANAGER"
    
    # Update package lists
    print_info "Updating package lists..."
    case "$PACKAGE_MANAGER" in
        apt)
            sudo apt update -qq
            ;;
        dnf)
            sudo dnf check-update -q || true
            ;;
        yum)
            sudo yum check-update -q || true
            ;;
    esac
    
    # Install required packages
    local packages=()
    
    # Common packages for all distributions
    if ! command_exists nginx; then
        packages+=(nginx)
    fi
    
    if ! command_exists python3; then
        packages+=(python3)
    fi
    
    if ! command_exists pip3; then
        case "$OS_TYPE" in
            debian)
                packages+=(python3-pip python3-venv python3-dev)
                ;;
            redhat)
                packages+=(python3-pip python3-devel)
                ;;
        esac
    fi
    
    if ! command_exists certbot; then
        case "$OS_TYPE" in
            debian)
                packages+=(certbot python3-certbot-nginx)
                ;;
            redhat)
                # Enable EPEL for CentOS/RHEL
                if [[ "$OS_ID" =~ ^(centos|rhel)$ ]]; then
                    if ! command_exists certbot; then
                        packages+=(epel-release)
                    fi
                fi
                packages+=(certbot python3-certbot-nginx)
                ;;
        esac
    fi
    
    # Install packages if any are needed
    if [[ ${#packages[@]} -gt 0 ]]; then
        print_info "Installing packages: ${packages[*]}"
        
        case "$PACKAGE_MANAGER" in
            apt)
                sudo DEBIAN_FRONTEND=noninteractive apt install -y "${packages[@]}"
                ;;
            dnf)
                sudo dnf install -y "${packages[@]}"
                ;;
            yum)
                sudo yum install -y "${packages[@]}"
                ;;
        esac
        
        print_status "System packages installed successfully"
    else
        print_status "All required system packages are already installed"
    fi
    
    # Verify installations
    local failed_packages=()
    
    if ! command_exists nginx; then
        failed_packages+=(nginx)
    fi
    
    if ! command_exists python3; then
        failed_packages+=(python3)
    fi
    
    if ! command_exists certbot; then
        failed_packages+=(certbot)
    fi
    
    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        print_error "Failed to install packages: ${failed_packages[*]}"
        exit 1
    fi
}

setup_python_environment() {
    print_step "Setting up Python environment"
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv venv
        print_status "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi
    
    # Upgrade pip and install packages
    print_info "Installing Python dependencies..."
    ./venv/bin/pip install --upgrade pip setuptools wheel
    
    # Install requirements with timeout and retry
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if ./venv/bin/pip install -r requirements.txt; then
            print_status "Python dependencies installed successfully"
            break
        else
            print_warning "Attempt $attempt failed, retrying... ($attempt/$max_attempts)"
            ((attempt++))
            
            if [[ $attempt -gt $max_attempts ]]; then
                print_error "Failed to install Python dependencies after $max_attempts attempts"
                exit 1
            fi
            
            sleep 5
        fi
    done
    
    # Install python-crontab separately if not already installed
    print_info "Ensuring python-crontab is installed for SSL auto-renewal..."
    ./venv/bin/pip install python-crontab==3.0.0 || print_warning "python-crontab installation failed - auto-renewal may not work"
}

setup_directories_and_permissions() {
    print_step "Setting up directories and permissions"
    
    # Create necessary directories
    print_info "Creating system directories..."
    sudo mkdir -p /var/www
    sudo mkdir -p /var/log/nginx-manager
    sudo mkdir -p /etc/nginx/sites-available
    sudo mkdir -p /etc/nginx/sites-enabled
    
    # Create local data directories
    mkdir -p data/nginx-sites-available
    mkdir -p data/nginx-sites-enabled
    mkdir -p data/www
    mkdir -p data/backups
    
    # Set up nginx directory permissions
    print_info "Setting up nginx directory permissions..."
    sudo chown -R $CURRENT_USER:www-data /etc/nginx/sites-available
    sudo chown -R $CURRENT_USER:www-data /etc/nginx/sites-enabled
    sudo chmod -R 775 /etc/nginx/sites-available
    sudo chmod -R 775 /etc/nginx/sites-enabled
    
    # Set up web root permissions
    sudo chown -R $CURRENT_USER:www-data /var/www
    sudo chmod -R 775 /var/www
    
    # Add current user to www-data group
    print_info "Adding $CURRENT_USER to www-data group..."
    sudo usermod -a -G www-data $CURRENT_USER
    
    # Also add www-data user to the current user's group for file access
    sudo usermod -a -G $CURRENT_USER www-data
    
    # Set up log directory permissions
    sudo mkdir -p /var/log/nginx-manager
    sudo chown -R $CURRENT_USER:www-data /var/log/nginx-manager
    sudo chmod -R 775 /var/log/nginx-manager
    
    print_status "Directories and permissions configured"
}

setup_ssl_directories() {
    print_step "Setting up SSL certificate directories"
    
    # Create user-accessible Let's Encrypt directories to avoid permission issues
    print_info "Creating SSL certificate directories..."
    mkdir -p ~/.letsencrypt
    mkdir -p ~/.letsencrypt/live
    mkdir -p ~/.letsencrypt/work
    mkdir -p ~/.letsencrypt/logs
    mkdir -p ~/.letsencrypt/renewal
    
    # Set appropriate permissions for SSL directories
    chmod 755 ~/.letsencrypt
    chmod 755 ~/.letsencrypt/live
    chmod 755 ~/.letsencrypt/work
    chmod 755 ~/.letsencrypt/logs
    chmod 755 ~/.letsencrypt/renewal
    
    # Make SSL directories readable by nginx (www-data group)
    sudo chown -R $CURRENT_USER:www-data ~/.letsencrypt
    sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
    sudo find ~/.letsencrypt -type f -exec chmod 644 {} \; 2>/dev/null || true
    
    # Test SSL directory permissions
    print_info "Testing SSL directory permissions..."
    if [[ -w ~/.letsencrypt && -w ~/.letsencrypt/logs ]]; then
        print_status "SSL directories are writable"
        # Create a test file to verify nginx can read from these directories
        echo "test" > ~/.letsencrypt/test_file
        if sudo -u www-data test -r ~/.letsencrypt/test_file 2>/dev/null; then
            print_status "Nginx can read SSL certificates from user directory"
            rm ~/.letsencrypt/test_file
        else
            print_warning "Nginx may not be able to read SSL certificates. Manual permission fix may be needed."
        fi
    else
        print_error "SSL directories are not writable. SSL certificate generation may fail."
    fi
    
    print_status "SSL directories configured"
}

setup_sudo_permissions() {
    print_step "Setting up optional sudo permissions"
    
    # Backup existing sudoers file if it exists
    backup_file "/etc/sudoers.d/nginx-manager"
    
    print_info "Configuring optional sudo permissions for development mode..."
    print_info "Note: When running as systemd service, sudo is not required"
    
    sudo tee /etc/sudoers.d/nginx-manager > /dev/null <<EOF
# Nginx Site Manager - Optional sudo permissions for development mode
# Generated on $(date) for user: $CURRENT_USER
# Note: These are only needed when use_sudo is set to true in config.yaml

$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl status nginx
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/certbot
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/certbot certonly *
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/certbot renew *
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/ln -sf /etc/nginx/sites-available/* /etc/nginx/sites-enabled/
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/rm /etc/nginx/sites-enabled/*
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/chown * ~/.letsencrypt/*
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/chmod * ~/.letsencrypt/*
EOF
    
    # Validate sudoers syntax
    if sudo visudo -c -f /etc/sudoers.d/nginx-manager; then
        print_status "Optional sudo permissions configured successfully"
        print_info "These permissions are used when use_sudo: true in config.yaml"
    else
        print_error "Invalid sudoers syntax detected"
        sudo rm -f /etc/sudoers.d/nginx-manager
        exit 1
    fi
}

initialize_application() {
    print_step "Initializing application"
    
    # Create initial config if it doesn't exist
    if [[ ! -f config.yaml ]]; then
        print_info "Creating initial configuration..."
        cp config.yaml.example config.yaml
        
        # Set default admin password for initial setup
        sed -i 's/CHANGE-THIS-TO-A-STRONG-PASSWORD!/AdminPass123!/' config.yaml
        
        print_status "Configuration file created from template"
        print_warning "Please edit config.yaml to customize your settings"
    else
        print_info "Configuration file already exists"
    fi
    
    # Initialize database
    print_info "Initializing database..."
    if ./venv/bin/python -c "from app.models import init_database; init_database()" 2>>"$INSTALL_LOG"; then
        print_status "Database initialized successfully"
    else
        print_warning "Database initialization encountered issues (check log for details)"
    fi
}

setup_systemd_service() {
    print_step "Setting up systemd service"
    
    # Backup existing service file
    backup_file "/etc/systemd/system/nginx-manager.service"
    
    print_info "Creating systemd service file..."
    sudo tee /etc/systemd/system/nginx-manager.service > /dev/null <<EOF
[Unit]
Description=Nginx Site Manager
Documentation=https://github.com/your-username/nginx-manager
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=$CURRENT_USER
Group=www-data
SupplementaryGroups=systemd-journal
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
TimeoutStopSec=10

# Security settings
# NoNewPrivileges=true  # Disabled to allow nginx wrapper script with sudo
PrivateTmp=true
ProtectSystem=strict
ProtectHome=false
ReadWritePaths=$INSTALL_DIR /var/www /var/log/nginx-manager /etc/nginx/sites-available /etc/nginx/sites-enabled /var/run/nginx-manager

# Allow nginx operations without sudo
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    print_info "Enabling systemd service..."
    sudo systemctl daemon-reload
    sudo systemctl enable nginx-manager
    
    print_status "Systemd service configured and enabled"
}

setup_nginx_wrapper() {
    print_step "Setting up nginx management wrapper"
    
    print_info "Creating nginx management wrapper script..."
    
    # Create wrapper script directory
    sudo mkdir -p /usr/local/bin/nginx-manager
    
    # Create the nginx wrapper script
    sudo tee /usr/local/bin/nginx-manager/nginx-wrapper.sh > /dev/null <<'EOF'
#!/bin/bash
# Nginx Management Wrapper for nginx-manager service
# This script allows the nginx-manager service to perform nginx operations
# without requiring interactive sudo or NoNewPrivileges=false

set -euo pipefail

# Function to log actions
log_action() {
    logger -t nginx-manager-wrapper "$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/nginx-manager/wrapper.log
}

# Validate command
case "${1:-}" in
    "test")
        log_action "Testing nginx configuration"
        exec /usr/sbin/nginx -t
        ;;
    "reload")
        log_action "Reloading nginx service"
        exec /bin/systemctl reload nginx
        ;;
    "restart")
        log_action "Restarting nginx service"
        exec /bin/systemctl restart nginx
        ;;
    "status")
        log_action "Checking nginx service status"
        exec /bin/systemctl status nginx
        ;;
    *)
        log_action "Invalid command attempted: ${1:-empty}"
        echo "Usage: $0 {test|reload|restart|status}"
        exit 1
        ;;
esac
EOF
    
    # Set proper permissions for the wrapper script
    sudo chmod 755 /usr/local/bin/nginx-manager/nginx-wrapper.sh
    sudo chown root:root /usr/local/bin/nginx-manager/nginx-wrapper.sh
    
    # Create a sudoers rule specifically for the wrapper
    print_info "Configuring sudo permissions for nginx wrapper..."
    sudo tee /etc/sudoers.d/nginx-manager-wrapper > /dev/null <<EOF
# Nginx Manager Wrapper - Allow nginx-manager service to use wrapper script
# This provides controlled access to nginx operations without full sudo
$CURRENT_USER ALL=(root) NOPASSWD: /usr/local/bin/nginx-manager/nginx-wrapper.sh test
$CURRENT_USER ALL=(root) NOPASSWD: /usr/local/bin/nginx-manager/nginx-wrapper.sh reload
$CURRENT_USER ALL=(root) NOPASSWD: /usr/local/bin/nginx-manager/nginx-wrapper.sh restart
$CURRENT_USER ALL=(root) NOPASSWD: /usr/local/bin/nginx-manager/nginx-wrapper.sh status
EOF
    
    # Validate sudoers syntax
    if sudo visudo -c -f /etc/sudoers.d/nginx-manager-wrapper; then
        print_status "Nginx wrapper configured successfully"
        print_info "Wrapper script: /usr/local/bin/nginx-manager/nginx-wrapper.sh"
    else
        print_error "Invalid sudoers syntax in wrapper configuration"
        sudo rm -f /etc/sudoers.d/nginx-manager-wrapper
        exit 1
    fi
    
    # Ensure log directory exists with proper permissions
    sudo mkdir -p /var/log/nginx-manager
    sudo chown $CURRENT_USER:www-data /var/log/nginx-manager
    sudo chmod 775 /var/log/nginx-manager
    
    # Create log file
    sudo touch /var/log/nginx-manager/wrapper.log
    sudo chown $CURRENT_USER:www-data /var/log/nginx-manager/wrapper.log
    sudo chmod 664 /var/log/nginx-manager/wrapper.log
}

setup_privileged_service() {
    print_step "Setting up privileged nginx service"
    
    print_info "Creating privileged nginx manager service..."
    
    # Create the privileged service script
    sudo tee /usr/local/bin/nginx-manager/nginx-manager.py > /dev/null << 'PRIVILEGED_SCRIPT_EOF'
#!/usr/bin/env python3
"""
Nginx Manager Service - A privileged service for nginx operations.
This service runs with elevated privileges and accepts commands via a file interface.
"""

import os
import sys
import time
import subprocess
import json
import logging
from pathlib import Path

# Configuration
COMMAND_FILE = "/var/run/nginx-manager/command"
RESULT_FILE = "/var/run/nginx-manager/result"
LOCK_FILE = "/var/run/nginx-manager/lock"
LOG_FILE = "/var/log/nginx-manager/service.log"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def ensure_directories():
    """Ensure required directories exist."""
    os.makedirs("/var/run/nginx-manager", mode=0o755, exist_ok=True)
    os.makedirs("/var/log/nginx-manager", mode=0o755, exist_ok=True)
    
    # Set appropriate group ownership for the runtime directory
    # This allows the main service user to write to the directory
    import grp
    import pwd
    
    try:
        # Try to detect the service group from systemd service files
        service_group = None
        service_files = [
            "/etc/systemd/system/nginx-manager.service",
            "/etc/systemd/system/nginx-server-manager.service"
        ]
        
        for service_file in service_files:
            if os.path.exists(service_file):
                with open(service_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith('Group='):
                            service_group = line.strip().split('=')[1]
                            break
                if service_group:
                    break
        
        # Fallback to www-data if no service group found
        if not service_group:
            service_group = 'www-data'
        
        # Get the group ID
        group_gid = grp.getgrnam(service_group).gr_gid
        
        # Change group ownership of runtime directory
        os.chown("/var/run/nginx-manager", -1, group_gid)
        
        # Set permissions to allow group write access
        os.chmod("/var/run/nginx-manager", 0o775)
        
        logger.info(f"Set runtime directory permissions for {service_group} group access")
    except (KeyError, OSError) as e:
        logger.warning(f"Could not set group permissions for runtime directory: {e}")
        logger.info("Runtime directory will use default permissions")

def execute_command(command):
    """Execute an nginx command and return the result."""
    try:
        if command == "test":
            result = subprocess.run(
                ["nginx", "-t"],
                capture_output=True,
                text=True
            )
        elif command == "reload":
            result = subprocess.run(
                ["systemctl", "reload", "nginx"],
                capture_output=True,
                text=True
            )
        elif command == "restart":
            result = subprocess.run(
                ["systemctl", "restart", "nginx"],
                capture_output=True,
                text=True
            )
        elif command == "status":
            result = subprocess.run(
                ["systemctl", "status", "nginx"],
                capture_output=True,
                text=True
            )
        else:
            return {
                "success": False,
                "message": f"Unknown command: {command}",
                "returncode": 1
            }
        
        return {
            "success": result.returncode == 0,
            "message": result.stdout or result.stderr,
            "returncode": result.returncode
        }
        
    except Exception as e:
        logger.error(f"Error executing command {command}: {e}")
        return {
            "success": False,
            "message": str(e),
            "returncode": 1
        }

def process_command_file():
    """Process a command from the command file and write result."""
    try:
        # Read command
        with open(COMMAND_FILE, 'r') as f:
            command = f.read().strip()
        
        logger.info(f"Processing command: {command}")
        
        # Execute command
        result = execute_command(command)
        
        # Write result
        with open(RESULT_FILE, 'w') as f:
            json.dump(result, f)
        
        # Remove command file to indicate completion
        os.unlink(COMMAND_FILE)
        
        logger.info(f"Command {command} completed with result: {result['success']}")
        
    except Exception as e:
        logger.error(f"Error processing command: {e}")
        # Write error result
        try:
            with open(RESULT_FILE, 'w') as f:
                json.dump({
                    "success": False,
                    "message": str(e),
                    "returncode": 1
                }, f)
        except:
            pass

def main():
    """Main service loop."""
    logger.info("Starting nginx manager service")
    ensure_directories()
    
    while True:
        try:
            # Check for command file
            if os.path.exists(COMMAND_FILE):
                # Use lock file to prevent race conditions
                if not os.path.exists(LOCK_FILE):
                    Path(LOCK_FILE).touch()
                    try:
                        process_command_file()
                    finally:
                        if os.path.exists(LOCK_FILE):
                            os.unlink(LOCK_FILE)
            
            time.sleep(0.5)  # Short polling interval
            
        except KeyboardInterrupt:
            logger.info("Shutting down nginx manager service")
            break
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
PRIVILEGED_SCRIPT_EOF
    
    # Set executable permissions
    sudo chmod +x /usr/local/bin/nginx-manager/nginx-manager.py
    
    # Create systemd service file for the privileged service
    print_info "Creating privileged nginx manager systemd service..."
    sudo tee /etc/systemd/system/nginx-manager-privileged.service > /dev/null << 'PRIVILEGED_SERVICE_EOF'
[Unit]
Description=Nginx Manager Privileged Service
After=nginx.service
Wants=nginx.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/nginx-manager/nginx-manager.py
Restart=always
RestartSec=3
TimeoutStopSec=10

# Create runtime directory
RuntimeDirectory=nginx-manager
RuntimeDirectoryMode=0775

[Install]
WantedBy=multi-user.target
PRIVILEGED_SERVICE_EOF
    
    # Reload systemd and enable the privileged service
    print_info "Enabling privileged nginx manager service..."
    sudo systemctl daemon-reload
    sudo systemctl enable nginx-manager-privileged
    
    print_status "Privileged nginx service configured successfully"
}
final_configuration() {
    print_step "Finalizing configuration"
    
    # Start nginx if not running
    if ! service_running nginx; then
        print_info "Starting nginx service..."
        sudo systemctl start nginx
        sudo systemctl enable nginx
        print_status "Nginx service started and enabled"
    else
        print_info "Nginx service is already running"
    fi
    
    # Enable certbot timer for automatic SSL renewals
    print_info "Configuring SSL certificate auto-renewal..."
    if command_exists certbot && systemctl list-unit-files | grep -q "certbot.timer"; then
        sudo systemctl enable certbot.timer
        sudo systemctl start certbot.timer
        print_status "SSL auto-renewal configured with certbot timer"
    else
        print_warning "Certbot timer not available - SSL auto-renewal will use fallback method"
    fi
    
    # Start the privileged nginx manager service
    print_info "Starting privileged nginx manager service..."
    sudo systemctl start nginx-manager-privileged
    if systemctl is-active --quiet nginx-manager-privileged; then
        print_status "Privileged nginx manager service started successfully"
    else
        print_warning "Privileged nginx manager service failed to start"
    fi
    
    # Validate nginx configuration
    if sudo nginx -t 2>/dev/null; then
        print_status "Nginx configuration is valid"
    else
        print_warning "Nginx configuration validation failed (may affect some features)"
    fi
    
    print_status "Final configuration completed"
}

show_completion_message() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "your-server-ip")
    
    echo -e "\n${GREEN}🎉 Installation completed successfully!${NC}\n"
    
    echo -e "${CYAN}━━━ NEXT STEPS ━━━${NC}"
    echo -e "${BLUE}1.${NC} Edit configuration: ${YELLOW}nano config.yaml${NC}"
    echo -e "${BLUE}2.${NC} Start the service: ${YELLOW}sudo systemctl start nginx-manager${NC}"
    echo -e "${BLUE}3.${NC} Access web interface: ${YELLOW}http://$server_ip:8080${NC}"
    echo -e "${BLUE}4.${NC} Default login: ${YELLOW}admin${NC} / ${YELLOW}AdminPass123!${NC}"
    
    echo -e "\n${CYAN}━━━ IMPORTANT SECURITY STEPS ━━━${NC}"
    echo -e "${RED}⚠${NC}  Change the default admin password in config.yaml"
    echo -e "${YELLOW}⚠${NC}  Log out and log back in for group permissions to take effect"
    echo -e "${YELLOW}⚠${NC}  Configure firewall to allow access to port 8080"
    echo -e "${YELLOW}⚠${NC}  Update SSL email in config.yaml (ssl.email)"
    echo -e "${YELLOW}⚠${NC}  For production SSL, set ssl.staging to false in config.yaml"
    
    echo -e "\n${CYAN}━━━ SERVICE MANAGEMENT ━━━${NC}"
    echo -e "${BLUE}•${NC} Check main service: ${YELLOW}sudo systemctl status nginx-manager${NC}"
    echo -e "${BLUE}•${NC} Check privileged service: ${YELLOW}sudo systemctl status nginx-manager-privileged${NC}"
    echo -e "${BLUE}•${NC} View main logs: ${YELLOW}sudo journalctl -u nginx-manager -f${NC}"
    echo -e "${BLUE}•${NC} View privileged logs: ${YELLOW}sudo journalctl -u nginx-manager-privileged -f${NC}"
    echo -e "${BLUE}•${NC} Restart services: ${YELLOW}sudo systemctl restart nginx-manager nginx-manager-privileged${NC}"
    
    echo -e "\n${CYAN}━━━ FEATURES AVAILABLE ━━━${NC}"
    echo -e "${GREEN}✓${NC} Site Management (Static, Proxy, Load Balancer)"
    echo -e "${GREEN}✓${NC} SSL Certificate Management (Let's Encrypt)"
    echo -e "${GREEN}✓${NC} File Management for Static Sites"
    echo -e "${GREEN}✓${NC} Real-time Log Monitoring"
    echo -e "${GREEN}✓${NC} Professional Web Interface"
    
    echo -e "\n${CYAN}━━━ SSL CONFIGURATION ━━━${NC}"
    echo -e "${BLUE}•${NC} Certificates stored in: ${YELLOW}~/.letsencrypt/${NC}"
    echo -e "${BLUE}•${NC} Auto-renewal configured with system certbot timer"
    echo -e "${BLUE}•${NC} Auto-renewal status visible in SSL dashboard"
    echo -e "${BLUE}•${NC} Default: Using staging server (test certificates)"
    echo -e "${BLUE}•${NC} For production: Set ssl.staging=false in config.yaml"
    
    echo -e "\n${CYAN}━━━ SUPPORT & DOCUMENTATION ━━━${NC}"
    echo -e "${BLUE}•${NC} Installation log: ${YELLOW}$INSTALL_LOG${NC}"
    echo -e "${BLUE}•${NC} Project documentation: ${YELLOW}README.md${NC}"
    echo -e "${BLUE}•${NC} Issues: ${YELLOW}https://github.com/your-username/nginx-manager/issues${NC}"
    
    if [[ -d "$BACKUP_DIR" ]]; then
        echo -e "\n${CYAN}━━━ BACKUP INFORMATION ━━━${NC}"
        echo -e "${BLUE}•${NC} Backups created in: ${YELLOW}$BACKUP_DIR${NC}"
    fi
    
    echo -e "\n${GREEN}Thank you for installing Nginx Site Manager!${NC}"
    echo -e "Transform your nginx management experience from command-line to point-and-click! 🚀"
}

# Run main installation
main "$@"