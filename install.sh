#!/bin/bash

# Nginx Site Manager Installation Script
# Detects OS and installs dependencies automatically

set -e

echo "Starting Nginx Site Manager installation..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   print_status "Please run as a regular user with sudo privileges"
   exit 1
fi

# Check if we're in the right directory
if [[ ! -f "requirements.txt" ]] || [[ ! -d "app" ]]; then
   print_error "This script must be run from the nginx-manager directory"
   print_status "Please cd to the nginx-manager directory and run: ./install.sh"
   exit 1
fi

# Detect OS
if [[ -f /etc/debian_version ]]; then
    OS="debian"
    print_status "Detected Debian/Ubuntu system"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
    print_status "Detected RedHat/CentOS/Fedora system"
else
    print_error "Unsupported operating system"
    exit 1
fi

# Update package lists
print_status "Updating package lists..."
if [[ "$OS" == "debian" ]]; then
    sudo apt update
elif [[ "$OS" == "redhat" ]]; then
    sudo yum update -y
fi

# Install nginx if not present
if ! command -v nginx &> /dev/null; then
    print_status "Installing nginx..."
    if [[ "$OS" == "debian" ]]; then
        sudo apt install -y nginx
    elif [[ "$OS" == "redhat" ]]; then
        sudo yum install -y nginx
    fi
else
    print_status "Nginx already installed"
fi

# Install Python 3 and pip if not present
if ! command -v python3 &> /dev/null; then
    print_status "Installing Python 3..."
    if [[ "$OS" == "debian" ]]; then
        sudo apt install -y python3 python3-pip python3-venv
    elif [[ "$OS" == "redhat" ]]; then
        sudo yum install -y python3 python3-pip
    fi
else
    print_status "Python 3 already installed"
fi

# Install certbot for SSL certificates
if ! command -v certbot &> /dev/null; then
    print_status "Installing certbot for SSL certificates..."
    if [[ "$OS" == "debian" ]]; then
        sudo apt install -y certbot python3-certbot-nginx
    elif [[ "$OS" == "redhat" ]]; then
        sudo yum install -y certbot python3-certbot-nginx
    fi
else
    print_status "Certbot already installed"
fi

# Get current user
CURRENT_USER=$(whoami)
print_status "Setting up for user: $CURRENT_USER"

# Create necessary directories
print_status "Creating directories..."
sudo mkdir -p /var/www
sudo mkdir -p /var/log/nginx-manager
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled

# Create local data directories for the application
mkdir -p data/nginx-sites-available
mkdir -p data/nginx-sites-enabled
mkdir -p data/www
mkdir -p data/backups

# Set up nginx directory permissions
print_status "Setting up nginx directory permissions..."
# Make nginx directories writable by www-data group
sudo chown -R $CURRENT_USER:www-data /etc/nginx/sites-available
sudo chown -R $CURRENT_USER:www-data /etc/nginx/sites-enabled
sudo chmod -R 775 /etc/nginx/sites-available
sudo chmod -R 775 /etc/nginx/sites-enabled

# Set up web root permissions
sudo chown -R $CURRENT_USER:www-data /var/www
sudo chmod -R 775 /var/www

# Add current user to www-data group
print_status "Adding $CURRENT_USER to www-data group..."
sudo usermod -a -G www-data $CURRENT_USER

# Also add www-data user to the current user's group for file access
sudo usermod -a -G $CURRENT_USER www-data

# Grant current user sudo access for specific nginx commands
print_status "Setting up sudo permissions for nginx operations..."
sudo tee /etc/sudoers.d/nginx-manager > /dev/null <<EOF
# Allow current user to manage nginx without password
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/systemctl status nginx
$CURRENT_USER ALL=(ALL) NOPASSWD: /usr/bin/certbot
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/ln -sf /etc/nginx/sites-available/* /etc/nginx/sites-enabled/
$CURRENT_USER ALL=(ALL) NOPASSWD: /bin/rm /etc/nginx/sites-enabled/*
EOF

# Install Python dependencies in current directory
print_status "Installing Python dependencies..."
if [[ ! -d "venv" ]]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
fi
print_status "Installing required packages..."
./venv/bin/pip install -r requirements.txt

# Set up log directory permissions
sudo mkdir -p /var/log/nginx-manager
sudo chown -R $CURRENT_USER:www-data /var/log/nginx-manager
sudo chmod -R 775 /var/log/nginx-manager

# Create systemd service
print_status "Creating systemd service..."
INSTALL_DIR=$(pwd)
sudo tee /etc/systemd/system/nginx-manager.service > /dev/null <<EOF
[Unit]
Description=Nginx Site Manager
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
Group=www-data
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable nginx-manager

# Create initial config if it doesn't exist
if [[ ! -f config.yaml ]]; then
    print_status "Creating initial configuration..."
    cp config.yaml.example config.yaml
    print_warning "Please edit config.yaml to customize your settings"
fi

# Initialize database
print_status "Initializing database..."
./venv/bin/python -c "from app.models import init_db; init_db()" 2>/dev/null || true

# Start nginx if not running
if ! systemctl is-active --quiet nginx; then
    print_status "Starting nginx..."
    sudo systemctl start nginx
    sudo systemctl enable nginx
fi

print_status "Installation completed successfully!"
print_status "==================================="
print_status "Next steps:"
echo ""
echo "1. Edit config.yaml to customize settings (especially change default password)"
echo "2. Start the service: sudo systemctl start nginx-manager"
echo "3. Access the web interface at http://$(hostname -I | awk '{print $1}'):8080"
echo "4. Default login: admin / admin123"
echo ""
print_warning "IMPORTANT POST-INSTALLATION STEPS:"
echo "- You MUST log out and log back in for group permissions to take effect"
echo "- Or run: newgrp www-data (for current session only)"
echo "- Change the default admin password in config.yaml"
echo "- Configure your firewall to allow access to port 8080 if needed"
echo ""
print_status "To check service status: sudo systemctl status nginx-manager"
print_status "To view logs: sudo journalctl -u nginx-manager -f"