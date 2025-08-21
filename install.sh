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

# Create nginx-manager user if it doesn't exist
if ! id "nginx-manager" &>/dev/null; then
    print_status "Creating nginx-manager user..."
    sudo useradd -r -s /bin/bash -d /opt/nginx-manager -m nginx-manager
else
    print_status "nginx-manager user already exists"
fi

# Create necessary directories
print_status "Creating directories..."
sudo mkdir -p /opt/nginx-manager
sudo mkdir -p /var/www
sudo mkdir -p /var/log/nginx-manager

# Set up directory permissions
print_status "Setting up permissions..."
sudo chown -R nginx-manager:nginx-manager /opt/nginx-manager
sudo chown -R nginx-manager:www-data /var/www
sudo chmod -R 755 /var/www

# Add nginx-manager user to www-data group
sudo usermod -a -G www-data nginx-manager

# Grant nginx-manager user sudo access for specific nginx commands
print_status "Setting up sudo permissions for nginx operations..."
sudo tee /etc/sudoers.d/nginx-manager > /dev/null <<EOF
# Allow nginx-manager user to manage nginx without password
nginx-manager ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
nginx-manager ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
nginx-manager ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
nginx-manager ALL=(ALL) NOPASSWD: /bin/systemctl status nginx
nginx-manager ALL=(ALL) NOPASSWD: /usr/bin/certbot
EOF

# Copy application files to /opt/nginx-manager
print_status "Installing application files..."
sudo cp -r . /opt/nginx-manager/
sudo chown -R nginx-manager:nginx-manager /opt/nginx-manager

# Install Python dependencies
print_status "Installing Python dependencies..."
cd /opt/nginx-manager
sudo -u nginx-manager python3 -m venv venv
sudo -u nginx-manager ./venv/bin/pip install -r requirements.txt

# Create systemd service
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/nginx-manager.service > /dev/null <<EOF
[Unit]
Description=Nginx Site Manager
After=network.target

[Service]
Type=simple
User=nginx-manager
Group=nginx-manager
WorkingDirectory=/opt/nginx-manager
Environment=PATH=/opt/nginx-manager/venv/bin
ExecStart=/opt/nginx-manager/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable nginx-manager

# Create initial config if it doesn't exist
if [[ ! -f /opt/nginx-manager/config.yaml ]]; then
    print_status "Creating initial configuration..."
    sudo -u nginx-manager cp /opt/nginx-manager/config.yaml.example /opt/nginx-manager/config.yaml
    print_warning "Please edit /opt/nginx-manager/config.yaml to customize your settings"
fi

# Start nginx if not running
if ! systemctl is-active --quiet nginx; then
    print_status "Starting nginx..."
    sudo systemctl start nginx
    sudo systemctl enable nginx
fi

print_status "Installation completed successfully!"
print_status "Next steps:"
echo "1. Edit /opt/nginx-manager/config.yaml to customize settings"
echo "2. Start the service: sudo systemctl start nginx-manager"
echo "3. Access the web interface at http://localhost:8080"
echo "4. Default login: admin / admin123 (change this in config.yaml)"

print_warning "Remember to:"
echo "- Change the default admin password in config.yaml"
echo "- Configure your firewall to allow access to port 8080"
echo "- Review the configuration before starting the service"