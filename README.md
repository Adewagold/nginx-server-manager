# Nginx Site Manager

> **A modern, web-based nginx management platform for effortless site deployment, SSL certificate management, and file operations**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)

## 🚀 Overview

Nginx Site Manager is a powerful, intuitive web interface that transforms nginx administration from complex command-line operations into simple point-and-click actions. Perfect for developers, system administrators, and anyone who wants to manage websites without touching the terminal.
<img width="1868" height="972" alt="image" src="https://github.com/user-attachments/assets/8c2a5ad9-4eea-4fa7-8a75-ec366c75f7c6" />

![Main Dashboard](https://github.com/user-attachments/assets/469e6684-3746-49f3-97c6-3280b6bcde73)
*Main dashboard showing site overview, system status, and management tools*

### ✨ Key Features

- 🌐 **Complete Site Management** - Create, configure, and manage nginx sites with ease
- 🔒 **Automatic SSL Certificates** - One-click Let's Encrypt SSL with auto-renewal
- 📁 **File Management** - Built-in file browser, editor, and upload for static sites
- 📊 **Real-time Monitoring** - Live logs, site status, and system health monitoring
- 🎨 **Professional UI** - Clean, responsive interface built with Bootstrap 5
- 🔐 **Secure by Design** - JWT authentication, input validation, and permission controls
- 🚀 **Easy Deployment** - One-command installation with automated setup

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage Guide](#-usage-guide)
- [API Documentation](#-api-documentation)
- [Security](#-security)
- [Contributing](#-contributing)
- [License](#-license)

## 🎯 Features

### 🌐 Site Management
- **Three Site Types**: Static sites, reverse proxies, and load balancers
- **Visual Configuration**: Point-and-click configuration with real-time validation
- **Enable/Disable Sites**: Toggle sites without deleting configurations
- **Status Monitoring**: Real-time site health checks and performance metrics
- **Configuration Templates**: Pre-built templates for common use cases

![Site Management](https://github.com/user-attachments/assets/700ff5e5-c37f-4fe0-a4b7-cf35699eac1a)
<img width="1655" height="990" alt="image" src="https://github.com/user-attachments/assets/bfa2280c-1c65-40e7-a964-bc09e9c90662" />


*Site management interface with status indicators and quick actions*

### 🔒 SSL Certificate Management
- **Let's Encrypt Integration**: Automatic certificate generation and renewal
- **One-Click SSL**: Enable HTTPS with a single button click
- **Certificate Monitoring**: Track expiry dates and renewal status
- **Auto-Renewal**: Automatic renewal with systemd timers
- **Staging Support**: Test certificates safely before production deployment
- **User-Accessible Storage**: Certificates stored in user directory (no root required)

![SSL Management](https://github.com/user-attachments/assets/4881ce9f-3af4-41ce-a119-4b69465d383b)
<img width="1404" height="1005" alt="image" src="https://github.com/user-attachments/assets/c7d7c992-e700-4f6b-8f42-7bcb7bdfb601" />
![View Logs](https://github.com/user-attachments/assets/f38625ec-031e-4ac6-b821-63e908809c59)


*SSL certificate dashboard with expiry tracking and auto-renewal status*

### 📁 File Management (Static Sites)
- **Built-in File Browser**: Navigate directories with breadcrumb navigation
- **File Editor**: Edit HTML, CSS, JavaScript with syntax highlighting
- **Drag-and-Drop Upload**: Upload single files or entire directories
- **ZIP Extraction**: Bulk upload and extract ZIP archives automatically
- **File Operations**: Create, rename, delete, move, and download files
- **Security**: Path validation, file type restrictions, and size limits


![File Management](https://github.com/user-attachments/assets/954b1871-b5f8-45a1-9425-c78ad42f26ed)
*Built-in file manager with drag-and-drop upload and inline editing*

### 📊 Advanced Monitoring
- **Real-time Log Viewer**: Filter and search nginx logs in real-time
- **System Status**: Monitor nginx service health and configuration
- **Site Status**: Individual site health checks and metrics
- **SSL Dashboard**: Certificate expiry tracking and renewal status
- **Error Handling**: Comprehensive error messages and troubleshooting
<img width="1361" height="1003" alt="image" src="https://github.com/user-attachments/assets/733a956e-7085-41ca-b8ed-a1690f0e5801" />

## 🚀 Quick Start

### Prerequisites
- Linux server (Ubuntu 18.04+, Debian 10+, CentOS 7+, Rocky Linux 8+)
- Python 3.8 or higher
- Nginx (will be installed if not present)
- Sudo privileges for initial setup

### One-Command Installation

```bash
# Clone the repository
git clone https://github.com/your-username/nginx-manager.git
cd nginx-manager

# Run the installation script
chmod +x install.sh
./install.sh

# Start the service
sudo systemctl start nginx-manager

# Access the web interface
# Open http://your-server-ip:8080 in your browser
# Default login: admin / admin123
```

That's it! Your nginx management interface is now running with:
- ✅ Nginx installed and configured
- ✅ SSL directories set up with proper permissions
- ✅ Python dependencies installed in virtual environment
- ✅ Systemd service configured for auto-startup
- ✅ Security permissions properly configured

![Login Screen](screenshots/login.png)
*Clean, professional login interface*

## 📦 Installation

### Automated Installation (Recommended)

The installation script automatically:
- Detects your OS and installs required packages
- Sets up nginx with proper permissions
- Installs Python dependencies in a virtual environment
- Configures SSL certificate directories for user access
- Creates a systemd service for auto-startup
- Sets up proper file permissions and security
- Tests SSL directory permissions

```bash
git clone https://github.com/Adewagold/nginx-server-manager.git
cd nginx-server-manager
chmod +x install.sh
./install.sh
```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

1. **Install Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install -y nginx python3 python3-pip python3-venv certbot python3-certbot-nginx

   # CentOS/Rocky Linux/AlmaLinux
   sudo yum install -y nginx python3 python3-pip certbot python3-certbot-nginx
   ```

2. **Clone and Setup**
   ```bash
   git clone https://github.com/Adewagold/nginx-server-manager.git
   cd nginx-server-manager
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Setup SSL Directories**
   ```bash
   mkdir -p ~/.letsencrypt/{live,work,logs,renewal}
   sudo chown -R $(whoami):www-data ~/.letsencrypt
   sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
   ```

4. **Configuration**
   ```bash
   cp config.yaml.example config.yaml
   # Edit config.yaml with your settings
   ```

5. **Initialize Database**
   ```bash
   python -c "from app.models import init_database; init_database()"
   ```

6. **Start the Application**
   ```bash
   ./venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
   ```

</details>

## ⚙️ Configuration

### Basic Configuration

Edit `config.yaml` to customize your installation:

```yaml
app:
  host: "0.0.0.0"
  port: 8080
  secret_key: "your-secret-key-here"
  access_token_expire_minutes: 60
  debug: false

admin:
  username: "admin"
  password: "your-secure-password"

paths:
  nginx_config_dir: "/etc/nginx/sites-available"
  nginx_enabled_dir: "/etc/nginx/sites-enabled"
  web_root: "/var/www"

security:
  rate_limit: 5  # requests per minute
  session_timeout: 30  # minutes
  cors_origins: ["*"]

logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

### SSL Configuration

The application automatically configures SSL certificates using Let's Encrypt:
- Certificates stored in `~/.letsencrypt/` for user accessibility
- Auto-renewal configured with systemd timers
- Staging server used by default for testing (remove `--staging` flag for production)
- Proper permissions set for nginx to read user certificates

## 📖 Usage Guide

### Creating Your First Site

1. **Access the Web Interface**
   - Open `http://your-server:8080` in your browser
   - Login with your admin credentials

2. **Create a New Site**
   - Click "New Site" button
   - Choose site type (Static, Proxy, or Load Balancer)
   - Configure domain, ports, and other settings
   - Click "Create Site"

![Site Creation](screenshots/create-site.png)
*Site creation form with real-time configuration validation*

3. **Enable the Site**
   - Click the "Enable" button in the site list
   - The site will be activated and nginx reloaded automatically

4. **Add SSL Certificate**
   - Click the SSL shield icon next to your site
   - Enter your email for Let's Encrypt
   - Certificate will be generated and configured automatically
   - Auto-renewal will be set up

5. **Manage Files (Static Sites)**
   - Click the "Manage Files" folder icon
   - Upload files via drag-and-drop
   - Edit files directly in the browser with syntax highlighting
   - Create folders and organize your content

![Site Configuration](screenshots/site-detail.png)
*Site configuration overview with status monitoring and quick actions*

### Site Types Explained

#### 🗂️ Static Sites
Perfect for:
- HTML/CSS/JavaScript websites
- React/Vue/Angular build outputs
- Documentation sites
- Landing pages

Features:
- File management with built-in editor
- Automatic caching for static assets
- Security headers and optimizations
- Custom error pages
- ZIP upload and extraction

#### 🔄 Reverse Proxy
Perfect for:
- Node.js applications
- Python web apps (Django/Flask)
- API backends
- Microservices

Features:
- Health checks and failover
- Request/response header modification
- SSL termination
- WebSocket support
- Configurable timeouts

#### ⚖️ Load Balancer
Perfect for:
- High-traffic applications
- Multi-server deployments
- Redundancy and scaling
- Performance optimization

Features:
- Multiple load balancing algorithms
- Health monitoring
- Session persistence
- Weighted distribution
- Automatic failover

### SSL Certificate Management

#### Automatic Certificates
1. Ensure your domain points to your server
2. Click the SSL enable button for any site
3. Enter your email address
4. Certificate is generated and configured automatically
5. Auto-renewal is set up with systemd timers

#### Certificate Monitoring
- View certificate expiry dates in the SSL dashboard
- Get warnings for certificates expiring within 30 days
- Monitor renewal status and history
- Manual renewal options available

### File Management Features

#### File Operations
- **Upload**: Drag files directly onto the upload area
- **Edit**: Click any text file to edit with syntax highlighting
- **Create**: New files and folders with optional templates
- **Download**: Individual files or entire directories
- **Move**: Drag and drop between folders
- **Rename**: Click rename button and enter new name
- **ZIP Extract**: Upload ZIP files for bulk content deployment

#### Security Features
- File type restrictions prevent dangerous uploads
- Path validation prevents directory traversal attacks
- Size limits prevent resource exhaustion
- Permission controls limit access to site directories only

### Real-time Log Monitoring

- **Live Log Streaming**: Watch nginx logs in real-time
- **Advanced Filtering**: Filter by log level, time range, or search terms
- **Site-Specific Logs**: View logs for individual sites
- **Download Logs**: Export filtered logs for analysis
- **Error Highlighting**: Visual highlighting of errors and warnings

![Log Monitoring](screenshots/logs.png)
*Real-time log viewer with filtering and search capabilities*

## 🔌 API Documentation

### Authentication

All API endpoints require JWT authentication:

```bash
# Login to get token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"

# Use token in subsequent requests
curl -X GET http://localhost:8080/api/sites \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Core Endpoints

#### Sites Management
```bash
# List all sites
GET /api/sites

# Create new site
POST /api/sites
Content-Type: application/json
{
  "name": "example-site",
  "domain": "example.com",
  "type": "static",
  "config": {}
}

# Get site details
GET /api/sites/{id}

# Update site
PUT /api/sites/{id}

# Delete site
DELETE /api/sites/{id}

# Enable/disable site
POST /api/sites/{id}/enable
POST /api/sites/{id}/disable
```

#### SSL Management
```bash
# Get SSL status
GET /api/ssl/sites/{id}/status

# Enable SSL
POST /api/ssl/sites/{id}/enable
Content-Type: application/json
{
  "email": "admin@example.com",
  "force_regenerate": false
}

# Disable SSL
POST /api/ssl/sites/{id}/disable

# Renew certificate
POST /api/ssl/sites/{id}/renew

# List all certificates
GET /api/ssl/certificates

# Get expiring certificates
GET /api/ssl/expiring
```

#### File Management
```bash
# List files in directory
GET /api/files/sites/{id}/files?path=/

# Upload files
POST /api/files/sites/{id}/files/upload
Content-Type: multipart/form-data

# Get file content
GET /api/files/sites/{id}/files/content?file_path=index.html

# Update file content
PUT /api/files/sites/{id}/files/content?file_path=index.html
Content-Type: application/json
{
  "content": "<!DOCTYPE html>..."
}

# Delete file or directory
DELETE /api/files/sites/{id}/files?file_path=old-file.html

# Rename file or directory
POST /api/files/sites/{id}/files/rename?file_path=old-name.html
Content-Type: application/json
{
  "new_name": "new-name.html"
}

# Download file
GET /api/files/sites/{id}/files/download?file_path=document.pdf
```

### Response Format

Success responses:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "example-site",
    "domain": "example.com",
    "ssl_enabled": true
  },
  "message": "Operation completed successfully"
}
```

Error responses:
```json
{
  "detail": "Site not found"
}
```

## 🔒 Security

### Security Features

- **Authentication**: JWT-based authentication with configurable expiry
- **Authorization**: Role-based access control and permission validation
- **Input Validation**: All inputs sanitized and validated
- **Path Security**: Directory traversal protection for file operations
- **Rate Limiting**: Configurable rate limits on API endpoints
- **CSRF Protection**: Cross-site request forgery protection
- **Secure Headers**: Security headers added to all responses
- **File Upload Security**: File type validation and size limits
- **SSL Management**: Secure certificate storage and management

### Security Best Practices

1. **Change Default Credentials**
   ```yaml
   # Edit config.yaml
   admin:
     username: "your-username"
     password: "strong-password-here"
   ```

2. **Use Strong Secret Keys**
   ```bash
   # Generate a secure secret key
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Enable HTTPS**
   - Always use SSL certificates in production
   - Redirect HTTP to HTTPS
   - Use strong cipher suites

4. **Network Security**
   - Run behind a reverse proxy (nginx/Apache)
   - Use firewall rules to restrict access
   - Consider VPN access for administration

5. **Regular Updates**
   - Keep the application updated
   - Monitor security advisories
   - Update SSL certificates before expiry

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/nginx-manager.git
   cd nginx-manager
   ```

2. **Setup Development Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run Development Server**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
   ```

### Project Structure

```
nginx-manager/
├── app/
│   ├── api/              # API endpoints
│   │   ├── sites.py      # Site management
│   │   ├── ssl.py        # SSL certificate management
│   │   ├── files.py      # File management
│   │   └── system.py     # System operations
│   ├── services/         # Business logic
│   │   ├── nginx_service.py    # Nginx operations
│   │   ├── ssl_service.py      # SSL operations
│   │   └── file_service.py     # File operations
│   ├── templates/        # Templates
│   │   ├── nginx/        # Nginx config templates
│   │   └── web/          # HTML templates
│   ├── models.py         # Database models
│   ├── auth.py           # Authentication
│   ├── config.py         # Configuration
│   └── main.py           # Application entry point
├── static/               # CSS, JavaScript, images
├── data/                 # SQLite database and backups
├── install.sh            # Installation script
├── config.yaml.example  # Configuration template
└── requirements.txt      # Python dependencies
```

## 🐛 Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check service status
sudo systemctl status nginx-manager

# Check logs
sudo journalctl -u nginx-manager -f

# Common fixes:
# 1. Check configuration file syntax
# 2. Ensure data directory exists and is writable
# 3. Verify nginx is installed and running
```

#### SSL Certificate Issues
```bash
# Check SSL directories
ls -la ~/.letsencrypt/

# Test permissions
sudo -u www-data test -r ~/.letsencrypt/test_file

# Fix permissions
sudo chown -R $(whoami):www-data ~/.letsencrypt
sudo find ~/.letsencrypt -type d -exec chmod 755 {} \;
```

#### Permission Errors
```bash
# Fix application permissions
sudo chown -R $(whoami):www-data /var/www

# Check nginx configuration permissions
ls -la /etc/nginx/sites-available/
```

### Log Files
- **Application logs**: Check systemd journal with `sudo journalctl -u nginx-manager -f`
- **Nginx logs**: `/var/log/nginx/error.log` and `/var/log/nginx/access.log`
- **SSL logs**: `~/.letsencrypt/logs/letsencrypt.log`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [Bootstrap 5](https://getbootstrap.com/) - UI framework  
- [Let's Encrypt](https://letsencrypt.org/) - Free SSL certificates
- [Font Awesome](https://fontawesome.com/) - Icons
- [SQLite](https://sqlite.org/) - Database engine
- [Claude Code](https://claude.ai/code) - The entire Code

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/nginx-manager/issues)
- **Documentation**: Full documentation coming soon
- **Community**: Join our discussions for tips and best practices

---

**Made with ❤️ for the nginx community**

> Transform your nginx management experience from complex command-line operations to simple point-and-click actions.

**🎯 Perfect for**: Web developers, system administrators, DevOps engineers, and anyone who manages nginx sites but prefers visual interfaces over command-line operations.
