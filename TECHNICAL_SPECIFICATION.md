# Nginx Site Manager - Technical Specification

## Project Overview
A web-based platform for managing nginx sites, SSL certificates, and configurations on Linux systems. Provides a simple interface for creating, managing, and monitoring nginx virtual hosts without requiring sudo access after initial setup.

## Technology Stack
- **Backend**: Python FastAPI
- **Database**: SQLite
- **Frontend**: HTML/CSS/JavaScript (served by FastAPI)
- **Authentication**: JWT with configurable credentials
- **SSL**: Let's Encrypt integration via certbot

## Core Features

### 1. Site Management
- Create/edit/delete nginx sites
- Support for static sites, reverse proxy, and load balancing
- Template-based configuration generation
- Enable/disable sites
- Configuration validation before applying

### 2. SSL Certificate Management
- Automatic Let's Encrypt certificate generation
- Certificate renewal automation
- SSL configuration templates

### 3. File Management
- Upload static site files
- Basic file browser for site directories
- Log file viewing

### 4. System Integration
- Auto-detect existing nginx sites
- Import existing configurations
- Nginx service management (reload, test config)

## Project Structure
```
nginx-manager/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Configuration management
│   ├── auth.py              # Authentication logic
│   ├── models.py            # SQLite models
│   ├── api/
│   │   ├── __init__.py
│   │   ├── sites.py         # Site management endpoints
│   │   ├── ssl.py           # SSL certificate endpoints
│   │   └── system.py        # System status endpoints
│   ├── services/
│   │   ├── __init__.py
│   │   ├── nginx_service.py # Nginx operations
│   │   ├── ssl_service.py   # SSL operations
│   │   └── file_service.py  # File operations
│   └── templates/
│       ├── nginx/           # Nginx config templates
│       └── web/             # HTML templates
├── static/                  # CSS, JS, images
├── data/
│   ├── sites.db            # SQLite database
│   └── nginx_configs/      # Generated nginx configs
├── install.sh              # Setup script
├── requirements.txt
├── config.yaml.example     # Configuration template
└── README.md
```

## Configuration File (config.yaml)
```yaml
app:
  host: "127.0.0.1"
  port: 8080
  secret_key: "your-secret-key"

admin:
  username: "admin"
  password: "admin123"

paths:
  nginx_config_dir: "/etc/nginx/sites-available"
  nginx_enabled_dir: "/etc/nginx/sites-enabled"
  web_root: "/var/www"
  ssl_cert_dir: "/etc/letsencrypt/live"

nginx:
  test_command: "nginx -t"
  reload_command: "systemctl reload nginx"
```

## Database Schema
```sql
-- Sites table
CREATE TABLE sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    domain TEXT NOT NULL,
    type TEXT NOT NULL, -- 'static', 'proxy', 'load_balancer'
    config_path TEXT,
    enabled BOOLEAN DEFAULT 0,
    ssl_enabled BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Site configurations (JSON storage)
CREATE TABLE site_configs (
    site_id INTEGER PRIMARY KEY,
    config_data TEXT, -- JSON string
    FOREIGN KEY (site_id) REFERENCES sites (id)
);
```

## API Endpoints

### Authentication
- `POST /auth/login` - Login with username/password
- `POST /auth/logout` - Logout

### Sites Management
- `GET /api/sites` - List all sites
- `POST /api/sites` - Create new site
- `GET /api/sites/{site_id}` - Get site details
- `PUT /api/sites/{site_id}` - Update site
- `DELETE /api/sites/{site_id}` - Delete site
- `POST /api/sites/{site_id}/enable` - Enable site
- `POST /api/sites/{site_id}/disable` - Disable site

### SSL Management
- `POST /api/ssl/{site_id}/generate` - Generate SSL certificate
- `GET /api/ssl/{site_id}/status` - Check certificate status
- `POST /api/ssl/{site_id}/renew` - Renew certificate

### System
- `GET /api/system/status` - Nginx and system status
- `POST /api/system/reload` - Reload nginx
- `GET /api/system/logs` - View nginx logs

### File Management
- `POST /api/files/upload/{site_id}` - Upload files to site
- `GET /api/files/{site_id}` - List site files

## Installation Script (install.sh)
```bash
#!/bin/bash
# Auto-detect OS and install dependencies
# Install nginx, python3, pip if not present
# Create non-sudo user for the application
# Set up directory permissions
# Install Python dependencies
# Create systemd service
# Generate initial config
```

## Site Types & Templates

### 1. Static Site
```nginx
server {
    listen 80;
    server_name example.com;
    root /var/www/example.com;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### 2. Reverse Proxy
```nginx
server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Load Balancer
```nginx
upstream backend {
    server 192.168.1.10:8080;
    server 192.168.1.11:8080;
}

server {
    listen 80;
    server_name lb.example.com;
    
    location / {
        proxy_pass http://backend;
    }
}
```

## Security Considerations
- JWT authentication for API access
- File upload restrictions and validation
- Nginx configuration validation before applying
- Separate user account with minimal permissions
- Rate limiting on API endpoints
- Input sanitization for all user inputs

## Development Setup
1. Clone repository
2. Run `./install.sh` for system setup
3. Copy `config.yaml.example` to `config.yaml`
4. Install dependencies: `pip install -r requirements.txt`
5. Run: `uvicorn app.main:app --reload`
6. Access at `http://localhost:8080`

## Future Enhancements
- Git integration for deployments
- Backup/restore functionality
- Multi-server management
- Performance monitoring
- Advanced security rules
- Docker container support
