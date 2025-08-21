# Nginx Site Manager

A web-based platform for managing nginx sites, SSL certificates, and configurations on Linux systems. Provides a simple interface for creating, managing, and monitoring nginx virtual hosts without requiring sudo access after initial setup.

## Features

- **Site Management**: Create, edit, delete, enable/disable nginx sites
- **Multiple Site Types**: Static sites, reverse proxy, and load balancer configurations
- **Web Interface**: Modern, responsive web UI for easy management
- **API Access**: RESTful API for automation and integration
- **Authentication**: JWT-based authentication with configurable credentials
- **Configuration Templates**: Pre-built nginx configuration templates
- **Real-time Status**: Monitor site status and nginx service health
- **Security**: Input validation, rate limiting, and proper permission management

## Technology Stack

- **Backend**: Python FastAPI
- **Database**: SQLite
- **Frontend**: HTML/CSS/JavaScript with Bootstrap 5
- **Authentication**: JWT tokens
- **Templates**: Jinja2 for nginx configurations

## Quick Start

### 1. System Requirements

- Linux system (Ubuntu/Debian or CentOS/RHEL/Fedora)
- Python 3.7+
- nginx
- sudo privileges for initial setup

### 2. Installation

```bash
# Clone the repository
git clone <repository-url>
cd nginx-manager

# Run the installation script
chmod +x install.sh
sudo ./install.sh
```

The installation script will:
- Install required system packages (nginx, python3, certbot)
- Create a dedicated `nginx-manager` user
- Set up proper directory permissions
- Install Python dependencies
- Create a systemd service

### 3. Configuration

```bash
# Copy and edit the configuration file
sudo cp config.yaml.example /opt/nginx-manager/config.yaml
sudo nano /opt/nginx-manager/config.yaml
```

**Important**: Change the default admin credentials and secret key:

```yaml
app:
  secret_key: "your-very-secure-secret-key-change-this-in-production"

admin:
  username: "admin"
  password: "your-secure-password"  # Change this!
```

### 4. Start the Service

```bash
# Start nginx if not already running
sudo systemctl start nginx
sudo systemctl enable nginx

# Start the nginx-manager service
sudo systemctl start nginx-manager
sudo systemctl enable nginx-manager

# Check service status
sudo systemctl status nginx-manager
```

### 5. Access the Web Interface

Open your web browser and navigate to:
- **URL**: `http://your-server-ip:8080`
- **Default Login**: `admin` / `admin123` (change immediately!)

## Usage Guide

### Creating Sites

1. **Access the Web Interface**: Navigate to the sites page
2. **Click "Create New Site"**
3. **Choose Site Type**:
   - **Static Site**: For HTML/CSS/JS files
   - **Reverse Proxy**: Forward requests to a backend application
   - **Load Balancer**: Distribute requests across multiple servers
4. **Fill in Details**:
   - Site name (internal identifier)
   - Domain name
   - Configuration options based on site type
5. **Create and Enable**: Choose to create only or create and enable immediately

### Site Types

#### Static Sites
- Serves files from `/var/www/[site-name]/`
- Automatically creates directory structure
- Supports custom index files
- Includes security headers and caching rules

#### Reverse Proxy
- Forwards requests to a backend application
- Configurable upstream URL
- Includes proper proxy headers
- Timeout and buffer settings

#### Load Balancer
- Distributes requests across multiple backend servers
- Round-robin load balancing
- Health check support
- Automatic failover

### Managing Sites

- **Enable/Disable**: Toggle site availability
- **View Configuration**: See generated nginx config
- **Check Status**: Monitor site health
- **Delete**: Remove site and configuration

## API Documentation

The platform provides a RESTful API for automation. Access the interactive documentation at:
- **Swagger UI**: `http://your-server:8080/docs` (when debug mode is enabled)

### Authentication

All API requests require a JWT token obtained through login:

```bash
# Login and get token
curl -X POST "http://your-server:8080/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=your-password"

# Use token in subsequent requests
curl -X GET "http://your-server:8080/api/sites/" \
  -H "Authorization: Bearer your-token-here"
```

### Key Endpoints

- `POST /auth/login` - Authenticate and get token
- `GET /api/sites/` - List all sites
- `POST /api/sites/` - Create new site
- `GET /api/sites/{id}` - Get site details
- `PUT /api/sites/{id}` - Update site
- `DELETE /api/sites/{id}` - Delete site
- `POST /api/sites/{id}/enable` - Enable site
- `POST /api/sites/{id}/disable` - Disable site
- `GET /api/system/status` - System status
- `POST /api/system/reload` - Reload nginx

## Configuration Reference

### Main Configuration (`config.yaml`)

```yaml
app:
  host: "127.0.0.1"           # Bind address
  port: 8080                  # Port number
  debug: false                # Debug mode
  secret_key: "change-this"   # JWT secret key
  access_token_expire_minutes: 1440  # Token expiration

admin:
  username: "admin"           # Admin username
  password: "secure-password" # Admin password

paths:
  nginx_config_dir: "/etc/nginx/sites-available"
  nginx_enabled_dir: "/etc/nginx/sites-enabled"
  web_root: "/var/www"
  ssl_cert_dir: "/etc/letsencrypt/live"
  data_dir: "./data"
  log_dir: "/var/log/nginx"

nginx:
  test_command: "sudo nginx -t"
  reload_command: "sudo systemctl reload nginx"
  restart_command: "sudo systemctl restart nginx"
  status_command: "sudo systemctl status nginx"
```

## Development

### Running in Development Mode

```bash
# Install dependencies
pip install -r requirements.txt

# Copy configuration
cp config.yaml.example config.yaml

# Edit paths for development (use local directories)
nano config.yaml

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

### Project Structure

```
nginx-manager/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Configuration management
│   ├── auth.py              # Authentication logic
│   ├── models.py            # Database models
│   ├── api/
│   │   ├── __init__.py
│   │   └── sites.py         # Site management endpoints
│   ├── services/
│   │   ├── __init__.py
│   │   └── nginx_service.py # Nginx operations
│   └── templates/
│       ├── nginx/           # Nginx config templates
│       └── web/             # HTML templates
├── static/                  # CSS, JS, images
│   ├── css/
│   └── js/
├── data/                    # SQLite database
├── install.sh              # Installation script
├── requirements.txt        # Python dependencies
├── config.yaml.example    # Configuration template
└── README.md              # This file
```

## Security Considerations

### Initial Setup
- Change default admin credentials immediately
- Use a strong secret key for JWT tokens
- Configure firewall to restrict access to port 8080
- Consider using a reverse proxy (nginx) for SSL termination

### Ongoing Security
- Regularly update the system and dependencies
- Monitor access logs
- Use strong passwords
- Enable rate limiting (configured by default)
- Review nginx configurations before applying

### File Permissions
The installation script sets up proper permissions:
- Application runs as `nginx-manager` user
- Limited sudo access for nginx operations only
- Web directories owned by `nginx-manager:www-data`

## Troubleshooting

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

#### Permission Errors
```bash
# Fix permissions
sudo chown -R nginx-manager:nginx-manager /opt/nginx-manager
sudo chown -R nginx-manager:www-data /var/www
```

#### Database Issues
```bash
# Check database permissions
ls -la /opt/nginx-manager/data/

# Recreate database (will lose data!)
sudo rm /opt/nginx-manager/data/sites.db
sudo systemctl restart nginx-manager
```

### Log Files
- Application logs: `/var/log/nginx-manager/app.log`
- Service logs: `sudo journalctl -u nginx-manager`
- Nginx logs: `/var/log/nginx/`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the troubleshooting section above
- Review the logs for error messages
- Open an issue on GitHub with detailed information about your problem

## Roadmap

Future enhancements planned:
- SSL certificate management with Let's Encrypt integration
- File upload and management for static sites
- Backup and restore functionality
- Multi-server management
- Advanced nginx configuration options
- Monitoring and alerting
- Docker container support