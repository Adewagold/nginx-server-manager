# User Guide

Complete guide to using Nginx Site Manager for creating, managing, and maintaining nginx-powered websites.

## Table of Contents

- [Getting Started](#getting-started)
- [Dashboard Overview](#dashboard-overview)
- [Site Management](#site-management)
- [SSL Certificate Management](#ssl-certificate-management)
- [File Management](#file-management)
- [System Monitoring](#system-monitoring)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)

## Getting Started

### First Login

1. **Access the web interface**:
   ```
   http://your-server-ip:8080
   ```

2. **Login with admin credentials**:
   - Default username: `admin`
   - Default password: `admin123`
   - **⚠️ Change these immediately after first login**

3. **Initial setup**:
   - Update admin password
   - Configure SSL email address
   - Review system settings

### Changing Admin Credentials

1. Click **Settings** in the navigation menu
2. Go to **Admin Settings** tab
3. Enter new username and strong password
4. Click **Update Credentials**
5. You'll be logged out and need to login with new credentials

## Dashboard Overview

The main dashboard provides an overview of your nginx sites and system status.

### Dashboard Sections

#### Site Summary
- **Total Sites**: Number of configured sites
- **Enabled Sites**: Currently active sites
- **SSL Enabled**: Sites with SSL certificates
- **Recent Activity**: Latest site changes

#### System Status
- **Nginx Status**: Service health indicator
- **System Load**: Server performance metrics
- **Disk Usage**: Available storage space
- **Memory Usage**: RAM utilization

#### Quick Actions
- **New Site**: Create a new website
- **SSL Dashboard**: Manage certificates
- **System Logs**: View system activity
- **Settings**: Application configuration

## Site Management

### Creating a New Site

1. **Click "New Site"** button on dashboard
2. **Choose site type**:
   - **Static Site**: HTML, CSS, JS websites
   - **Reverse Proxy**: Forward to backend applications
   - **Load Balancer**: Distribute traffic across multiple servers

#### Creating a Static Site

**Step 1: Basic Information**
- **Site Name**: Internal identifier (letters, numbers, hyphens only)
- **Domain**: Your domain name (e.g., `example.com`)
- **Enable www redirect**: Automatically redirect www.example.com to example.com
- **Description**: Optional site description

**Step 2: Configuration**
- **Document Root**: Where your files will be stored (auto-created)
- **Index Files**: Default files to serve (index.html, index.htm)
- **Enable Directory Listing**: Show file list if no index file
- **Custom Error Pages**: Use custom 404, 500 pages

**Step 3: Advanced Settings** (Optional)
- **Client Max Body Size**: Maximum upload size
- **Enable Gzip**: Compress responses for faster loading
- **Cache Control**: Browser caching headers
- **Security Headers**: Additional security headers

**Example Static Site Creation:**
```
Site Name: my-website
Domain: mysite.com
Document Root: /var/www/my-website
Index Files: index.html, index.htm
Enable Gzip: Yes
Client Max Body Size: 10M
```

#### Creating a Reverse Proxy

**Step 1: Basic Information**
- **Site Name**: Internal identifier
- **Domain**: Your domain name
- **Backend URL**: Target application URL (e.g., `http://localhost:3000`)

**Step 2: Proxy Configuration**
- **Proxy Headers**: Headers to pass to backend
- **Timeout Settings**: Connection and read timeouts
- **Buffer Settings**: Proxy buffering configuration
- **WebSocket Support**: Enable for real-time applications

**Step 3: Load Balancing** (Optional)
- **Multiple Backends**: Add multiple backend servers
- **Load Balancing Method**: Round-robin, least-connections, ip-hash
- **Health Checks**: Monitor backend server health

**Example Reverse Proxy:**
```
Site Name: node-app
Domain: app.mysite.com
Backend URL: http://localhost:3000
Proxy Headers: Host, X-Real-IP, X-Forwarded-For
Timeout: 60s
WebSocket Support: Yes
```

#### Creating a Load Balancer

**Step 1: Basic Information**
- **Site Name**: Internal identifier
- **Domain**: Your domain name

**Step 2: Backend Servers**
- **Server 1**: `http://192.168.1.10:3000`
- **Server 2**: `http://192.168.1.11:3000`
- **Server 3**: `http://192.168.1.12:3000`

**Step 3: Load Balancing Configuration**
- **Method**: Choose balancing algorithm
  - `round_robin`: Distribute requests evenly
  - `least_conn`: Send to server with fewest active connections
  - `ip_hash`: Route based on client IP (session persistence)
  - `weight`: Assign different weights to servers
- **Health Checks**: Monitor server availability
- **Failover**: Automatic failover to healthy servers

**Example Load Balancer:**
```
Site Name: web-cluster
Domain: cluster.mysite.com
Servers:
  - http://192.168.1.10:3000 (weight: 3)
  - http://192.168.1.11:3000 (weight: 2)
  - http://192.168.1.12:3000 (weight: 1)
Method: weighted round-robin
Health Check: /health every 30s
```

### Managing Existing Sites

#### Site List View
The site list shows all configured sites with:
- **Status**: Enabled/Disabled indicator
- **Domain**: Site domain name
- **Type**: Site type (Static, Proxy, Load Balancer)
- **SSL Status**: Certificate status indicator
- **Actions**: Quick action buttons

#### Site Actions

**Enable/Disable Site**
- Click the **power button** to toggle site status
- Disabled sites remain configured but don't serve traffic
- Useful for maintenance or testing

**Edit Site Configuration**
- Click the **edit button** to modify settings
- All creation options can be modified
- Changes are applied immediately after saving

**Delete Site**
- Click the **delete button** to remove site
- **⚠️ Warning**: This permanently deletes the site configuration
- Static site files are moved to backup folder

**View Site Details**
- Click the **info button** for detailed information
- Shows configuration, traffic stats, and logs
- Access recent error logs and performance metrics

### Site Configuration Templates

#### High-Performance Static Site
```yaml
Site Type: Static
Gzip Compression: Enabled
Cache Control: 1 year for assets, 1 hour for HTML
Security Headers: Full set enabled
Client Max Body Size: 50M
Directory Listing: Disabled
```

#### API Backend Proxy
```yaml
Site Type: Reverse Proxy
Backend: http://localhost:8000
Headers: Standard proxy headers + API key
Timeout: 120s
Buffer Size: 8k
WebSocket: Enabled
```

#### Multi-Server Load Balancer
```yaml
Site Type: Load Balancer
Method: least_conn
Health Check: /health every 10s
Failover: Automatic
Session Persistence: IP hash
```

## SSL Certificate Management

### SSL Dashboard

Access the SSL dashboard to view and manage all SSL certificates:
- **Certificate List**: All domains with SSL status
- **Expiry Dates**: Certificates expiring in next 30 days
- **Auto-Renewal Status**: Renewal configuration status
- **Recent Activities**: Certificate generation and renewal logs

### Enabling SSL for a Site

**Method 1: From Site List**
1. Find your site in the site list
2. Click the **SSL shield icon**
3. Enter your email address
4. Click **Enable SSL**

**Method 2: From Site Details**
1. Open site details page
2. Go to **SSL** tab
3. Click **Enable SSL Certificate**
4. Configure SSL settings

### SSL Configuration Options

**Basic SSL Setup**
- **Email Address**: Required for Let's Encrypt registration
- **Auto-Renewal**: Enable automatic certificate renewal
- **Force HTTPS**: Redirect HTTP to HTTPS

**Advanced SSL Settings**
- **Certificate Authority**: Let's Encrypt (production/staging)
- **Key Size**: 2048 or 4096 bits
- **Challenge Type**: HTTP-01 (webroot) or DNS-01
- **Certificate Name**: Custom certificate naming

### SSL Certificate Lifecycle

#### Certificate Generation Process
1. **Domain Validation**: Ensure domain points to your server
2. **Challenge Setup**: Create verification files
3. **Certificate Request**: Submit to Let's Encrypt
4. **Certificate Installation**: Install and configure nginx
5. **Auto-Renewal Setup**: Configure automatic renewal

#### Renewal Process
- **Automatic**: Certificates are renewed 30 days before expiry
- **Manual**: Force renewal from SSL dashboard
- **Monitoring**: Email notifications for renewal failures

### SSL Troubleshooting

#### Common SSL Issues

**Domain Validation Fails**
```
Error: Domain validation failed
Solutions:
1. Ensure DNS points to your server
2. Check firewall allows port 80
3. Verify nginx is running
4. Check domain accessibility
```

**Certificate Installation Fails**
```
Error: Failed to install certificate
Solutions:
1. Check nginx configuration syntax
2. Verify SSL directory permissions
3. Ensure sufficient disk space
4. Review certificate files
```

**Auto-Renewal Fails**
```
Error: Certificate renewal failed
Solutions:
1. Check certbot logs
2. Verify SSL directories exist
3. Test manual renewal
4. Check system permissions
```

## File Management

File management is available for static sites, providing a complete file browser and editor.

### Accessing File Manager

1. **From Site List**: Click the **folder icon** next to a static site
2. **From Site Details**: Click **Manage Files** tab

### File Browser Features

#### Navigation
- **Breadcrumb Navigation**: Click path segments to navigate
- **Folder Tree**: Expandable folder structure
- **Back/Forward**: Browser-style navigation
- **Home Button**: Return to site root

#### File Operations

**Upload Files**
- **Drag & Drop**: Drag files from your computer
- **Click to Browse**: Select files using file dialog
- **Bulk Upload**: Upload multiple files at once
- **ZIP Extraction**: Upload and auto-extract ZIP archives

**File Management**
- **Create File**: New HTML, CSS, JS files with templates
- **Create Folder**: Organize content in directories
- **Rename**: Rename files and folders
- **Move**: Drag files between folders
- **Copy**: Duplicate files
- **Delete**: Remove files and folders

**Download Options**
- **Single File**: Download individual files
- **Multiple Files**: Select and download multiple files
- **Folder as ZIP**: Download entire folders as ZIP archives

### File Editor

#### Built-in Code Editor
- **Syntax Highlighting**: HTML, CSS, JavaScript, JSON, XML, Markdown
- **Line Numbers**: For easy reference
- **Find & Replace**: Search and replace text
- **Auto-Indentation**: Proper code formatting
- **Real-time Preview**: Preview HTML files while editing

#### Supported File Types

**Editable Files**
- **Text**: .txt, .md, .readme
- **Web**: .html, .css, .js, .json, .xml
- **Config**: .yml, .yaml, .ini, .conf
- **Code**: .py, .php, .rb (view-only for security)

**Previewable Files**
- **Images**: .png, .jpg, .jpeg, .gif, .svg, .ico
- **Documents**: .pdf (basic viewer)
- **Archives**: .zip (file listing)

#### Editor Features

**File Templates**
When creating new files, choose from templates:
- **HTML5 Document**: Complete HTML5 boilerplate
- **CSS Stylesheet**: Basic CSS structure with reset
- **JavaScript Module**: Modern JS module template
- **README**: Markdown documentation template

**Code Assistance**
- **Auto-completion**: Basic HTML tag completion
- **Bracket Matching**: Highlight matching brackets
- **Code Folding**: Collapse code sections
- **Error Highlighting**: Basic syntax error detection

### File Security

#### Upload Restrictions
- **File Type Validation**: Only safe file types allowed
- **Size Limits**: Maximum file size enforced
- **Path Validation**: Prevent directory traversal attacks
- **Virus Scanning**: Optional malware detection

#### Permission System
- **Site Isolation**: Files isolated to site directories
- **User Permissions**: Respect system file permissions
- **Backup Integration**: Automatic backups before changes

### Bulk Operations

#### Bulk File Upload
1. **Select Multiple Files**: Use Ctrl+Click or Shift+Click
2. **Drag to Upload Area**: Drop all files at once
3. **Progress Tracking**: Monitor upload progress
4. **Error Handling**: Retry failed uploads

#### ZIP Archive Handling
1. **Upload ZIP File**: Drag ZIP to upload area
2. **Preview Contents**: Review files before extraction
3. **Extract Options**: Choose extraction location
4. **Automatic Cleanup**: Remove ZIP after extraction

## System Monitoring

### System Status Page

Access comprehensive system information:
- **Service Status**: Nginx, application, and system services
- **Resource Usage**: CPU, memory, disk, network
- **Performance Metrics**: Response times, error rates
- **Recent Activity**: System events and changes

### Log Viewer

#### Real-time Log Streaming
- **Live Updates**: Logs update automatically
- **Multiple Sources**: Application, nginx, SSL, system logs
- **Filtering**: Filter by log level, time range, keywords
- **Search**: Find specific log entries

#### Log Management
- **Download Logs**: Export logs for analysis
- **Log Rotation**: Automatic log file rotation
- **Archive Access**: View historical log files
- **Log Cleanup**: Manage log file storage

### Performance Monitoring

#### Site Performance
- **Response Times**: Track site response times
- **Error Rates**: Monitor 4xx and 5xx errors
- **Traffic Metrics**: Requests per second, bandwidth
- **SSL Performance**: Certificate validation times

#### System Health
- **Resource Alerts**: Warnings for high resource usage
- **Service Monitoring**: Automatic service health checks
- **Uptime Tracking**: System availability statistics
- **Performance Trends**: Historical performance data

## Advanced Features

### Configuration Backup & Restore

#### Automatic Backups
- **Schedule**: Daily automatic backups
- **Retention**: Keep backups for 30 days
- **Content**: Site configs, SSL certificates, database
- **Compression**: Compressed backup files

#### Manual Backup
1. Go to **Settings** → **Backup & Restore**
2. Click **Create Backup Now**
3. Choose backup content:
   - Site configurations
   - Website files
   - SSL certificates
   - Database
4. Download backup file

#### Restore Process
1. Upload backup file
2. Select content to restore
3. Choose restore options:
   - Overwrite existing
   - Merge with existing
   - Create new sites
4. Confirm and restore

### Custom Nginx Configuration

#### Configuration Templates
- **Template Editing**: Modify nginx config templates
- **Variable Substitution**: Dynamic configuration generation
- **Validation**: Automatic syntax validation
- **Backup**: Template backups before changes

#### Advanced Nginx Features
- **Custom Directives**: Add custom nginx directives
- **Location Blocks**: Define custom location handling
- **Upstream Configuration**: Advanced load balancing
- **Rate Limiting**: Configure request rate limiting

### API Integration

#### REST API Access
- **Authentication**: JWT token-based API access
- **Endpoints**: Full CRUD operations for all features
- **Documentation**: Built-in API documentation
- **Rate Limiting**: API request rate limiting

#### Webhook Integration
- **Event Notifications**: Webhooks for site events
- **Custom Endpoints**: Configure webhook destinations
- **Event Types**: Site created, SSL renewed, errors
- **Retry Logic**: Automatic webhook retry on failure

## Best Practices

### Site Organization

#### Naming Conventions
- **Site Names**: Use descriptive, lowercase names with hyphens
- **Domain Structure**: Organize subdomains logically
- **File Structure**: Maintain clean directory structure

#### Configuration Management
- **Documentation**: Document site purposes and configurations
- **Version Control**: Use git for static site content
- **Testing**: Test configurations before deploying
- **Monitoring**: Set up monitoring for critical sites

### Security Best Practices

#### General Security
- **Strong Passwords**: Use complex admin passwords
- **Regular Updates**: Keep system and application updated
- **SSL Certificates**: Enable HTTPS for all public sites
- **Access Control**: Limit administrative access

#### File Security
- **Upload Validation**: Restrict allowed file types
- **Permission Management**: Use appropriate file permissions
- **Regular Audits**: Review uploaded content regularly
- **Backup Security**: Secure backup files

### Performance Optimization

#### Static Site Optimization
- **Compression**: Enable gzip compression
- **Caching**: Set appropriate cache headers
- **Image Optimization**: Optimize images before upload
- **Minification**: Minify CSS and JavaScript

#### Proxy Configuration
- **Connection Pooling**: Use persistent connections
- **Buffer Configuration**: Optimize buffer sizes
- **Timeout Settings**: Set appropriate timeouts
- **Health Checks**: Monitor backend health

### Maintenance Procedures

#### Regular Maintenance
- **Log Review**: Regularly review system logs
- **Certificate Monitoring**: Monitor SSL certificate expiry
- **Performance Review**: Analyze site performance
- **Backup Verification**: Test backup restoration

#### Troubleshooting Workflow
1. **Identify Issue**: Use monitoring and logs
2. **Isolate Problem**: Test individual components
3. **Check Configuration**: Validate nginx configs
4. **Review Recent Changes**: Check recent modifications
5. **Apply Fix**: Implement and test solution
6. **Document Solution**: Record fix for future reference

---

For additional information, see:
- [Configuration Guide](configuration.md)
- [API Documentation](api-documentation.md)
- [Security Guide](security.md)
- [Troubleshooting](troubleshooting.md)