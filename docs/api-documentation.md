# API Documentation

Complete reference for the Nginx Site Manager REST API, including authentication, endpoints, request/response formats, and examples.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Request/Response Format](#requestresponse-format)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Site Management API](#site-management-api)
- [SSL Management API](#ssl-management-api)
- [File Management API](#file-management-api)
- [System Management API](#system-management-api)
- [Monitoring API](#monitoring-api)
- [Code Examples](#code-examples)

## Overview

The Nginx Site Manager API provides programmatic access to all application features through RESTful endpoints. The API uses JSON for data exchange and JWT tokens for authentication.

### Base URL
```
http://your-server:8080/api
```

### API Version
Current version: `v1`
All endpoints are prefixed with `/api` (version included in future releases)

### Content Types
- **Request**: `application/json`
- **Response**: `application/json`
- **File Uploads**: `multipart/form-data`

## Authentication

### Login Endpoint

**POST** `/auth/login`

Authenticate and receive a JWT token for API access.

**Request**:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Token Usage

Include the JWT token in the Authorization header for all API requests:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/sites
```

### Token Refresh

**POST** `/auth/refresh`

Refresh an expired token (if refresh tokens are enabled).

**Request**:
```json
{
  "refresh_token": "your-refresh-token"
}
```

## Request/Response Format

### Standard Response Format

All API responses follow a consistent format:

**Success Response**:
```json
{
  "success": true,
  "data": {
    // Response data
  },
  "message": "Operation completed successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Error Response**:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "domain",
      "issue": "Domain name is required"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Pagination

List endpoints support pagination:

**Request**:
```
GET /api/sites?page=2&limit=10
```

**Response**:
```json
{
  "success": true,
  "data": {
    "items": [...],
    "pagination": {
      "page": 2,
      "limit": 10,
      "total_items": 25,
      "total_pages": 3,
      "has_next": true,
      "has_prev": true
    }
  }
}
```

## Error Handling

### HTTP Status Codes

- **200**: Success
- **201**: Created
- **400**: Bad Request
- **401**: Unauthorized
- **403**: Forbidden
- **404**: Not Found
- **422**: Validation Error
- **429**: Rate Limit Exceeded
- **500**: Internal Server Error

### Error Codes

| Code | Description |
|------|-------------|
| `VALIDATION_ERROR` | Input validation failed |
| `AUTHENTICATION_ERROR` | Authentication failed |
| `AUTHORIZATION_ERROR` | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | Requested resource not found |
| `RESOURCE_CONFLICT` | Resource already exists |
| `EXTERNAL_SERVICE_ERROR` | External service (nginx, certbot) error |
| `SYSTEM_ERROR` | Internal system error |

## Rate Limiting

API requests are rate limited to prevent abuse:

- **Default Limit**: 60 requests per minute per IP
- **Authenticated**: 300 requests per minute per user
- **Headers**: Rate limit info included in response headers

**Rate Limit Headers**:
```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 299
X-RateLimit-Reset: 1642248600
```

## Site Management API

### List Sites

**GET** `/api/sites`

Get a list of all configured sites.

**Query Parameters**:
- `page` (integer): Page number (default: 1)
- `limit` (integer): Items per page (default: 20)
- `type` (string): Filter by site type (`static`, `proxy`, `load_balancer`)
- `enabled` (boolean): Filter by enabled status
- `domain` (string): Filter by domain name (partial match)

**Example Request**:
```bash
curl -H "Authorization: Bearer TOKEN" \
     "http://localhost:8080/api/sites?type=static&enabled=true"
```

**Response**:
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1,
        "name": "example-site",
        "domain": "example.com",
        "type": "static",
        "enabled": true,
        "ssl_enabled": true,
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T12:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total_items": 1,
      "total_pages": 1
    }
  }
}
```

### Get Site Details

**GET** `/api/sites/{id}`

Get detailed information about a specific site.

**Response**:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "example-site",
    "domain": "example.com",
    "type": "static",
    "enabled": true,
    "ssl_enabled": true,
    "config": {
      "document_root": "/var/www/example-site",
      "index_files": ["index.html", "index.htm"],
      "enable_gzip": true,
      "client_max_body_size": "10M"
    },
    "stats": {
      "total_files": 15,
      "disk_usage": "2.4MB",
      "last_modified": "2024-01-15T12:00:00Z"
    },
    "created_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-01-15T12:00:00Z"
  }
}
```

### Create Site

**POST** `/api/sites`

Create a new site configuration.

**Request Body**:
```json
{
  "name": "my-new-site",
  "domain": "mynewsite.com",
  "type": "static",
  "config": {
    "document_root": "/var/www/my-new-site",
    "index_files": ["index.html"],
    "enable_gzip": true,
    "client_max_body_size": "50M",
    "enable_ssl_redirect": false
  }
}
```

**Response**:
```json
{
  "success": true,
  "data": {
    "id": 2,
    "name": "my-new-site",
    "domain": "mynewsite.com",
    "type": "static",
    "enabled": false,
    "ssl_enabled": false,
    "created_at": "2024-01-15T13:00:00Z"
  },
  "message": "Site created successfully"
}
```

### Update Site

**PUT** `/api/sites/{id}`

Update an existing site configuration.

**Request Body**:
```json
{
  "domain": "updated-domain.com",
  "config": {
    "client_max_body_size": "100M",
    "enable_gzip": true
  }
}
```

### Delete Site

**DELETE** `/api/sites/{id}`

Delete a site configuration.

**Query Parameters**:
- `backup_files` (boolean): Create backup of site files (default: true)

**Response**:
```json
{
  "success": true,
  "message": "Site deleted successfully",
  "data": {
    "backup_location": "/backups/example-site-20240115.tar.gz"
  }
}
```

### Enable/Disable Site

**POST** `/api/sites/{id}/enable`
**POST** `/api/sites/{id}/disable`

Enable or disable a site (creates/removes nginx symlink).

**Response**:
```json
{
  "success": true,
  "message": "Site enabled successfully"
}
```

### Site Configuration Templates

**GET** `/api/sites/templates`

Get available site configuration templates.

**Response**:
```json
{
  "success": true,
  "data": {
    "static": {
      "name": "Static Website",
      "description": "Basic HTML/CSS/JS website",
      "config": {
        "document_root": "/var/www/{site_name}",
        "index_files": ["index.html", "index.htm"],
        "enable_gzip": true,
        "client_max_body_size": "10M"
      }
    },
    "proxy": {
      "name": "Reverse Proxy",
      "description": "Proxy to backend application",
      "config": {
        "backend_url": "http://localhost:3000",
        "proxy_timeout": "60s",
        "proxy_headers": {
          "Host": "$host",
          "X-Real-IP": "$remote_addr",
          "X-Forwarded-For": "$proxy_add_x_forwarded_for"
        }
      }
    }
  }
}
```

## SSL Management API

### Get SSL Status

**GET** `/api/ssl/sites/{id}/status`

Get SSL certificate status for a site.

**Response**:
```json
{
  "success": true,
  "data": {
    "ssl_enabled": true,
    "certificate_path": "/home/user/.letsencrypt/live/example.com/fullchain.pem",
    "private_key_path": "/home/user/.letsencrypt/live/example.com/privkey.pem",
    "expiry_date": "2024-04-15T10:00:00Z",
    "days_until_expiry": 89,
    "auto_renewal_enabled": true,
    "last_renewal": "2024-01-15T10:00:00Z"
  }
}
```

### Enable SSL

**POST** `/api/ssl/sites/{id}/enable`

Enable SSL certificate for a site.

**Request Body**:
```json
{
  "email": "admin@example.com",
  "force_regenerate": false,
  "staging": false
}
```

**Response**:
```json
{
  "success": true,
  "data": {
    "certificate_generated": true,
    "certificate_path": "/home/user/.letsencrypt/live/example.com/",
    "auto_renewal_configured": true
  },
  "message": "SSL certificate enabled successfully"
}
```

### Disable SSL

**POST** `/api/ssl/sites/{id}/disable`

Disable SSL certificate for a site.

**Query Parameters**:
- `keep_certificate` (boolean): Keep certificate files (default: true)

### Renew Certificate

**POST** `/api/ssl/sites/{id}/renew`

Force renewal of SSL certificate.

**Request Body**:
```json
{
  "force": false
}
```

### List All Certificates

**GET** `/api/ssl/certificates`

Get all SSL certificates across all sites.

**Response**:
```json
{
  "success": true,
  "data": {
    "certificates": [
      {
        "site_id": 1,
        "domain": "example.com",
        "certificate_path": "/home/user/.letsencrypt/live/example.com/",
        "expiry_date": "2024-04-15T10:00:00Z",
        "days_until_expiry": 89,
        "status": "valid"
      }
    ],
    "summary": {
      "total_certificates": 1,
      "expiring_soon": 0,
      "expired": 0
    }
  }
}
```

### Get Expiring Certificates

**GET** `/api/ssl/expiring`

Get certificates expiring within a specified number of days.

**Query Parameters**:
- `days` (integer): Days threshold (default: 30)

## File Management API

### List Files

**GET** `/api/files/sites/{id}/files`

List files and directories for a static site.

**Query Parameters**:
- `path` (string): Directory path (default: "/")
- `recursive` (boolean): Include subdirectories (default: false)
- `include_hidden` (boolean): Include hidden files (default: false)

**Response**:
```json
{
  "success": true,
  "data": {
    "path": "/",
    "items": [
      {
        "name": "index.html",
        "type": "file",
        "size": 2048,
        "modified": "2024-01-15T12:00:00Z",
        "permissions": "644"
      },
      {
        "name": "assets",
        "type": "directory",
        "size": null,
        "modified": "2024-01-15T11:00:00Z",
        "permissions": "755"
      }
    ],
    "total_items": 2,
    "total_size": 2048
  }
}
```

### Upload Files

**POST** `/api/files/sites/{id}/files/upload`

Upload files to a site directory.

**Request**: `multipart/form-data`
- `files`: One or more files
- `path`: Target directory path (optional, default: "/")
- `extract_zip`: Extract ZIP files (optional, default: false)
- `overwrite`: Overwrite existing files (optional, default: false)

**Example**:
```bash
curl -X POST \
  -H "Authorization: Bearer TOKEN" \
  -F "files=@index.html" \
  -F "files=@style.css" \
  -F "path=/assets" \
  -F "overwrite=true" \
  http://localhost:8080/api/files/sites/1/files/upload
```

**Response**:
```json
{
  "success": true,
  "data": {
    "uploaded_files": [
      {
        "filename": "index.html",
        "size": 2048,
        "path": "/assets/index.html"
      }
    ],
    "failed_files": [],
    "total_uploaded": 1
  },
  "message": "Files uploaded successfully"
}
```

### Get File Content

**GET** `/api/files/sites/{id}/files/content`

Get the content of a text file.

**Query Parameters**:
- `file_path` (string): Path to the file

**Response**:
```json
{
  "success": true,
  "data": {
    "content": "<!DOCTYPE html>\n<html>...",
    "file_type": "html",
    "size": 2048,
    "encoding": "utf-8",
    "last_modified": "2024-01-15T12:00:00Z"
  }
}
```

### Update File Content

**PUT** `/api/files/sites/{id}/files/content`

Update the content of a text file.

**Query Parameters**:
- `file_path` (string): Path to the file

**Request Body**:
```json
{
  "content": "<!DOCTYPE html>\n<html>\n<head>...",
  "encoding": "utf-8",
  "create_backup": true
}
```

### Delete File/Directory

**DELETE** `/api/files/sites/{id}/files`

Delete a file or directory.

**Query Parameters**:
- `file_path` (string): Path to file/directory
- `recursive` (boolean): Delete directories recursively (default: false)
- `create_backup` (boolean): Create backup before deletion (default: true)

### Rename File/Directory

**POST** `/api/files/sites/{id}/files/rename`

Rename a file or directory.

**Query Parameters**:
- `file_path` (string): Current path

**Request Body**:
```json
{
  "new_name": "new-filename.html"
}
```

### Download File

**GET** `/api/files/sites/{id}/files/download`

Download a file or directory as ZIP.

**Query Parameters**:
- `file_path` (string): Path to file/directory

**Response**: Binary file download

### Create Directory

**POST** `/api/files/sites/{id}/files/directory`

Create a new directory.

**Request Body**:
```json
{
  "path": "/new-directory",
  "recursive": true
}
```

## System Management API

### System Status

**GET** `/api/system/status`

Get overall system status and health information.

**Response**:
```json
{
  "success": true,
  "data": {
    "nginx": {
      "status": "running",
      "version": "1.18.0",
      "uptime": "5 days, 10:30:22"
    },
    "application": {
      "status": "running",
      "version": "1.0.0",
      "uptime": "2 days, 14:15:30"
    },
    "system": {
      "cpu_usage": 15.2,
      "memory_usage": 45.8,
      "disk_usage": 67.3,
      "load_average": [0.5, 0.7, 0.6]
    }
  }
}
```

### Nginx Operations

**POST** `/api/system/nginx/test`

Test nginx configuration syntax.

**POST** `/api/system/nginx/reload`

Reload nginx configuration.

**POST** `/api/system/nginx/restart`

Restart nginx service.

**Response**:
```json
{
  "success": true,
  "data": {
    "operation": "reload",
    "output": "nginx: configuration file /etc/nginx/nginx.conf test is successful",
    "exit_code": 0
  },
  "message": "Nginx reloaded successfully"
}
```

### Application Settings

**GET** `/api/system/settings`

Get application configuration settings.

**PUT** `/api/system/settings`

Update application settings.

**Request Body**:
```json
{
  "rate_limit": 10,
  "session_timeout": 45,
  "enable_debug": false
}
```

## Monitoring API

### Health Check

**GET** `/api/health`

Basic health check endpoint (no authentication required).

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T13:00:00Z",
  "version": "1.0.0"
}
```

### Metrics

**GET** `/api/metrics`

Get application metrics (Prometheus format available).

**Query Parameters**:
- `format` (string): Response format (`json` or `prometheus`)

## Code Examples

### Python Client Example

```python
import requests
import json

class NginxManagerClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = None
        self.login(username, password)
    
    def login(self, username, password):
        response = requests.post(
            f"{self.base_url}/auth/login",
            data={"username": username, "password": password}
        )
        response.raise_for_status()
        self.token = response.json()["access_token"]
    
    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}
    
    def list_sites(self):
        response = requests.get(
            f"{self.base_url}/api/sites",
            headers=self._headers()
        )
        return response.json()
    
    def create_site(self, name, domain, site_type="static"):
        data = {
            "name": name,
            "domain": domain,
            "type": site_type
        }
        response = requests.post(
            f"{self.base_url}/api/sites",
            headers=self._headers(),
            json=data
        )
        return response.json()
    
    def enable_ssl(self, site_id, email):
        data = {"email": email}
        response = requests.post(
            f"{self.base_url}/api/ssl/sites/{site_id}/enable",
            headers=self._headers(),
            json=data
        )
        return response.json()

# Usage
client = NginxManagerClient("http://localhost:8080", "admin", "password")
sites = client.list_sites()
print(f"Found {len(sites['data']['items'])} sites")

# Create new site
new_site = client.create_site("example", "example.com")
site_id = new_site["data"]["id"]

# Enable SSL
ssl_result = client.enable_ssl(site_id, "admin@example.com")
```

### JavaScript Client Example

```javascript
class NginxManagerClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
        this.token = null;
    }

    async login(username, password) {
        const response = await fetch(`${this.baseUrl}/auth/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: new URLSearchParams({username, password})
        });
        
        if (!response.ok) throw new Error('Login failed');
        
        const data = await response.json();
        this.token = data.access_token;
        return data;
    }

    async apiCall(endpoint, options = {}) {
        const response = await fetch(`${this.baseUrl}/api${endpoint}`, {
            ...options,
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'API call failed');
        }
        
        return response.json();
    }

    async listSites() {
        return this.apiCall('/sites');
    }

    async createSite(name, domain, type = 'static') {
        return this.apiCall('/sites', {
            method: 'POST',
            body: JSON.stringify({name, domain, type})
        });
    }

    async uploadFiles(siteId, files, path = '/') {
        const formData = new FormData();
        files.forEach(file => formData.append('files', file));
        formData.append('path', path);

        return fetch(`${this.baseUrl}/api/files/sites/${siteId}/files/upload`, {
            method: 'POST',
            headers: {'Authorization': `Bearer ${this.token}`},
            body: formData
        }).then(r => r.json());
    }
}

// Usage
const client = new NginxManagerClient('http://localhost:8080');
await client.login('admin', 'password');

const sites = await client.listSites();
console.log(`Found ${sites.data.items.length} sites`);
```

### cURL Examples

```bash
#!/bin/bash

# Configuration
BASE_URL="http://localhost:8080"
USERNAME="admin"
PASSWORD="password"

# Login and get token
TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD" \
  | jq -r '.access_token')

echo "Token: $TOKEN"

# List sites
curl -s -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/sites" | jq '.'

# Create new site
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test-site","domain":"test.com","type":"static"}' \
  "$BASE_URL/api/sites" | jq '.'

# Enable SSL
SITE_ID=1
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com"}' \
  "$BASE_URL/api/ssl/sites/$SITE_ID/enable" | jq '.'

# Upload file
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -F "files=@index.html" \
  -F "path=/" \
  "$BASE_URL/api/files/sites/$SITE_ID/files/upload"
```

---

For more information, see:
- [User Guide](user-guide.md)
- [Configuration Guide](configuration.md)
- [Security Guide](security.md)