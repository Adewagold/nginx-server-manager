# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an nginx site manager - a web-based platform for managing nginx sites, SSL certificates, and configurations on Linux systems. It provides a simple interface for creating and managing nginx virtual hosts without requiring sudo access after initial setup.

## Technology Stack

- **Backend**: Python FastAPI
- **Database**: SQLite
- **Frontend**: HTML/CSS/JavaScript (served by FastAPI)  
- **Authentication**: JWT
- **SSL**: Let's Encrypt integration via certbot

## Common Development Commands

```bash
# Setup and installation
./install.sh                           # Initial system setup
cp config.yaml.example config.yaml     # Create config file
pip install -r requirements.txt        # Install dependencies

# Development server
uvicorn app.main:app --reload          # Run development server
uvicorn app.main:app --host 0.0.0.0 --port 8080  # Run with custom host/port

# Testing nginx configurations
nginx -t                               # Test nginx config syntax
systemctl reload nginx                 # Reload nginx service

# Database operations
sqlite3 data/sites.db                  # Access SQLite database directly
```

## Project Structure

The project follows a FastAPI application structure:

- `app/main.py` - FastAPI application entry point
- `app/config.py` - Configuration management (reads config.yaml)
- `app/auth.py` - JWT authentication logic
- `app/models.py` - SQLite database models
- `app/api/` - API endpoint modules (sites.py, ssl.py, system.py)
- `app/services/` - Business logic services (nginx_service.py, ssl_service.py, file_service.py)
- `app/templates/` - Template files (nginx configs and web templates)
- `static/` - CSS, JavaScript, and static assets
- `data/` - SQLite database and generated nginx configs

## Site Types and Configuration

The application supports three main site types:

1. **Static sites** - Serve HTML/CSS/JS files from web root
2. **Reverse proxy** - Forward requests to backend applications
3. **Load balancer** - Distribute requests across multiple backend servers

Each site type has corresponding nginx configuration templates in `app/templates/nginx/`.

## Database Schema

Uses SQLite with two main tables:
- `sites` - Basic site information and metadata
- `site_configs` - JSON configuration data for each site

## Authentication & Security

- JWT token-based authentication
- Configurable admin credentials in config.yaml
- File upload validation and restrictions
- Nginx configuration validation before applying changes
- Runs with minimal system permissions after setup

## Configuration

Main configuration in `config.yaml`:
- Application settings (host, port, secret key)
- Admin credentials
- System paths (nginx directories, web root, SSL certificates)
- Nginx command configurations

## API Structure

RESTful API with endpoints organized by functionality:
- `/auth/*` - Authentication
- `/api/sites/*` - Site management
- `/api/ssl/*` - SSL certificate operations
- `/api/system/*` - System status and nginx operations
- `/api/files/*` - File management

## Development Notes

- The application requires initial setup via install.sh to configure system permissions
- Nginx configurations are generated from templates and validated before applying
- SSL certificates are managed through Let's Encrypt integration
- File operations are restricted to designated web directories for security