#!/bin/bash

# Nginx Site Manager Demo Setup Script
# This script sets up a complete demo environment with sample sites and data

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
DEMO_USER="demo"
DEMO_PASSWORD="DemoPassword123!"
DEMO_EMAIL="demo@nginx-manager.local"
NGINX_MANAGER_DIR="/opt/nginx-manager"
DEMO_SITES_DIR="/var/www/demo"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE}$1${NC}"
    echo -e "${PURPLE}================================${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root!"
        print_status "Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if nginx-manager is installed
    if [[ ! -d "$NGINX_MANAGER_DIR" ]]; then
        print_error "Nginx Site Manager not found at $NGINX_MANAGER_DIR"
        print_status "Please install Nginx Site Manager first using ./install.sh"
        exit 1
    fi
    
    # Check if nginx-manager service is running
    if ! systemctl is-active --quiet nginx-manager; then
        print_warning "Nginx Site Manager service is not running"
        print_status "Starting nginx-manager service..."
        sudo systemctl start nginx-manager
        sleep 3
    fi
    
    # Check required commands
    local required_commands=("curl" "jq" "python3")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Required command '$cmd' not found"
            print_status "Please install $cmd and try again"
            exit 1
        fi
    done
    
    print_success "System requirements check passed"
}

# Wait for service to be ready
wait_for_service() {
    print_status "Waiting for Nginx Site Manager to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
            print_success "Nginx Site Manager is ready"
            return 0
        fi
        
        print_status "Attempt $attempt/$max_attempts - waiting for service..."
        sleep 2
        ((attempt++))
    done
    
    print_error "Nginx Site Manager did not become ready within expected time"
    print_status "Please check the service logs: sudo journalctl -u nginx-manager"
    exit 1
}

# Create demo user
create_demo_user() {
    print_status "Creating demo user..."
    
    # Check if demo user already exists
    local auth_response
    auth_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$DEMO_USER\",\"password\":\"$DEMO_PASSWORD\"}" \
        http://localhost:8080/auth/login || true)
    
    if echo "$auth_response" | jq -e '.access_token' > /dev/null 2>&1; then
        print_success "Demo user already exists and can authenticate"
        return 0
    fi
    
    # Create demo user by updating config
    local config_file="$NGINX_MANAGER_DIR/config.yaml"
    if [[ -f "$config_file" ]]; then
        print_status "Updating configuration with demo user..."
        sudo sed -i "s/admin_username:.*/admin_username: $DEMO_USER/" "$config_file"
        sudo sed -i "s/admin_password:.*/admin_password: $DEMO_PASSWORD/" "$config_file"
        sudo sed -i "s/admin_email:.*/admin_email: $DEMO_EMAIL/" "$config_file"
        
        # Restart service to pick up config changes
        sudo systemctl restart nginx-manager
        wait_for_service
        
        print_success "Demo user created successfully"
    else
        print_error "Configuration file not found at $config_file"
        exit 1
    fi
}

# Authenticate and get token
authenticate() {
    print_status "Authenticating with demo user..."
    
    local auth_response
    auth_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$DEMO_USER\",\"password\":\"$DEMO_PASSWORD\"}" \
        http://localhost:8080/auth/login)
    
    if ! echo "$auth_response" | jq -e '.access_token' > /dev/null; then
        print_error "Failed to authenticate demo user"
        print_status "Response: $auth_response"
        exit 1
    fi
    
    # Export token for use in API calls
    export AUTH_TOKEN=$(echo "$auth_response" | jq -r '.access_token')
    print_success "Authentication successful"
}

# Create demo directories
create_demo_directories() {
    print_status "Creating demo directories..."
    
    sudo mkdir -p "$DEMO_SITES_DIR"/{portfolio,blog,api,docs}
    sudo chown -R nginx-manager:nginx-manager "$DEMO_SITES_DIR"
    sudo chmod -R 755 "$DEMO_SITES_DIR"
    
    print_success "Demo directories created"
}

# Create sample sites
create_sample_sites() {
    print_header "Creating Sample Sites"
    
    # Site 1: Static Portfolio Site
    create_portfolio_site
    
    # Site 2: Blog Site
    create_blog_site
    
    # Site 3: API Documentation Site
    create_docs_site
    
    print_success "All sample sites created"
}

# Create portfolio site
create_portfolio_site() {
    print_status "Creating portfolio site..."
    
    local site_data='{
        "name": "demo-portfolio",
        "domain": "portfolio.demo.local",
        "site_type": "static",
        "description": "Sample portfolio website showcasing static site capabilities",
        "config": {
            "web_root": "/var/www/demo/portfolio",
            "index_file": "index.html",
            "enable_gzip": true,
            "enable_security_headers": true
        }
    }'
    
    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "$site_data" \
        http://localhost:8080/api/sites/)
    
    if echo "$response" | jq -e '.id' > /dev/null; then
        local site_id=$(echo "$response" | jq -r '.id')
        print_success "Portfolio site created (ID: $site_id)"
        
        # Copy sample content
        sudo cp "$(dirname "$0")/sites/sample-static.html" "$DEMO_SITES_DIR/portfolio/index.html"
        sudo chown nginx-manager:nginx-manager "$DEMO_SITES_DIR/portfolio/index.html"
        
        # Enable the site
        curl -s -X POST \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            "http://localhost:8080/api/sites/$site_id/enable" > /dev/null
            
        print_success "Portfolio site enabled and content deployed"
    else
        print_warning "Failed to create portfolio site: $response"
    fi
}

# Create blog site
create_blog_site() {
    print_status "Creating blog site..."
    
    local site_data='{
        "name": "demo-blog",
        "domain": "blog.demo.local",
        "site_type": "static",
        "description": "Sample blog site with multiple pages",
        "config": {
            "web_root": "/var/www/demo/blog",
            "index_file": "index.html",
            "enable_gzip": true,
            "enable_security_headers": true,
            "custom_error_pages": {
                "404": "404.html"
            }
        }
    }'
    
    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "$site_data" \
        http://localhost:8080/api/sites/)
    
    if echo "$response" | jq -e '.id' > /dev/null; then
        local site_id=$(echo "$response" | jq -r '.id')
        print_success "Blog site created (ID: $site_id)"
        
        # Create blog content
        create_blog_content
        
        # Enable the site
        curl -s -X POST \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            "http://localhost:8080/api/sites/$site_id/enable" > /dev/null
            
        print_success "Blog site enabled and content deployed"
    else
        print_warning "Failed to create blog site: $response"
    fi
}

# Create documentation site
create_docs_site() {
    print_status "Creating documentation site..."
    
    local site_data='{
        "name": "demo-docs",
        "domain": "docs.demo.local",
        "site_type": "static",
        "description": "Sample documentation site",
        "config": {
            "web_root": "/var/www/demo/docs",
            "index_file": "index.html",
            "enable_gzip": true,
            "enable_security_headers": true
        }
    }'
    
    local response
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -d "$site_data" \
        http://localhost:8080/api/sites/)
    
    if echo "$response" | jq -e '.id' > /dev/null; then
        local site_id=$(echo "$response" | jq -r '.id')
        print_success "Documentation site created (ID: $site_id)"
        
        # Create docs content
        create_docs_content
        
        # Enable the site
        curl -s -X POST \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            "http://localhost:8080/api/sites/$site_id/enable" > /dev/null
            
        print_success "Documentation site enabled and content deployed"
    else
        print_warning "Failed to create documentation site: $response"
    fi
}

# Create blog content
create_blog_content() {
    local blog_dir="$DEMO_SITES_DIR/blog"
    
    # Create index.html
    sudo tee "$blog_dir/index.html" > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Demo Blog - Nginx Site Manager</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .post { background: #f9f9f9; padding: 15px; margin: 15px 0; border-radius: 5px; }
        .post h3 { color: #333; margin-top: 0; }
        .date { color: #666; font-size: 0.9em; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📝 Demo Blog</h1>
        <p>A sample blog powered by Nginx Site Manager</p>
    </div>
    
    <div class="post">
        <h3><a href="post1.html">Getting Started with Nginx Site Manager</a></h3>
        <p class="date">Published: December 15, 2024</p>
        <p>Learn how to create your first website with Nginx Site Manager in just a few minutes...</p>
    </div>
    
    <div class="post">
        <h3><a href="post2.html">SSL Certificates Made Easy</a></h3>
        <p class="date">Published: December 10, 2024</p>
        <p>Discover how to secure your website with automatic SSL certificates from Let's Encrypt...</p>
    </div>
    
    <div class="post">
        <h3><a href="post3.html">Advanced Nginx Configuration</a></h3>
        <p class="date">Published: December 5, 2024</p>
        <p>Explore advanced features like reverse proxies, load balancing, and custom configurations...</p>
    </div>
</body>
</html>
EOF

    # Create 404.html
    sudo tee "$blog_dir/404.html" > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Not Found - Demo Blog</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { background: #ffe6e6; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; }
        h1 { color: #cc0000; }
    </style>
</head>
<body>
    <div class="error">
        <h1>404 - Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <p><a href="/">← Back to Blog Home</a></p>
    </div>
</body>
</html>
EOF

    sudo chown -R nginx-manager:nginx-manager "$blog_dir"
}

# Create documentation content
create_docs_content() {
    local docs_dir="$DEMO_SITES_DIR/docs"
    
    sudo tee "$docs_dir/index.html" > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documentation - Nginx Site Manager Demo</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 0; }
        .sidebar { width: 250px; background: #2c3e50; color: white; height: 100vh; position: fixed; padding: 20px; overflow-y: auto; }
        .content { margin-left: 290px; padding: 30px; }
        .sidebar h2 { color: #ecf0f1; border-bottom: 2px solid #34495e; padding-bottom: 10px; }
        .sidebar ul { list-style: none; padding: 0; }
        .sidebar li { margin: 10px 0; }
        .sidebar a { color: #bdc3c7; text-decoration: none; }
        .sidebar a:hover { color: #ecf0f1; }
        .code { background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>📚 Documentation</h2>
        <ul>
            <li><a href="#overview">Overview</a></li>
            <li><a href="#installation">Installation</a></li>
            <li><a href="#static-sites">Static Sites</a></li>
            <li><a href="#ssl">SSL Management</a></li>
            <li><a href="#reverse-proxy">Reverse Proxy</a></li>
            <li><a href="#api">API Reference</a></li>
        </ul>
    </div>
    
    <div class="content">
        <h1 id="overview">🚀 Nginx Site Manager Documentation</h1>
        <p>Welcome to the comprehensive documentation for Nginx Site Manager - the easiest way to manage nginx sites, SSL certificates, and configurations.</p>
        
        <h2 id="installation">📦 Installation</h2>
        <p>Install Nginx Site Manager with a single command:</p>
        <div class="code">curl -sSL https://get.nginx-manager.com | bash</div>
        
        <h2 id="static-sites">🌐 Static Sites</h2>
        <p>Create and manage static websites with ease:</p>
        <div class="code">
# Create a new static site
POST /api/sites/
{
  "name": "my-site",
  "domain": "example.com",
  "site_type": "static"
}
        </div>
        
        <h2 id="ssl">🔒 SSL Management</h2>
        <p>Automatic SSL certificates with Let's Encrypt:</p>
        <div class="code">
# Request SSL certificate
POST /api/sites/{site_id}/ssl/request

# Check certificate status
GET /api/sites/{site_id}/ssl/status
        </div>
        
        <h2 id="reverse-proxy">🔄 Reverse Proxy</h2>
        <p>Configure reverse proxy to backend applications:</p>
        <div class="code">
# Create reverse proxy site
{
  "site_type": "reverse_proxy",
  "config": {
    "backend_url": "http://localhost:3000",
    "health_check_path": "/health"
  }
}
        </div>
        
        <h2 id="api">📡 API Reference</h2>
        <p>Complete REST API for programmatic management:</p>
        <ul>
            <li><code>GET /api/sites/</code> - List all sites</li>
            <li><code>POST /api/sites/</code> - Create new site</li>
            <li><code>PUT /api/sites/{id}</code> - Update site</li>
            <li><code>DELETE /api/sites/{id}</code> - Delete site</li>
        </ul>
    </div>
</body>
</html>
EOF

    sudo chown -R nginx-manager:nginx-manager "$docs_dir"
}

# Update hosts file for demo domains
update_hosts_file() {
    print_status "Updating hosts file for demo domains..."
    
    local domains=("portfolio.demo.local" "blog.demo.local" "docs.demo.local")
    local hosts_entries=""
    
    for domain in "${domains[@]}"; do
        if ! grep -q "$domain" /etc/hosts; then
            hosts_entries+="127.0.0.1 $domain\n"
        fi
    done
    
    if [[ -n "$hosts_entries" ]]; then
        echo -e "\n# Nginx Site Manager Demo Sites" | sudo tee -a /etc/hosts > /dev/null
        echo -e "$hosts_entries" | sudo tee -a /etc/hosts > /dev/null
        print_success "Demo domains added to hosts file"
    else
        print_success "Demo domains already exist in hosts file"
    fi
}

# Print demo access information
print_demo_info() {
    print_header "Demo Environment Ready!"
    
    echo -e "${GREEN}🎉 Demo setup completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Management Interface:${NC}"
    echo -e "  URL: ${YELLOW}http://localhost:8080${NC}"
    echo -e "  Username: ${YELLOW}$DEMO_USER${NC}"
    echo -e "  Password: ${YELLOW}$DEMO_PASSWORD${NC}"
    echo ""
    echo -e "${BLUE}Demo Sites:${NC}"
    echo -e "  Portfolio: ${YELLOW}http://portfolio.demo.local${NC}"
    echo -e "  Blog: ${YELLOW}http://blog.demo.local${NC}"
    echo -e "  Documentation: ${YELLOW}http://docs.demo.local${NC}"
    echo ""
    echo -e "${BLUE}What to try:${NC}"
    echo -e "  1. Log in to the management interface"
    echo -e "  2. Visit the demo sites"
    echo -e "  3. Upload files using the file manager"
    echo -e "  4. Request SSL certificates for your domains"
    echo -e "  5. Create new sites and configurations"
    echo ""
    echo -e "${PURPLE}📚 Learn more:${NC}"
    echo -e "  - Check out the guides in the 'demo/guides/' directory"
    echo -e "  - Read the documentation at http://docs.demo.local"
    echo -e "  - Explore the API at http://localhost:8080/docs"
    echo ""
    echo -e "${GREEN}Happy exploring! 🚀${NC}"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        print_error "Demo setup failed!"
        print_status "Check the logs above for more information."
        print_status "You can try running the script again or check the troubleshooting guide."
    fi
    exit $exit_code
}

# Main execution
main() {
    trap cleanup EXIT
    
    print_header "Nginx Site Manager Demo Setup"
    
    check_root
    check_requirements
    wait_for_service
    create_demo_user
    authenticate
    create_demo_directories
    create_sample_sites
    update_hosts_file
    print_demo_info
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Nginx Site Manager Demo Setup Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -h, --help     Show this help message"
            echo "  --user USER    Demo username (default: demo)"
            echo "  --password PWD Demo password (default: DemoPassword123!)"
            echo ""
            echo "This script sets up a complete demo environment with:"
            echo "  - Demo user account"
            echo "  - Sample static sites (portfolio, blog, docs)"
            echo "  - Local domain configuration"
            echo "  - Sample content and configurations"
            echo ""
            exit 0
            ;;
        --user)
            DEMO_USER="$2"
            shift 2
            ;;
        --password)
            DEMO_PASSWORD="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            print_status "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"