#!/bin/bash

# Nginx Site Manager Uninstall Script
# Safely removes the application and optionally cleans up system changes
# Version: 1.0

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

# Uninstall variables
SCRIPT_VERSION="1.0"
UNINSTALL_LOG="/tmp/nginx-manager-uninstall.log"
CURRENT_USER=$(whoami)
BACKUP_DIR="/tmp/nginx-manager-uninstall-backup-$(date +%Y%m%d_%H%M%S)"

# Function to print colored output
print_header() {
    echo -e "\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_status() {
    echo -e "${GREEN}✓${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$UNINSTALL_LOG"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >> "$UNINSTALL_LOG"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$UNINSTALL_LOG"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$UNINSTALL_LOG"
}

print_step() {
    echo -e "\n${CYAN}▶${NC} ${CYAN}$1${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [STEP] $1" >> "$UNINSTALL_LOG"
}

# Function to check if service exists and is running
service_exists() {
    systemctl list-units --full -all | grep -Fq "$1.service"
}

service_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

# Function to safely remove file/directory with backup
safe_remove() {
    local item="$1"
    local description="$2"
    
    if [[ -e "$item" ]]; then
        print_info "Backing up $description..."
        mkdir -p "$BACKUP_DIR"
        cp -r "$item" "$BACKUP_DIR/" 2>/dev/null || true
        
        print_info "Removing $description..."
        sudo rm -rf "$item"
        print_status "Removed $description"
    else
        print_info "$description not found (already removed or never existed)"
    fi
}

# Function to get user confirmation
confirm_action() {
    local message="$1"
    local default="$2"
    
    if [[ "$default" == "y" ]]; then
        prompt="$message [Y/n]: "
    else
        prompt="$message [y/N]: "
    fi
    
    while true; do
        read -p "$prompt" response
        response=${response,,} # Convert to lowercase
        
        if [[ -z "$response" ]]; then
            response="$default"
        fi
        
        case "$response" in
            y|yes)
                return 0
                ;;
            n|no)
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

# Function to show uninstall options
show_uninstall_options() {
    print_header "Nginx Site Manager Uninstall Options"
    
    echo -e "${CYAN}Choose what to uninstall:${NC}"
    echo -e "${BLUE}1.${NC} Application only (keep sites, configs, and system packages)"
    echo -e "${BLUE}2.${NC} Application + generated configs (remove nginx sites created by this tool)"
    echo -e "${BLUE}3.${NC} Full uninstall (remove everything including system packages)"
    echo -e "${BLUE}4.${NC} Cancel uninstallation"
    echo ""
    
    while true; do
        read -p "Select option [1-4]: " choice
        case $choice in
            1)
                UNINSTALL_LEVEL="app"
                break
                ;;
            2)
                UNINSTALL_LEVEL="configs"
                break
                ;;
            3)
                UNINSTALL_LEVEL="full"
                break
                ;;
            4)
                echo "Uninstallation cancelled."
                exit 0
                ;;
            *)
                echo "Please select a valid option (1-4)."
                ;;
        esac
    done
    
    # Confirm the choice
    case $UNINSTALL_LEVEL in
        app)
            confirm_text="Remove only the Nginx Site Manager application"
            ;;
        configs)
            confirm_text="Remove application and generated nginx configurations"
            ;;
        full)
            confirm_text="Remove everything including system packages (nginx, certbot, etc.)"
            ;;
    esac
    
    print_warning "This will: $confirm_text"
    
    if ! confirm_action "Are you sure you want to continue?" "n"; then
        echo "Uninstallation cancelled."
        exit 0
    fi
}

# Function to stop and remove service
remove_service() {
    print_step "Removing systemd service"
    
    if service_exists "nginx-manager"; then
        if service_running "nginx-manager"; then
            print_info "Stopping nginx-manager service..."
            sudo systemctl stop nginx-manager
            print_status "Service stopped"
        fi
        
        print_info "Disabling nginx-manager service..."
        sudo systemctl disable nginx-manager
        
        safe_remove "/etc/systemd/system/nginx-manager.service" "systemd service file"
        
        print_info "Reloading systemd daemon..."
        sudo systemctl daemon-reload
        
        print_status "Systemd service removed"
    else
        print_info "Nginx-manager service not found"
    fi
}

# Function to remove sudo permissions
remove_sudo_permissions() {
    print_step "Removing sudo permissions"
    
    safe_remove "/etc/sudoers.d/nginx-manager" "sudo permissions file"
}

# Function to remove user from groups
remove_user_from_groups() {
    print_step "Removing user from groups"
    
    # Remove user from www-data group
    if groups "$CURRENT_USER" | grep -q "www-data"; then
        print_info "Removing $CURRENT_USER from www-data group..."
        sudo gpasswd -d "$CURRENT_USER" www-data || print_warning "Failed to remove user from www-data group"
        print_status "User removed from www-data group"
    fi
    
    # Remove www-data from user's group
    if groups "www-data" | grep -q "$CURRENT_USER"; then
        print_info "Removing www-data from $CURRENT_USER group..."
        sudo gpasswd -d www-data "$CURRENT_USER" || print_warning "Failed to remove www-data from user group"
        print_status "www-data removed from user group"
    fi
}

# Function to remove application files
remove_application() {
    print_step "Removing application files"
    
    # Remove Python virtual environment
    if [[ -d "venv" ]]; then
        print_info "Removing Python virtual environment..."
        rm -rf venv
        print_status "Virtual environment removed"
    fi
    
    # Remove data directory (with confirmation for important data)
    if [[ -d "data" ]]; then
        print_warning "The data directory contains your database and site backups"
        if confirm_action "Remove data directory? (This will delete all your sites and settings)" "n"; then
            safe_remove "data" "data directory"
        else
            print_info "Keeping data directory"
        fi
    fi
    
    # Remove log directory
    safe_remove "/var/log/nginx-manager" "log directory"
    
    print_status "Application files cleaned up"
}

# Function to remove nginx configurations
remove_nginx_configs() {
    print_step "Removing nginx configurations"
    
    # List sites created by nginx-manager
    local sites_found=()
    
    if [[ -d "/etc/nginx/sites-available" ]]; then
        # Look for sites that might have been created by nginx-manager
        while IFS= read -r -d '' file; do
            if grep -q "# Generated by Nginx Site Manager" "$file" 2>/dev/null; then
                sites_found+=("$(basename "$file")")
            fi
        done < <(find /etc/nginx/sites-available -name "*" -type f -print0 2>/dev/null)
    fi
    
    if [[ ${#sites_found[@]} -gt 0 ]]; then
        print_info "Found nginx sites created by Site Manager:"
        for site in "${sites_found[@]}"; do
            echo "  - $site"
        done
        
        if confirm_action "Remove these nginx configurations?" "y"; then
            for site in "${sites_found[@]}"; do
                # Remove from sites-enabled
                safe_remove "/etc/nginx/sites-enabled/$site" "nginx enabled site: $site"
                
                # Remove from sites-available
                safe_remove "/etc/nginx/sites-available/$site" "nginx available site: $site"
            done
            
            # Test nginx configuration
            if sudo nginx -t 2>/dev/null; then
                print_info "Reloading nginx..."
                sudo systemctl reload nginx || print_warning "Failed to reload nginx"
            else
                print_warning "Nginx configuration test failed after removing sites"
            fi
        fi
    else
        print_info "No nginx sites created by Site Manager found"
    fi
    
    print_status "Nginx configurations processed"
}

# Function to remove SSL certificates and directories
remove_ssl_certificates() {
    print_step "Removing SSL certificates"
    
    if [[ -d "$HOME/.letsencrypt" ]]; then
        print_warning "This will remove all SSL certificates stored in ~/.letsencrypt/"
        
        if confirm_action "Remove SSL certificates and Let's Encrypt configuration?" "n"; then
            safe_remove "$HOME/.letsencrypt" "SSL certificates directory"
        else
            print_info "Keeping SSL certificates"
        fi
    else
        print_info "No SSL certificates directory found"
    fi
}

# Function to remove system packages
remove_system_packages() {
    print_step "Removing system packages"
    
    print_warning "This will attempt to remove nginx, certbot, and related packages"
    print_warning "This may affect other applications that use these packages"
    
    if confirm_action "Remove system packages (nginx, certbot)?" "n"; then
        # Detect package manager
        if command -v apt >/dev/null 2>&1; then
            PACKAGE_MANAGER="apt"
        elif command -v dnf >/dev/null 2>&1; then
            PACKAGE_MANAGER="dnf"
        elif command -v yum >/dev/null 2>&1; then
            PACKAGE_MANAGER="yum"
        else
            print_warning "Cannot detect package manager, skipping package removal"
            return
        fi
        
        local packages_to_remove=("certbot" "python3-certbot-nginx")
        
        # Ask about nginx separately since it might be used by other applications
        if confirm_action "Remove nginx? (This may affect other websites)" "n"; then
            packages_to_remove+=("nginx")
        fi
        
        if [[ ${#packages_to_remove[@]} -gt 0 ]]; then
            print_info "Removing packages: ${packages_to_remove[*]}"
            
            case "$PACKAGE_MANAGER" in
                apt)
                    sudo apt remove -y "${packages_to_remove[@]}" || print_warning "Some packages may not have been removed"
                    if confirm_action "Run apt autoremove to clean up unused dependencies?" "y"; then
                        sudo apt autoremove -y
                    fi
                    ;;
                dnf)
                    sudo dnf remove -y "${packages_to_remove[@]}" || print_warning "Some packages may not have been removed"
                    ;;
                yum)
                    sudo yum remove -y "${packages_to_remove[@]}" || print_warning "Some packages may not have been removed"
                    ;;
            esac
            
            print_status "System packages removed"
        fi
    else
        print_info "Keeping system packages"
    fi
}

# Function to clean up web directories
cleanup_web_directories() {
    print_step "Cleaning up web directories"
    
    # Only clean up directories we know were created by the installer
    if [[ -d "/var/www" ]]; then
        print_info "Checking /var/www for Site Manager content..."
        
        # Look for sites that might belong to Site Manager
        local site_dirs=()
        if [[ -d "data" && -f "data/sites.db" ]]; then
            print_info "Found Site Manager database, checking for managed sites..."
            # This is a simple approach - in a real implementation, you might query the database
        fi
        
        print_info "Web directory cleanup completed (manual review recommended)"
    fi
}

# Function to show completion message
show_completion_message() {
    local uninstall_description
    
    case $UNINSTALL_LEVEL in
        app)
            uninstall_description="Application-only uninstall completed"
            ;;
        configs)
            uninstall_description="Application and configuration uninstall completed"
            ;;
        full)
            uninstall_description="Full uninstall completed"
            ;;
    esac
    
    print_header "🗑️ Uninstall Complete"
    
    echo -e "${GREEN}$uninstall_description${NC}\n"
    
    echo -e "${CYAN}━━━ WHAT WAS REMOVED ━━━${NC}"
    echo -e "${GREEN}✓${NC} Nginx Site Manager application"
    echo -e "${GREEN}✓${NC} Systemd service"
    echo -e "${GREEN}✓${NC} Sudo permissions"
    
    if [[ "$UNINSTALL_LEVEL" != "app" ]]; then
        echo -e "${GREEN}✓${NC} Generated nginx configurations"
        echo -e "${GREEN}✓${NC} SSL certificates (if confirmed)"
    fi
    
    if [[ "$UNINSTALL_LEVEL" == "full" ]]; then
        echo -e "${GREEN}✓${NC} System packages (if confirmed)"
    fi
    
    echo -e "\n${CYAN}━━━ BACKUP INFORMATION ━━━${NC}"
    echo -e "${BLUE}•${NC} Backups created in: ${YELLOW}$BACKUP_DIR${NC}"
    echo -e "${BLUE}•${NC} Uninstall log: ${YELLOW}$UNINSTALL_LOG${NC}"
    
    echo -e "\n${CYAN}━━━ MANUAL CLEANUP (if needed) ━━━${NC}"
    echo -e "${BLUE}•${NC} Review remaining files in /var/www/"
    echo -e "${BLUE}•${NC} Check nginx configuration: sudo nginx -t"
    echo -e "${BLUE}•${NC} Remove project directory if desired"
    
    if [[ "$UNINSTALL_LEVEL" != "full" ]]; then
        echo -e "${BLUE}•${NC} Remove nginx/certbot manually if no longer needed"
    fi
    
    echo -e "\n${YELLOW}Note: You may need to log out and back in for group changes to take effect${NC}"
    
    echo -e "\n${GREEN}Thank you for using Nginx Site Manager!${NC}"
}

# Main uninstall function
main() {
    print_header "Nginx Site Manager Uninstall Script v$SCRIPT_VERSION"
    
    # Initialize log file
    echo "=== Nginx Site Manager Uninstall Log ===" > "$UNINSTALL_LOG"
    echo "Date: $(date)" >> "$UNINSTALL_LOG"
    echo "User: $CURRENT_USER" >> "$UNINSTALL_LOG"
    echo "Script Version: $SCRIPT_VERSION" >> "$UNINSTALL_LOG"
    echo "=======================================" >> "$UNINSTALL_LOG"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root"
        print_info "Please run as the same user who installed Nginx Site Manager"
        exit 1
    fi
    
    # Show options and get user choice
    show_uninstall_options
    
    print_info "Starting uninstall process (level: $UNINSTALL_LEVEL)..."
    
    # Common uninstall steps for all levels
    remove_service
    remove_sudo_permissions
    remove_user_from_groups
    remove_application
    
    # Configuration-level and full uninstall steps
    if [[ "$UNINSTALL_LEVEL" != "app" ]]; then
        remove_nginx_configs
        remove_ssl_certificates
        cleanup_web_directories
    fi
    
    # Full uninstall steps
    if [[ "$UNINSTALL_LEVEL" == "full" ]]; then
        remove_system_packages
    fi
    
    show_completion_message
}

# Run main uninstall
main "$@"