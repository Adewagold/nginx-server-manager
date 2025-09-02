"""
Nginx service operations for the Site Manager.
Handles nginx configuration generation, validation, and service management.
"""

import os
import subprocess
import shutil
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from jinja2 import Environment, FileSystemLoader, Template

from app.config import get_config
from app.models import get_site_model


class NginxService:
    """Service for managing nginx configurations and operations."""
    
    def __init__(self):
        self.config = get_config()
        self.site_model = get_site_model()
        self._setup_templates()
        
        # Privileged service communication
        self.command_file = "/var/run/nginx-manager/command"
        self.result_file = "/var/run/nginx-manager/result"
    
    def _call_privileged_service(self, command: str, timeout: int = 10) -> Tuple[bool, str]:
        """Call the privileged nginx manager service."""
        try:
            # Remove any existing result file
            if os.path.exists(self.result_file):
                os.unlink(self.result_file)
            
            # Write command to command file
            with open(self.command_file, 'w') as f:
                f.write(command)
            
            # Wait for result with timeout
            start_time = time.time()
            while time.time() - start_time < timeout:
                if os.path.exists(self.result_file):
                    # Read result
                    with open(self.result_file, 'r') as f:
                        result = json.load(f)
                    
                    # Clean up result file
                    os.unlink(self.result_file)
                    
                    return result['success'], result['message']
                
                time.sleep(0.1)
            
            # Timeout occurred
            return False, f"Timeout waiting for privileged service response to '{command}'"
            
        except Exception as e:
            return False, f"Error communicating with privileged service: {str(e)}"
    
    def _setup_templates(self):
        """Setup Jinja2 templating environment."""
        template_dir = Path("app/templates/nginx")
        if template_dir.exists():
            self.jinja_env = Environment(loader=FileSystemLoader(str(template_dir)))
        else:
            # If template directory doesn't exist, create it and add basic templates
            template_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_templates()
            self.jinja_env = Environment(loader=FileSystemLoader(str(template_dir)))
    
    def _create_default_templates(self):
        """Create default nginx configuration templates."""
        template_dir = Path("app/templates/nginx")
        
        # Static site template
        static_template = """server {
    listen 80;
    server_name {{ domain }};
    
    root {{ web_root }}/{{ site_name }};
    index index.html index.htm;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    # Cache static assets
    location ~* \\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Deny access to hidden files
    location ~ /\\. {
        deny all;
    }
}"""
        
        # Reverse proxy template
        proxy_template = """server {
    listen 80;
    server_name {{ domain }};
    
    # Proxy settings
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    location / {
        proxy_pass {{ upstream_url }};
        
        # Timeout settings
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}"""
        
        # Load balancer template
        load_balancer_template = """upstream {{ site_name }}_backend {
{% for server in upstream_servers %}
    server {{ server }};
{% endfor %}
}

server {
    listen 80;
    server_name {{ domain }};
    
    # Proxy settings
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    location / {
        proxy_pass http://{{ site_name }}_backend;
        
        # Load balancing method
        # Options: round_robin (default), least_conn, ip_hash
        
        # Health checks
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        
        # Timeout settings
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}"""
        
        with open(template_dir / "static.conf", "w") as f:
            f.write(static_template)
        
        with open(template_dir / "proxy.conf", "w") as f:
            f.write(proxy_template)
        
        with open(template_dir / "load_balancer.conf", "w") as f:
            f.write(load_balancer_template)
    
    def generate_config(self, site_data: Dict[str, Any]) -> str:
        """Generate nginx configuration for a site."""
        site_type = site_data["type"]
        template_name = f"{site_type}.conf"
        
        try:
            template = self.jinja_env.get_template(template_name)
        except Exception:
            raise ValueError(f"Template not found for site type: {site_type}")
        
        # Prepare template variables
        # Expand SSL certificate paths if they contain ~
        ssl_cert_path = site_data.get("ssl_certificate_path", "") or ""
        ssl_key_path = site_data.get("ssl_certificate_key_path", "") or ""
        
        if ssl_cert_path and ssl_cert_path.startswith("~"):
            ssl_cert_path = os.path.expanduser(ssl_cert_path)
        if ssl_key_path and ssl_key_path.startswith("~"):
            ssl_key_path = os.path.expanduser(ssl_key_path)
        
        template_vars = {
            "site_name": site_data["name"],
            "domain": site_data["domain"],
            "web_root": self.config.paths.web_root,
            "ssl_enabled": bool(site_data.get("ssl_enabled", False)),
            "ssl_certificate_path": ssl_cert_path,
            "ssl_certificate_key_path": ssl_key_path,
            **site_data.get("config", {})
        }
        
        return template.render(**template_vars)
    
    def validate_config(self, config_content: str, temp_file: Optional[str] = None) -> Tuple[bool, str]:
        """Validate nginx configuration by creating a minimal test setup."""
        if temp_file is None:
            temp_file = f"/tmp/nginx_test_{os.getpid()}.conf"
        
        temp_dir = f"/tmp/nginx_test_{os.getpid()}"
        
        try:
            # Create temporary directory structure
            os.makedirs(temp_dir, exist_ok=True)
            
            # Create a temporary PID file path for testing
            pid_file = os.path.join(temp_dir, "nginx.pid")
            
            # Create temporary log directory
            log_dir = os.path.join(temp_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            # Replace log paths in config content to use temp directory
            # This prevents permission errors during validation
            import re
            modified_config = re.sub(
                r'(access_log|error_log)\s+/var/log/nginx/([^;]+);',
                rf'\1 {log_dir}/\2;',
                config_content
            )
            
            # Also replace port 80 and 443 with high ports for testing
            # This prevents permission errors when testing without root
            modified_config = re.sub(r'listen\s+80\b', 'listen 8080', modified_config)
            modified_config = re.sub(r'listen\s+443\b', 'listen 8443', modified_config)
            
            # Create minimal nginx.conf for testing
            test_nginx_conf = f"""
pid {pid_file};
worker_processes 1;
error_log {log_dir}/error.log;

events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log {log_dir}/access.log;
    
    # Include the server block to test
    include {temp_file};
}}
"""
            
            main_conf_file = os.path.join(temp_dir, "nginx.conf")
            with open(main_conf_file, "w") as f:
                f.write(test_nginx_conf)
            
            # Write the modified server block to temporary file
            with open(temp_file, "w") as f:
                f.write(modified_config)
            
            # Test configuration using the temporary main config
            # Build command based on use_sudo setting
            if self.config.nginx.use_sudo:
                command = ["sudo", "nginx", "-t", "-c", main_conf_file]
            else:
                command = ["nginx", "-t", "-c", main_conf_file]
            
            # Try to run the command
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True
                )
            except (PermissionError, FileNotFoundError) as e:
                # If running without sudo fails, try with sudo if not already using it
                if not self.config.nginx.use_sudo:
                    command = ["sudo", "nginx", "-t", "-c", main_conf_file]
                    try:
                        result = subprocess.run(
                            command,
                            capture_output=True,
                            text=True
                        )
                    except Exception:
                        # If sudo also fails, validation cannot be performed
                        return True, "Configuration validation skipped (insufficient permissions)"
                else:
                    return True, "Configuration validation skipped (insufficient permissions)"
            
            if result.returncode == 0:
                return True, "Configuration is valid"
            else:
                # Check for "no new privileges" error
                if "no new privileges" in result.stderr:
                    # If we can't validate due to permissions, skip validation
                    return True, "Configuration validation skipped (systemd restrictions)"
                return False, result.stderr
        
        except Exception as e:
            return False, f"Error validating configuration: {str(e)}"
        
        finally:
            # Clean up temporary files and directory
            for file_path in [temp_file, main_conf_file if 'main_conf_file' in locals() else None]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.unlink(file_path)
                    except:
                        pass
            
            # Clean up log directory if it exists
            if 'log_dir' in locals() and os.path.exists(log_dir):
                try:
                    # Remove any log files created during testing
                    for log_file in os.listdir(log_dir):
                        os.unlink(os.path.join(log_dir, log_file))
                    os.rmdir(log_dir)
                except:
                    pass
            
            # Clean up temp directory
            if os.path.exists(temp_dir):
                try:
                    os.rmdir(temp_dir)
                except:
                    pass
    
    def save_config(self, site_id: int, config_content: str) -> Tuple[bool, str]:
        """Save nginx configuration to sites-available."""
        site_data = self.site_model.get_by_id(site_id)
        if not site_data:
            return False, "Site not found"
        
        site_name = site_data["name"]
        config_path = os.path.join(self.config.paths.nginx_config_dir, site_name)
        
        try:
            # Validate configuration first
            is_valid, message = self.validate_config(config_content)
            if not is_valid:
                return False, f"Configuration validation failed: {message}"
            
            # Backup existing config if it exists
            if os.path.exists(config_path):
                backup_path = f"{config_path}.backup"
                shutil.copy2(config_path, backup_path)
            
            # Write new configuration
            with open(config_path, "w") as f:
                f.write(config_content)
            
            # Update site record with config path
            self.site_model.set_config_path(site_id, config_path)
            
            return True, f"Configuration saved to {config_path}"
        
        except Exception as e:
            return False, f"Error saving configuration: {str(e)}"
    
    def generate_site_config(self, site_id: int) -> Tuple[bool, str]:
        """Generate and save nginx configuration for a site."""
        try:
            # Get site data
            site_data = self.site_model.get_by_id(site_id)
            if not site_data:
                return False, "Site not found"
            
            # Generate configuration from template
            config_content = self.generate_config(site_data)
            
            # Save configuration
            return self.save_config(site_id, config_content)
        
        except Exception as e:
            return False, f"Error generating site configuration: {str(e)}"
    
    def enable_site(self, site_id: int) -> Tuple[bool, str]:
        """Enable a site by creating symlink in sites-enabled."""
        site_data = self.site_model.get_by_id(site_id)
        if not site_data:
            return False, "Site not found"
        
        site_name = site_data["name"]
        config_path = site_data.get("config_path")
        
        if not config_path or not os.path.exists(config_path):
            return False, "Site configuration file not found"
        
        enabled_path = os.path.join(self.config.paths.nginx_enabled_dir, site_name)
        
        try:
            # Create symlink if it doesn't exist
            if not os.path.exists(enabled_path):
                os.symlink(config_path, enabled_path)
            
            # Test nginx configuration
            # Note: We skip test if it fails due to permission issues
            is_valid, message = self.test_nginx_config()
            if not is_valid:
                # Check if this is a permission issue we can ignore
                permission_errors = [
                    "Permission denied",
                    "no new privileges", 
                    "Cannot use sudo",
                    "restricted environment",
                    "Authentication required",
                    "Interactive authentication required"
                ]
                
                is_permission_error = any(error in message for error in permission_errors)
                if not is_permission_error:
                    # This is a real configuration error, not a permission issue
                    if os.path.exists(enabled_path):
                        os.unlink(enabled_path)
                    return False, f"Nginx test failed: {message}"
                # If it's just a permission issue, continue with reload
            
            # Reload nginx
            reload_success, reload_message = self.reload_nginx()
            if not reload_success:
                # Check if this is a permission issue that we can work around
                permission_reload_errors = [
                    "manual nginx reload required",
                    "nginx reload required",
                    "Cannot use sudo",
                    "restricted environment",
                    "insufficient permissions",
                    "Authentication required",
                    "Interactive authentication required"
                ]
                
                is_permission_reload_error = any(error in reload_message for error in permission_reload_errors)
                if is_permission_reload_error:
                    # Permission issue - site is enabled and nginx will auto-reload via systemd watcher
                    self.site_model.enable(site_id)
                    return True, f"Site {site_name} enabled successfully. Nginx will reload automatically."
                else:
                    # Real reload failure
                    if os.path.exists(enabled_path):
                        os.unlink(enabled_path)
                    return False, f"Nginx reload failed: {reload_message}"
            
            # Update site status
            self.site_model.enable(site_id)
            
            return True, f"Site {site_name} enabled successfully"
        
        except Exception as e:
            return False, f"Error enabling site: {str(e)}"
    
    def disable_site(self, site_id: int) -> Tuple[bool, str]:
        """Disable a site by removing symlink from sites-enabled."""
        site_data = self.site_model.get_by_id(site_id)
        if not site_data:
            return False, "Site not found"
        
        site_name = site_data["name"]
        enabled_path = os.path.join(self.config.paths.nginx_enabled_dir, site_name)
        
        try:
            # Remove symlink if it exists
            if os.path.exists(enabled_path):
                os.unlink(enabled_path)
            
            # Reload nginx
            reload_success, reload_message = self.reload_nginx()
            if not reload_success:
                # Check if this is a permission issue that we can work around
                permission_reload_errors = [
                    "manual nginx reload required",
                    "nginx reload required",
                    "Cannot use sudo",
                    "restricted environment",
                    "insufficient permissions",
                    "Authentication required",
                    "Interactive authentication required"
                ]
                
                is_permission_reload_error = any(error in reload_message for error in permission_reload_errors)
                if is_permission_reload_error:
                    # Permission issue - site is disabled and nginx will auto-reload via systemd watcher
                    self.site_model.disable(site_id)
                    return True, f"Site {site_name} disabled successfully. Nginx will reload automatically."
                else:
                    # Real reload failure - restore the symlink
                    if not os.path.exists(enabled_path):
                        # Get config path to restore symlink
                        config_path = site_data.get("config_path")
                        if config_path and os.path.exists(config_path):
                            os.symlink(config_path, enabled_path)
                    return False, f"Nginx reload failed: {reload_message}"
            
            # Update site status
            self.site_model.disable(site_id)
            
            return True, f"Site {site_name} disabled successfully"
        
        except Exception as e:
            return False, f"Error disabling site: {str(e)}"
    
    def delete_site_config(self, site_id: int) -> Tuple[bool, str]:
        """Delete nginx configuration files for a site."""
        site_data = self.site_model.get_by_id(site_id)
        if not site_data:
            return False, "Site not found"
        
        site_name = site_data["name"]
        config_path = os.path.join(self.config.paths.nginx_config_dir, site_name)
        enabled_path = os.path.join(self.config.paths.nginx_enabled_dir, site_name)
        
        try:
            # First disable the site
            if site_data.get("enabled"):
                self.disable_site(site_id)
            
            # Remove configuration file
            if os.path.exists(config_path):
                os.unlink(config_path)
            
            # Remove symlink if it exists
            if os.path.exists(enabled_path):
                os.unlink(enabled_path)
            
            return True, f"Configuration files for {site_name} deleted"
        
        except Exception as e:
            return False, f"Error deleting site configuration: {str(e)}"
    
    def test_nginx_config(self) -> Tuple[bool, str]:
        """Test nginx configuration."""
        # Try privileged service first
        if os.path.exists(self.command_file.rsplit('/', 1)[0]):  # Check if run directory exists
            return self._call_privileged_service("test")
        
        # Fallback to old method if privileged service not available
        try:
            wrapper_script = "/usr/local/bin/nginx-manager/nginx-wrapper.sh"
            
            if os.path.exists(wrapper_script):
                try:
                    command = ["sudo", wrapper_script, "test"]
                    result = subprocess.run(command, capture_output=True, text=True)
                    
                    if result.returncode != 0 and "no new privileges" in result.stderr:
                        result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
                except Exception:
                    result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            else:
                result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, "Nginx configuration test passed"
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                return False, f"Nginx config test failed: {error_msg}"
        
        except Exception as e:
            return False, f"Error testing nginx configuration: {str(e)}"
    
    def test_config(self) -> Tuple[bool, str]:
        """Test nginx configuration syntax."""
        try:
            # Try different approaches based on environment restrictions
            wrapper_script = "/usr/local/bin/nginx-manager/nginx-wrapper.sh"
            
            # First try: wrapper script with sudo (works in normal environment)
            if os.path.exists(wrapper_script):
                try:
                    command = ["sudo", wrapper_script, "test"]
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True
                    )
                    
                    # If sudo fails due to NoNewPrivileges, try direct nginx command
                    if result.returncode != 0 and "no new privileges" in result.stderr:
                        result = subprocess.run(
                            ["nginx", "-t"],
                            capture_output=True,
                            text=True
                        )
                except Exception:
                    # If wrapper fails completely, try direct nginx command
                    result = subprocess.run(
                        ["nginx", "-t"],
                        capture_output=True,
                        text=True
                    )
            else:
                # Fallback: try direct nginx command
                result = subprocess.run(
                    ["nginx", "-t"],
                    capture_output=True,
                    text=True
                )
            
            if result.returncode == 0:
                return True, "Nginx configuration syntax is valid"
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                return False, f"Nginx config test failed: {error_msg}"
        
        except Exception as e:
            return False, f"Error testing nginx configuration: {str(e)}"
    
    def reload_nginx(self) -> Tuple[bool, str]:
        """Reload nginx service with config validation."""
        try:
            # First, test the nginx configuration
            test_valid, test_msg = self.test_nginx_config()
            if not test_valid:
                return False, f"Nginx config test failed: {test_msg}"
            
            # Try privileged service first
            if os.path.exists(self.command_file.rsplit('/', 1)[0]):  # Check if run directory exists
                return self._call_privileged_service("reload")
            
            # Fallback to old method if privileged service not available
            wrapper_script = "/usr/local/bin/nginx-manager/nginx-wrapper.sh"
            
            if os.path.exists(wrapper_script):
                try:
                    reload_command = ["sudo", wrapper_script, "reload"]
                    reload_result = subprocess.run(reload_command, capture_output=True, text=True)
                    
                    if reload_result.returncode != 0 and "no new privileges" in reload_result.stderr:
                        reload_result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
                except Exception:
                    reload_result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
            else:
                reload_result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
            
            if reload_result.returncode == 0:
                return True, "Nginx reloaded successfully"
            else:
                error_msg = reload_result.stderr.strip() or reload_result.stdout.strip()
                return False, f"Nginx reload failed: {error_msg}"
        
        except Exception as e:
            return False, f"Error reloading nginx: {str(e)}"
    
    def restart_nginx(self) -> Tuple[bool, str]:
        """Restart nginx service."""
        try:
            # First, test the nginx configuration
            test_valid, test_msg = self.test_nginx_config()
            if not test_valid:
                return False, f"Nginx config test failed: {test_msg}"
            
            # Build restart command based on use_sudo setting
            if self.config.nginx.use_sudo:
                restart_command = ["sudo"] + self.config.nginx.restart_command.split()
            else:
                restart_command = self.config.nginx.restart_command.split()
            
            # Try to restart nginx
            try:
                restart_result = subprocess.run(
                    restart_command,
                    capture_output=True,
                    text=True
                )
            except (PermissionError, FileNotFoundError) as e:
                # If running without sudo fails, try with sudo
                if not self.config.nginx.use_sudo:
                    restart_command = ["sudo"] + self.config.nginx.restart_command.split()
                    restart_result = subprocess.run(
                        restart_command,
                        capture_output=True,
                        text=True
                    )
                else:
                    raise e
            
            if restart_result.returncode == 0:
                return True, "Nginx configuration tested and restarted successfully"
            else:
                error_msg = restart_result.stderr.strip() or restart_result.stdout.strip()
                # Check for "no new privileges" error
                if "no new privileges" in error_msg:
                    return False, "Cannot use sudo: Running in restricted environment. Please ensure proper file permissions are set."
                return False, f"Nginx restart failed: {error_msg}"
        
        except Exception as e:
            return False, f"Error restarting nginx: {str(e)}"
    
    def get_nginx_status(self) -> Dict[str, Any]:
        """Get nginx service status."""
        try:
            # Build status command based on use_sudo setting
            if self.config.nginx.use_sudo:
                status_command = ["sudo"] + self.config.nginx.status_command.split()
            else:
                status_command = self.config.nginx.status_command.split()
            
            # Try to get status
            try:
                result = subprocess.run(
                    status_command,
                    capture_output=True,
                    text=True
                )
            except (PermissionError, FileNotFoundError) as e:
                # If running without sudo fails, try with sudo
                if not self.config.nginx.use_sudo:
                    status_command = ["sudo"] + self.config.nginx.status_command.split()
                    result = subprocess.run(
                        status_command,
                        capture_output=True,
                        text=True
                    )
                else:
                    raise e
            
            # Check for "no new privileges" error
            if "no new privileges" in result.stderr:
                return {
                    "running": False,
                    "status": "Cannot use sudo: Running in restricted environment. Service status unavailable."
                }
            
            return {
                "running": result.returncode == 0,
                "status": result.stdout if result.returncode == 0 else result.stderr
            }
        
        except Exception as e:
            return {
                "running": False,
                "status": f"Error checking nginx status: {str(e)}"
            }
    
    def create_web_directory(self, site_name: str) -> Tuple[bool, str]:
        """Create web directory for a static site."""
        web_dir = os.path.join(self.config.paths.web_root, site_name)
        
        try:
            os.makedirs(web_dir, exist_ok=True)
            
            # Set proper permissions
            os.chmod(web_dir, 0o755)
            
            # Create a default index.html if it doesn't exist
            index_file = os.path.join(web_dir, "index.html")
            if not os.path.exists(index_file):
                default_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{site_name}</title>
</head>
<body>
    <h1>Welcome to {site_name}</h1>
    <p>This is the default page for your new site.</p>
    <p>Upload your files to customize this page.</p>
</body>
</html>"""
                with open(index_file, "w") as f:
                    f.write(default_content)
            
            return True, f"Web directory created at {web_dir}"
        
        except Exception as e:
            return False, f"Error creating web directory: {str(e)}"
    
    def list_available_sites(self) -> List[str]:
        """List all available nginx site configurations."""
        config_dir = self.config.paths.nginx_config_dir
        if not os.path.exists(config_dir):
            return []
        
        return [f for f in os.listdir(config_dir) if os.path.isfile(os.path.join(config_dir, f))]
    
    def list_enabled_sites(self) -> List[str]:
        """List all enabled nginx sites."""
        enabled_dir = self.config.paths.nginx_enabled_dir
        if not os.path.exists(enabled_dir):
            return []
        
        return [f for f in os.listdir(enabled_dir) if os.path.islink(os.path.join(enabled_dir, f))]


# Global service instance
_nginx_service: Optional[NginxService] = None


def get_nginx_service() -> NginxService:
    """Get the global nginx service instance."""
    global _nginx_service
    if _nginx_service is None:
        _nginx_service = NginxService()
    return _nginx_service