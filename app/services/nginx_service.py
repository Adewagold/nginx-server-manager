"""
Nginx service operations for the Site Manager.
Handles nginx configuration generation, validation, and service management.
"""

import os
import subprocess
import shutil
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
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Deny access to hidden files
    location ~ /\. {
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
        template_vars = {
            "site_name": site_data["name"],
            "domain": site_data["domain"],
            "web_root": self.config.paths.web_root,
            **site_data.get("config", {})
        }
        
        return template.render(**template_vars)
    
    def validate_config(self, config_content: str, temp_file: Optional[str] = None) -> Tuple[bool, str]:
        """Validate nginx configuration."""
        if temp_file is None:
            temp_file = f"/tmp/nginx_test_{os.getpid()}.conf"
        
        try:
            # Write config to temporary file
            with open(temp_file, "w") as f:
                f.write(config_content)
            
            # Test configuration using configured command
            result = subprocess.run(
                self.config.nginx.test_command.split(),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return True, "Configuration is valid"
            else:
                return False, result.stderr
        
        except Exception as e:
            return False, f"Error validating configuration: {str(e)}"
        
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
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
            is_valid, message = self.test_nginx_config()
            if not is_valid:
                # Remove symlink if config test fails
                if os.path.exists(enabled_path):
                    os.unlink(enabled_path)
                return False, f"Nginx test failed: {message}"
            
            # Reload nginx
            reload_success, reload_message = self.reload_nginx()
            if not reload_success:
                # Remove symlink if reload fails
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
        try:
            result = subprocess.run(
                self.config.nginx.test_command.split(),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return True, "Nginx configuration test passed"
            else:
                return False, result.stderr
        
        except Exception as e:
            return False, f"Error testing nginx configuration: {str(e)}"
    
    def reload_nginx(self) -> Tuple[bool, str]:
        """Reload nginx service."""
        try:
            result = subprocess.run(
                self.config.nginx.reload_command.split(),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return True, "Nginx reloaded successfully"
            else:
                return False, result.stderr
        
        except Exception as e:
            return False, f"Error reloading nginx: {str(e)}"
    
    def get_nginx_status(self) -> Dict[str, Any]:
        """Get nginx service status."""
        try:
            result = subprocess.run(
                self.config.nginx.status_command.split(),
                capture_output=True,
                text=True
            )
            
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