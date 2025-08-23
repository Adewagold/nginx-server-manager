"""
Configuration management for the Nginx Site Manager.
Loads settings from config.yaml and provides typed configuration objects.
"""

import os
import yaml
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings
from pathlib import Path


class AppConfig(BaseSettings):
    """Application server configuration."""
    host: str = "127.0.0.1"
    port: int = 8080
    debug: bool = False
    secret_key: str = Field(..., min_length=32)
    access_token_expire_minutes: int = 1440  # 24 hours


class AdminConfig(BaseSettings):
    """Administrator credentials configuration."""
    username: str = "admin"
    password: str = Field(..., min_length=6)


class PathsConfig(BaseSettings):
    """System paths configuration."""
    nginx_config_dir: str = "/etc/nginx/sites-available"
    nginx_enabled_dir: str = "/etc/nginx/sites-enabled"
    web_root: str = "/var/www"
    ssl_cert_dir: str = "/etc/letsencrypt/live"
    data_dir: str = "./data"
    log_dir: str = "/var/log/nginx"


class NginxConfig(BaseSettings):
    """Nginx service commands configuration."""
    test_command: str = "sudo nginx -t"
    reload_command: str = "sudo systemctl reload nginx"
    restart_command: str = "sudo systemctl restart nginx"
    status_command: str = "sudo systemctl status nginx"


class UploadConfig(BaseSettings):
    """File upload configuration."""
    max_file_size: int = 104857600  # 100MB
    allowed_extensions: List[str] = [
        ".html", ".htm", ".css", ".js",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".pdf", ".txt", ".xml", ".json"
    ]


class SSLConfig(BaseSettings):
    """SSL/TLS configuration."""
    email: str = "admin@yourdomain.com"
    staging: bool = False
    auto_renew: bool = True


class SecurityConfig(BaseSettings):
    """Enhanced security settings configuration."""
    # Authentication settings
    min_password_length: int = 12
    max_login_attempts: int = 3
    lockout_duration_minutes: int = 15
    password_hash_rounds: int = 12
    
    # Session management
    session_timeout: int = 30  # Reduced from 60 for better security
    max_concurrent_sessions: int = 3
    
    # Rate limiting
    rate_limit: int = 30  # Requests per minute (reduced)
    burst_limit: int = 10
    
    # CORS settings
    cors_origins: List[str] = ["http://localhost:8080", "http://127.0.0.1:8080"]
    cors_methods: List[str] = ["GET", "POST", "PUT", "DELETE"]
    cors_headers: List[str] = ["Content-Type", "Authorization"]
    
    # File upload security
    max_file_size_mb: int = 50
    max_files_per_upload: int = 10
    allowed_file_extensions: List[str] = [
        ".html", ".htm", ".css", ".js", ".json", ".xml",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".pdf", ".txt", ".md", ".zip"
    ]
    blocked_file_extensions: List[str] = [
        ".php", ".asp", ".jsp", ".exe", ".bat", ".sh",
        ".py", ".rb", ".pl", ".cgi", ".scr", ".vbs"
    ]
    
    # IP security
    ip_whitelist_enabled: bool = False
    allowed_ip_ranges: List[str] = ["127.0.0.1/32", "192.168.0.0/16", "10.0.0.0/8"]
    
    # Content security
    enable_content_scanning: bool = True
    
    # Security headers
    enable_hsts: bool = True
    hsts_max_age: int = 31536000  # 1 year
    enable_csrf_protection: bool = True


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str = "/var/log/nginx-manager/app.log"


class DatabaseConfig(BaseSettings):
    """Database configuration."""
    url: str = "sqlite:///./data/sites.db"
    pool_size: int = 10
    max_overflow: int = 20


class Config:
    """Main configuration class that loads and validates all settings."""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self._load_config()
    
    def _load_config(self):
        """Load configuration from YAML file."""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(
                f"Configuration file {self.config_file} not found. "
                "Please copy config.yaml.example to config.yaml and customize it."
            )
        
        with open(self.config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Initialize configuration sections
        self.app = AppConfig(**config_data.get('app', {}))
        self.admin = AdminConfig(**config_data.get('admin', {}))
        self.paths = PathsConfig(**config_data.get('paths', {}))
        self.nginx = NginxConfig(**config_data.get('nginx', {}))
        self.upload = UploadConfig(**config_data.get('upload', {}))
        self.ssl = SSLConfig(**config_data.get('ssl', {}))
        self.security = SecurityConfig(**config_data.get('security', {}))
        self.logging = LoggingConfig(**config_data.get('logging', {}))
        self.database = DatabaseConfig(**config_data.get('database', {}))
        
        # Create data directory if it doesn't exist
        Path(self.paths.data_dir).mkdir(parents=True, exist_ok=True)
    
    def validate(self) -> List[str]:
        """Validate configuration and return any errors."""
        errors = []
        warnings = []
        
        # Check if required directories exist
        required_dirs = [
            self.paths.nginx_config_dir,
            self.paths.nginx_enabled_dir,
            self.paths.web_root
        ]
        
        for dir_path in required_dirs:
            if not os.path.exists(dir_path):
                errors.append(f"Required directory does not exist: {dir_path}")
        
        # Check if nginx is installed
        if os.system("which nginx > /dev/null 2>&1") != 0:
            errors.append("nginx is not installed or not in PATH")
        
        # Validate secret key strength
        if len(self.app.secret_key) < 32:
            errors.append("secret_key must be at least 32 characters long")
        
        # Check secret key complexity
        if self.app.secret_key.isalnum():
            warnings.append("secret_key should contain special characters for better security")
        
        # Check if default credentials are still being used
        if self.admin.username == "admin" and self.admin.password in ["admin123", "admin", "password"]:
            errors.append("Default/weak admin credentials detected. Please use strong credentials.")
        
        # Validate admin password strength if not hashed
        if not self.admin.password.startswith('$2b$'):
            if len(self.admin.password) < self.security.min_password_length:
                errors.append(f"Admin password must be at least {self.security.min_password_length} characters long")
            
            # Check password complexity
            import re
            if not re.search(r'[A-Z]', self.admin.password):
                warnings.append("Admin password should contain uppercase letters")
            if not re.search(r'[a-z]', self.admin.password):
                warnings.append("Admin password should contain lowercase letters")
            if not re.search(r'\d', self.admin.password):
                warnings.append("Admin password should contain numbers")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', self.admin.password):
                warnings.append("Admin password should contain special characters")
        
        # Security configuration validation
        if self.security.session_timeout > 120:
            warnings.append("Session timeout is very long, consider reducing for better security")
        
        if self.security.max_login_attempts > 5:
            warnings.append("Max login attempts is high, consider reducing to prevent brute force")
        
        if self.security.rate_limit > 100:
            warnings.append("Rate limit is very high, consider reducing to prevent abuse")
        
        # File upload security validation
        dangerous_extensions = ['.php', '.asp', '.jsp', '.exe', '.bat', '.sh', '.py']
        allowed_dangerous = [ext for ext in self.upload.allowed_extensions if ext in dangerous_extensions]
        if allowed_dangerous:
            errors.append(f"Dangerous file extensions allowed: {', '.join(allowed_dangerous)}")
        
        # Check file size limits
        if self.upload.max_file_size > 1073741824:  # 1GB
            warnings.append("Maximum file size is very large, consider reducing")
        
        # SSL configuration validation
        if self.ssl.staging and os.getenv('PRODUCTION') == 'true':
            warnings.append("SSL staging mode enabled in production environment")
        
        # Debug mode check
        if self.app.debug and os.getenv('PRODUCTION') == 'true':
            errors.append("Debug mode should not be enabled in production")
        
        # CORS configuration check
        if '*' in self.security.cors_origins:
            warnings.append("CORS allows all origins (*), consider restricting for security")
        
        # Log warnings
        if warnings:
            import logging
            logger = logging.getLogger(__name__)
            for warning in warnings:
                logger.warning(f"Configuration warning: {warning}")
        
        return errors
    
    def get_database_url(self) -> str:
        """Get the complete database URL with absolute path."""
        if self.database.url.startswith("sqlite:///"):
            # Convert relative path to absolute
            db_path = self.database.url[10:]  # Remove "sqlite:///"
            if not os.path.isabs(db_path):
                db_path = os.path.join(self.paths.data_dir, os.path.basename(db_path))
            return f"sqlite:///{db_path}"
        return self.database.url


# Global configuration instance
config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global config
    if config is None:
        config = Config()
    return config


def reload_config():
    """Reload the configuration from file."""
    global config
    config = Config()


def init_config(config_file: str = "config.yaml"):
    """Initialize configuration with a specific file."""
    global config
    config = Config(config_file)