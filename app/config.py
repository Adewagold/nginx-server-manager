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
    """Security settings configuration."""
    rate_limit: int = 60
    cors_origins: List[str] = ["http://localhost:8080", "http://127.0.0.1:8080"]
    session_timeout: int = 60


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
        
        # Check if default credentials are still being used
        if self.admin.username == "admin" and self.admin.password == "admin123":
            errors.append("Default admin credentials detected. Please change them for security.")
        
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