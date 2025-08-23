"""
Enhanced security module for Nginx Site Manager.
Provides comprehensive security controls, input validation, and threat detection.
"""

import re
import os
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from ipaddress import ip_address, ip_network

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field, validator
import bcrypt

from app.config import get_config

# Configure logging
logger = logging.getLogger(__name__)


class SecurityConfig(BaseModel):
    """Enhanced security configuration."""
    
    # Authentication settings
    min_password_length: int = 12
    max_login_attempts: int = 10
    lockout_duration_minutes: int = 15
    password_hash_rounds: int = 12
    
    # Session management
    session_timeout_minutes: int = 30
    max_concurrent_sessions: int = 3
    
    # Rate limiting
    rate_limit_per_minute: int = 30
    burst_limit: int = 10
    
    # File upload security
    max_file_size_mb: int = 50
    max_files_per_upload: int = 10
    allowed_mime_types: List[str] = [
        'text/html', 'text/css', 'text/javascript', 'application/javascript',
        'image/png', 'image/jpeg', 'image/gif', 'image/svg+xml', 'image/x-icon',
        'application/pdf', 'text/plain', 'application/json', 'application/xml'
    ]
    
    # Path validation
    max_path_length: int = 255
    forbidden_path_patterns: List[str] = [
        r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
        r'/etc/', r'/proc/', r'/sys/', r'/dev/', r'/var/log/'
    ]
    
    # IP whitelisting
    ip_whitelist_enabled: bool = False
    allowed_ip_ranges: List[str] = ["127.0.0.1/32", "192.168.0.0/16", "10.0.0.0/8"]
    
    # Content scanning
    enable_content_scanning: bool = True
    dangerous_patterns: List[str] = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'eval\s*\(',
        r'Function\s*\(',
        r'setTimeout\s*\(',
        r'setInterval\s*\(',
        r'document\.write',
        r'document\.cookie',
        r'window\.location',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
    ]
    
    # HTTP security headers
    security_headers: Dict[str, str] = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
    }


class SecurityEvent(BaseModel):
    """Security event for logging and monitoring."""
    
    event_type: str
    severity: str  # low, medium, high, critical
    source_ip: str
    user_agent: Optional[str] = None
    username: Optional[str] = None
    description: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    additional_data: Dict[str, Any] = {}


class ThreatDetector:
    """Detects and responds to security threats."""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.blocked_ips: Dict[str, datetime] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.suspicious_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for threat detection."""
        return [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                for pattern in self.config.dangerous_patterns]
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP address is blocked."""
        if ip in self.blocked_ips:
            block_time = self.blocked_ips[ip]
            if datetime.utcnow() - block_time < timedelta(minutes=self.config.lockout_duration_minutes):
                return True
            else:
                # Remove expired blocks
                del self.blocked_ips[ip]
        return False
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist."""
        if not self.config.ip_whitelist_enabled:
            return True
        
        try:
            client_ip = ip_address(ip)
            for allowed_range in self.config.allowed_ip_ranges:
                if client_ip in ip_network(allowed_range):
                    return True
            return False
        except ValueError:
            return False
    
    def record_failed_attempt(self, ip: str) -> bool:
        """Record failed login attempt and check if IP should be blocked."""
        current_time = datetime.utcnow()
        
        # Initialize if not exists
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        
        # Remove old attempts (older than 1 hour)
        self.failed_attempts[ip] = [
            attempt for attempt in self.failed_attempts[ip]
            if current_time - attempt < timedelta(hours=1)
        ]
        
        # Add current attempt
        self.failed_attempts[ip].append(current_time)
        
        # Check if should be blocked
        if len(self.failed_attempts[ip]) >= self.config.max_login_attempts:
            self.blocked_ips[ip] = current_time
            self.log_security_event(SecurityEvent(
                event_type="ip_blocked",
                severity="high",
                source_ip=ip,
                description=f"IP blocked after {len(self.failed_attempts[ip])} failed attempts"
            ))
            return True
        
        return False
    
    def scan_content(self, content: str, content_type: str = "text") -> List[str]:
        """Scan content for dangerous patterns."""
        if not self.config.enable_content_scanning:
            return []
        
        threats_found = []
        
        for pattern in self.suspicious_patterns:
            if pattern.search(content):
                threats_found.append(pattern.pattern)
        
        # Additional checks for specific content types
        if content_type in ["html", "htm"]:
            # Check for dangerous HTML attributes
            dangerous_attrs = ['onload', 'onerror', 'onclick', 'onmouseover']
            for attr in dangerous_attrs:
                if re.search(rf'{attr}\s*=', content, re.IGNORECASE):
                    threats_found.append(f"Dangerous HTML attribute: {attr}")
        
        elif content_type in ["js", "javascript"]:
            # Check for dangerous JavaScript functions
            dangerous_js = ['eval(', 'Function(', 'setTimeout(', 'setInterval(']
            for func in dangerous_js:
                if func in content:
                    threats_found.append(f"Dangerous JavaScript function: {func}")
        
        return threats_found
    
    def validate_file_upload(self, filename: str, content: bytes, mime_type: str) -> List[str]:
        """Validate uploaded file for security threats."""
        issues = []
        
        # Check file size
        if len(content) > self.config.max_file_size_mb * 1024 * 1024:
            issues.append(f"File too large: {len(content)} bytes")
        
        # Check MIME type
        if mime_type not in self.config.allowed_mime_types:
            issues.append(f"Disallowed MIME type: {mime_type}")
        
        # Check filename for dangerous patterns
        if re.search(r'[<>:"|?*\\]', filename):
            issues.append("Filename contains dangerous characters")
        
        # Check for null bytes
        if b'\x00' in content:
            issues.append("File contains null bytes")
        
        # Scan text content for threats
        if mime_type.startswith('text/'):
            try:
                text_content = content.decode('utf-8', errors='ignore')
                threats = self.scan_content(text_content, mime_type.split('/')[1])
                issues.extend([f"Dangerous content: {threat}" for threat in threats])
            except Exception as e:
                logger.warning(f"Failed to scan content: {e}")
        
        return issues
    
    def log_security_event(self, event: SecurityEvent):
        """Log security event."""
        logger.warning(f"SECURITY EVENT: {event.event_type} - {event.description} - IP: {event.source_ip}")
        
        # In production, you might want to send this to a SIEM system
        # or store in a dedicated security events database


class InputValidator:
    """Validates and sanitizes user input."""
    
    def __init__(self):
        self.config = SecurityConfig()
    
    def validate_filename(self, filename: str) -> str:
        """Validate and sanitize filename."""
        if not filename:
            raise HTTPException(400, "Filename cannot be empty")
        
        # Remove path separators and dangerous characters
        filename = os.path.basename(filename)
        filename = re.sub(r'[<>:"|?*\\]', '', filename)
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        
        # Ensure filename is not empty after sanitization
        if not filename:
            raise HTTPException(400, "Invalid filename")
        
        return filename
    
    def validate_path(self, path: str, base_path: str) -> str:
        """Validate and normalize file path to prevent directory traversal."""
        if not path:
            raise HTTPException(400, "Path cannot be empty")
        
        # Check length
        if len(path) > self.config.max_path_length:
            raise HTTPException(400, f"Path too long (max {self.config.max_path_length} chars)")
        
        # Check for dangerous patterns
        for pattern in self.config.forbidden_path_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                raise HTTPException(400, f"Forbidden path pattern detected: {pattern}")
        
        # Normalize and resolve path
        try:
            # Remove null bytes
            path = path.replace('\x00', '')
            
            # Normalize path separators
            path = path.replace('\\', '/')
            
            # Join with base path and resolve
            full_path = os.path.join(base_path, path)
            resolved_path = os.path.abspath(full_path)
            base_abs = os.path.abspath(base_path)
            
            # Ensure resolved path is within base directory
            if not resolved_path.startswith(base_abs + os.sep) and resolved_path != base_abs:
                raise HTTPException(400, "Path traversal attempt detected")
            
            return resolved_path
            
        except Exception as e:
            logger.warning(f"Path validation error: {e}")
            raise HTTPException(400, "Invalid path")
    
    def validate_domain(self, domain: str) -> str:
        """Validate domain name."""
        if not domain:
            raise HTTPException(400, "Domain cannot be empty")
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, domain):
            raise HTTPException(400, "Invalid domain format")
        
        # Check length
        if len(domain) > 253:
            raise HTTPException(400, "Domain name too long")
        
        # Convert to lowercase
        return domain.lower()
    
    def validate_site_name(self, name: str) -> str:
        """Validate site name."""
        if not name:
            raise HTTPException(400, "Site name cannot be empty")
        
        # Allow only alphanumeric, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            raise HTTPException(400, "Site name can only contain letters, numbers, hyphens, and underscores")
        
        # Check length
        if len(name) > 50:
            raise HTTPException(400, "Site name too long (max 50 characters)")
        
        # Check for reserved names
        reserved_names = ['admin', 'api', 'www', 'mail', 'ftp', 'ssh', 'root', 'test', 'staging']
        if name.lower() in reserved_names:
            raise HTTPException(400, f"'{name}' is a reserved name")
        
        return name.lower()
    
    def sanitize_html(self, content: str) -> str:
        """Sanitize HTML content."""
        # Remove dangerous script tags
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove dangerous event attributes
        content = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)
        
        # Remove javascript: URLs
        content = re.sub(r'javascript:[^"\'>\s]*', '', content, flags=re.IGNORECASE)
        
        return content


class PasswordValidator:
    """Validates password strength and manages password policies."""
    
    def __init__(self):
        self.config = SecurityConfig()
    
    def validate_password(self, password: str) -> List[str]:
        """Validate password strength and return list of issues."""
        issues = []
        
        # Check minimum length
        if len(password) < self.config.min_password_length:
            issues.append(f"Password must be at least {self.config.min_password_length} characters long")
        
        # Check for uppercase letters
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letters
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        # Check for digits
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one number")
        
        # Check for special characters
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Check for common passwords
        common_passwords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ]
        if password.lower() in common_passwords:
            issues.append("Password is too common")
        
        return issues
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt(rounds=self.config.password_hash_rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False


class SecurityMiddleware:
    """Security middleware for FastAPI requests."""
    
    def __init__(self):
        self.threat_detector = ThreatDetector()
        self.input_validator = InputValidator()
        
    async def __call__(self, request: Request, call_next):
        """Process request through security checks."""
        client_ip = request.client.host
        
        # Check IP whitelist
        if not self.threat_detector.is_ip_whitelisted(client_ip):
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="ip_not_whitelisted",
                severity="high",
                source_ip=client_ip,
                description="Request from non-whitelisted IP"
            ))
            raise HTTPException(403, "Access denied")
        
        # Check if IP is blocked
        if self.threat_detector.is_ip_blocked(client_ip):
            raise HTTPException(429, "IP address is temporarily blocked")
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        security_config = SecurityConfig()
        for header, value in security_config.security_headers.items():
            response.headers[header] = value
        
        # Remove server information
        response.headers.pop("server", None)
        
        return response


# Global instances
_threat_detector: Optional[ThreatDetector] = None
_input_validator: Optional[InputValidator] = None
_password_validator: Optional[PasswordValidator] = None


def get_threat_detector() -> ThreatDetector:
    """Get global threat detector instance."""
    global _threat_detector
    if _threat_detector is None:
        _threat_detector = ThreatDetector()
    return _threat_detector


def get_input_validator() -> InputValidator:
    """Get global input validator instance."""
    global _input_validator
    if _input_validator is None:
        _input_validator = InputValidator()
    return _input_validator


def get_password_validator() -> PasswordValidator:
    """Get global password validator instance."""
    global _password_validator
    if _password_validator is None:
        _password_validator = PasswordValidator()
    return _password_validator


# Security utility functions
def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def generate_csrf_token() -> str:
    """Generate CSRF token."""
    return secrets.token_hex(32)


def hash_file(file_path: str) -> str:
    """Calculate SHA-256 hash of file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def is_safe_redirect_url(url: str, allowed_hosts: List[str]) -> bool:
    """Check if redirect URL is safe (prevents open redirect attacks)."""
    if not url:
        return False
    
    # Only allow relative URLs or URLs from allowed hosts
    if url.startswith('/'):
        return True
    
    for host in allowed_hosts:
        if url.startswith(f'http://{host}') or url.startswith(f'https://{host}'):
            return True
    
    return False