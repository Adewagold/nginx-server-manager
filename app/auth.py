"""
JWT Authentication system for the Nginx Site Manager.
Handles user authentication, token generation, and security middleware with enhanced security features.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set
import secrets
import logging
import hashlib

from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt

from app.config import get_config
from app.security import (
    get_threat_detector, get_password_validator, SecurityEvent,
    generate_secure_token
)

# Configure logging
logger = logging.getLogger(__name__)

# Password hashing context with enhanced security
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Increased rounds for better security
)

# HTTP Bearer token scheme
security = HTTPBearer()


class AuthManager:
    """Manages authentication operations with enhanced security."""
    
    def __init__(self):
        self.config = get_config()
        self.threat_detector = get_threat_detector()
        self.password_validator = get_password_validator()
        
        # Initialize admin password hash if using plain text
        self._ensure_password_hashed()
    
    def _ensure_password_hashed(self):
        """Ensure admin password is properly hashed."""
        admin_config = self.config.admin
        
        # Check if password is already hashed (bcrypt hashes start with $2b$)
        if not admin_config.password.startswith('$2b$'):
            logger.warning("Admin password is not hashed, upgrading security...")
            
            # Validate password strength before hashing
            issues = self.password_validator.validate_password(admin_config.password)
            if issues:
                logger.error(f"Admin password does not meet security requirements: {', '.join(issues)}")
                raise ValueError(f"Admin password security issues: {', '.join(issues)}")
            
            # Hash the password
            hashed = self.password_validator.hash_password(admin_config.password)
            
            # Update config (note: this would require config file update in production)
            admin_config.password = hashed
            logger.info("Admin password has been hashed for security")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against its hash with enhanced security."""
        if not plain_password or not hashed_password:
            return False
        
        # Use enhanced password validator
        return self.password_validator.verify_password(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash with security validation."""
        # Validate password strength first
        issues = self.password_validator.validate_password(password)
        if issues:
            raise ValueError(f"Password security issues: {', '.join(issues)}")
        
        return self.password_validator.hash_password(password)
    
    def authenticate_user(self, username: str, password: str, client_ip: str = "unknown") -> Optional[Dict[str, Any]]:
        """Authenticate user credentials with enhanced security checks."""
        # Check if IP is blocked
        if self.threat_detector.is_ip_blocked(client_ip):
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="blocked_ip_login_attempt",
                severity="high",
                source_ip=client_ip,
                username=username,
                description="Login attempt from blocked IP"
            ))
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "IP temporarily blocked")
        
        # Log login attempt
        self.threat_detector.log_security_event(SecurityEvent(
            event_type="login_attempt",
            severity="low",
            source_ip=client_ip,
            username=username,
            description="User login attempt"
        ))
        
        # Validate input
        if not username or not password:
            self._handle_failed_login(username, client_ip, "Empty credentials")
            return None
        
        # Basic input sanitization
        username = username.strip()[:100]  # Limit length
        
        # Admin user authentication
        admin_config = self.config.admin
        
        if username != admin_config.username:
            self._handle_failed_login(username, client_ip, "Invalid username")
            return None
        
        # Verify password (now supports both hashed and plain text for transition)
        password_valid = False
        if admin_config.password.startswith('$2b$'):
            # Hashed password
            password_valid = self.verify_password(password, admin_config.password)
        else:
            # Plain text password (legacy support)
            password_valid = (password == admin_config.password)
            if password_valid:
                logger.warning("Using plain text password comparison - please hash your password")
        
        if password_valid:
            # Successful login
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="login_success",
                severity="low",
                source_ip=client_ip,
                username=username,
                description="Successful login"
            ))
            
            return {
                "username": username,
                "role": "admin",
                "permissions": ["read", "write", "admin"],
                "login_time": datetime.utcnow().isoformat(),
                "client_ip": client_ip
            }
        else:
            self._handle_failed_login(username, client_ip, "Invalid password")
            return None
    
    def _handle_failed_login(self, username: str, client_ip: str, reason: str):
        """Handle failed login attempt with security logging and blocking."""
        self.threat_detector.log_security_event(SecurityEvent(
            event_type="login_failure",
            severity="medium",
            source_ip=client_ip,
            username=username,
            description=f"Failed login: {reason}"
        ))
        
        # Check if IP should be blocked
        if self.threat_detector.record_failed_attempt(client_ip):
            logger.warning(f"IP {client_ip} blocked due to multiple failed login attempts")
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token with enhanced security."""
        to_encode = data.copy()
        current_time = datetime.utcnow()
        
        if expires_delta:
            expire = current_time + expires_delta
        else:
            expire = current_time + timedelta(
                minutes=self.config.app.access_token_expire_minutes
            )
        
        # Add security claims
        jti = generate_secure_token()  # Unique token ID for revocation
        to_encode.update({
            "exp": expire,
            "iat": current_time,
            "nbf": current_time,  # Not before time
            "jti": jti,  # JWT ID for token tracking
            "aud": "nginx-manager",  # Audience
            "iss": "nginx-manager-auth"  # Issuer
        })
        
        # Add fingerprint for additional security
        if "client_ip" in data:
            to_encode["fingerprint"] = hashlib.sha256(
                f"{data['client_ip']}{jti}".encode()
            ).hexdigest()[:16]
        
        try:
            encoded_jwt = jwt.encode(
                to_encode, 
                self.config.app.secret_key, 
                algorithm="HS256"
            )
            
            # Log token creation
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="token_created",
                severity="low",
                source_ip=data.get("client_ip", "unknown"),
                username=data.get("username", "unknown"),
                description=f"Access token created with JTI: {jti}",
                additional_data={"jti": jti, "expires": expire.isoformat()}
            ))
            
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Failed to create JWT token: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Token creation failed")
    
    def verify_token(self, token: str, client_ip: str = "unknown") -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token with enhanced security checks."""
        if not token:
            return None
        
        try:
            # Decode and verify token
            payload = jwt.decode(
                token, 
                self.config.app.secret_key, 
                algorithms=["HS256"],
                audience="nginx-manager",
                issuer="nginx-manager-auth"
            )
            
            username: str = payload.get("username")
            jti: str = payload.get("jti")
            
            if not username or not jti:
                self.threat_detector.log_security_event(SecurityEvent(
                    event_type="invalid_token",
                    severity="medium",
                    source_ip=client_ip,
                    description="Token missing required claims"
                ))
                return None
            
            # Verify token fingerprint if available
            if "fingerprint" in payload and client_ip != "unknown":
                expected_fingerprint = hashlib.sha256(
                    f"{client_ip}{jti}".encode()
                ).hexdigest()[:16]
                
                if payload["fingerprint"] != expected_fingerprint:
                    self.threat_detector.log_security_event(SecurityEvent(
                        event_type="token_fingerprint_mismatch",
                        severity="high",
                        source_ip=client_ip,
                        username=username,
                        description="Token fingerprint mismatch - possible token theft"
                    ))
                    return None
            
            # Check if token is expired (additional check)
            exp = payload.get("exp")
            if exp and datetime.utcnow() > datetime.fromtimestamp(exp):
                self.threat_detector.log_security_event(SecurityEvent(
                    event_type="expired_token_used",
                    severity="low",
                    source_ip=client_ip,
                    username=username,
                    description="Attempt to use expired token"
                ))
                return None
            
            # Check not before time
            nbf = payload.get("nbf")
            if nbf and datetime.utcnow() < datetime.fromtimestamp(nbf):
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="expired_token",
                severity="low",
                source_ip=client_ip,
                description="Expired token used"
            ))
            return None
        except jwt.InvalidAudienceError:
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="invalid_token_audience",
                severity="medium",
                source_ip=client_ip,
                description="Token with invalid audience"
            ))
            return None
        except jwt.InvalidIssuerError:
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="invalid_token_issuer",
                severity="medium",
                source_ip=client_ip,
                description="Token with invalid issuer"
            ))
            return None
        except JWTError as e:
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="jwt_error",
                severity="medium",
                source_ip=client_ip,
                description=f"JWT verification error: {str(e)}"
            ))
            return None
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security), 
                         request: Request = None) -> Dict[str, Any]:
        """Get current authenticated user from JWT token with enhanced security."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        client_ip = "unknown"
        if request:
            client_ip = request.client.host
        
        try:
            payload = self.verify_token(credentials.credentials, client_ip)
            if payload is None:
                raise credentials_exception
            
            username: str = payload.get("username")
            if username is None:
                raise credentials_exception
            
            # Additional security checks
            if self.threat_detector.is_ip_blocked(client_ip):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="IP address is temporarily blocked"
                )
            
            return payload
                
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Authentication error: {e}")
            raise credentials_exception
    
    def require_permission(self, required_permission: str):
        """Decorator to require specific permission."""
        def permission_checker(current_user: Dict[str, Any] = Depends(self.get_current_user)):
            permissions = current_user.get("permissions", [])
            if required_permission not in permissions and "admin" not in permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            return current_user
        return permission_checker


class SessionManager:
    """Enhanced session manager with security features."""
    
    def __init__(self):
        self.config = get_config()
        self.threat_detector = get_threat_detector()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.revoked_tokens: Set[str] = set()
        self.user_sessions: Dict[str, List[str]] = {}  # username -> list of session_ids
        
        # Start background cleanup task
        self._last_cleanup = datetime.utcnow()
    
    def create_session(self, username: str, token: str, client_ip: str = "unknown", 
                      user_agent: str = None) -> str:
        """Create a new user session with security tracking."""
        session_id = generate_secure_token(32)
        current_time = datetime.utcnow()
        
        # Enforce maximum concurrent sessions per user
        if username in self.user_sessions:
            if len(self.user_sessions[username]) >= 3:  # Max 3 concurrent sessions
                # Remove oldest session
                oldest_session = self.user_sessions[username].pop(0)
                self.destroy_session(oldest_session)
        
        session_data = {
            "username": username,
            "token": token,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "created_at": current_time,
            "last_activity": current_time,
            "request_count": 0,
            "fingerprint": hashlib.sha256(f"{client_ip}{user_agent}{session_id}".encode()).hexdigest()[:16]
        }
        
        self.active_sessions[session_id] = session_data
        
        # Track user sessions
        if username not in self.user_sessions:
            self.user_sessions[username] = []
        self.user_sessions[username].append(session_id)
        
        # Log session creation
        self.threat_detector.log_security_event(SecurityEvent(
            event_type="session_created",
            severity="low",
            source_ip=client_ip,
            username=username,
            description=f"New session created: {session_id}",
            additional_data={"session_id": session_id, "user_agent": user_agent}
        ))
        
        return session_id
    
    def get_session(self, session_id: str, client_ip: str = "unknown", 
                   user_agent: str = None) -> Optional[Dict[str, Any]]:
        """Get session with security validation."""
        session = self.active_sessions.get(session_id)
        if not session:
            return None
        
        current_time = datetime.utcnow()
        
        # Check if session is expired
        timeout_minutes = getattr(self.config.security, 'session_timeout', 30)
        if current_time - session["last_activity"] > timedelta(minutes=timeout_minutes):
            self.destroy_session(session_id)
            return None
        
        # Validate session fingerprint
        expected_fingerprint = hashlib.sha256(
            f"{session['client_ip']}{session.get('user_agent', '')}{session_id}".encode()
        ).hexdigest()[:16]
        
        if session["fingerprint"] != expected_fingerprint:
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="session_hijack_attempt",
                severity="critical",
                source_ip=client_ip,
                username=session["username"],
                description=f"Session hijack attempt detected for session {session_id}"
            ))
            self.destroy_session(session_id)
            return None
        
        # Update session activity
        session["last_activity"] = current_time
        session["request_count"] += 1
        
        return session
    
    def destroy_session(self, session_id: str) -> bool:
        """Destroy a user session securely."""
        session = self.active_sessions.get(session_id)
        if not session:
            return False
        
        username = session["username"]
        
        # Remove from active sessions
        removed_session = self.active_sessions.pop(session_id, None)
        
        # Remove from user sessions tracking
        if username in self.user_sessions:
            if session_id in self.user_sessions[username]:
                self.user_sessions[username].remove(session_id)
            
            # Clean up empty user session list
            if not self.user_sessions[username]:
                del self.user_sessions[username]
        
        # Revoke associated token
        if removed_session and "token" in removed_session:
            self.revoke_token(removed_session["token"])
        
        # Log session destruction
        if removed_session:
            self.threat_detector.log_security_event(SecurityEvent(
                event_type="session_destroyed",
                severity="low",
                source_ip=session.get("client_ip", "unknown"),
                username=username,
                description=f"Session destroyed: {session_id}"
            ))
        
        return removed_session is not None
    
    def revoke_token(self, token: str):
        """Add token to revocation list."""
        try:
            # Extract JTI from token for revocation tracking
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            jti = unverified_payload.get("jti")
            if jti:
                self.revoked_tokens.add(jti)
                
                # Limit revoked tokens set size (keep only recent ones)
                if len(self.revoked_tokens) > 10000:
                    # In production, this should be stored in database
                    self.revoked_tokens = set(list(self.revoked_tokens)[-5000:])
        except Exception as e:
            logger.warning(f"Failed to extract JTI from token for revocation: {e}")
    
    def is_token_revoked(self, token: str) -> bool:
        """Check if token is revoked."""
        try:
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            jti = unverified_payload.get("jti")
            return jti in self.revoked_tokens if jti else False
        except Exception:
            return True  # Treat invalid tokens as revoked
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions and old revoked tokens."""
        current_time = datetime.utcnow()
        
        # Only run cleanup every 5 minutes
        if current_time - self._last_cleanup < timedelta(minutes=5):
            return
        
        timeout_minutes = getattr(self.config.security, 'session_timeout', 30)
        expired_sessions = []
        
        # Find expired sessions
        for session_id, session in self.active_sessions.items():
            if current_time - session["last_activity"] > timedelta(minutes=timeout_minutes):
                expired_sessions.append(session_id)
        
        # Remove expired sessions
        for session_id in expired_sessions:
            self.destroy_session(session_id)
        
        # Clean old revoked tokens (older than 24 hours)
        # In production, this should be handled by database TTL
        if len(self.revoked_tokens) > 1000:
            self.revoked_tokens = set(list(self.revoked_tokens)[-500:])
        
        self._last_cleanup = current_time
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_user_sessions(self, username: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user."""
        if username not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in self.user_sessions[username]:
            session = self.active_sessions.get(session_id)
            if session:
                sessions.append({
                    "session_id": session_id,
                    "created_at": session["created_at"],
                    "last_activity": session["last_activity"],
                    "client_ip": session["client_ip"],
                    "user_agent": session.get("user_agent"),
                    "request_count": session["request_count"]
                })
        
        return sessions
    
    def destroy_all_user_sessions(self, username: str) -> int:
        """Destroy all sessions for a specific user."""
        if username not in self.user_sessions:
            return 0
        
        session_ids = self.user_sessions[username].copy()
        destroyed_count = 0
        
        for session_id in session_ids:
            if self.destroy_session(session_id):
                destroyed_count += 1
        
        return destroyed_count


# Global instances
_auth_manager: Optional[AuthManager] = None
_session_manager: Optional[SessionManager] = None


def get_auth_manager() -> AuthManager:
    """Get the global authentication manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


def get_session_manager() -> SessionManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


# Dependency functions for FastAPI
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security),
                    request: Request = Depends()) -> Dict[str, Any]:
    """FastAPI dependency to get current authenticated user with enhanced security."""
    return get_auth_manager().get_current_user(credentials, request)


def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """FastAPI dependency to require admin privileges."""
    permissions = current_user.get("permissions", [])
    if "admin" not in permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


def require_write_permission(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """FastAPI dependency to require write permissions."""
    permissions = current_user.get("permissions", [])
    if "write" not in permissions and "admin" not in permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permissions required"
        )
    return current_user


def check_security_middleware(request: Request) -> bool:
    """Enhanced security middleware dependency."""
    client_ip = request.client.host
    threat_detector = get_threat_detector()
    
    # Check IP whitelist
    if not threat_detector.is_ip_whitelisted(client_ip):
        threat_detector.log_security_event(SecurityEvent(
            event_type="ip_not_whitelisted",
            severity="high",
            source_ip=client_ip,
            description="Request from non-whitelisted IP"
        ))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Check if IP is blocked
    if threat_detector.is_ip_blocked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="IP address temporarily blocked due to suspicious activity"
        )
    
    # Session cleanup (run periodically)
    session_manager = get_session_manager()
    session_manager.cleanup_expired_sessions()
    
    return True


def validate_request_size(request: Request) -> bool:
    """Validate request size to prevent DoS attacks."""
    if hasattr(request, 'headers'):
        content_length = request.headers.get('content-length')
        if content_length:
            try:
                size = int(content_length)
                # Limit request size to 10MB
                if size > 10 * 1024 * 1024:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Request too large"
                    )
            except ValueError:
                pass
    
    return True