"""
JWT Authentication system for the Nginx Site Manager.
Handles user authentication, token generation, and security middleware.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import secrets

from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt

from app.config import get_config


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer()


class AuthManager:
    """Manages authentication operations."""
    
    def __init__(self):
        self.config = get_config()
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return pwd_context.hash(password)
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user credentials."""
        # For now, we only support the admin user from config
        # In the future, this could be extended to support a user database
        admin_config = self.config.admin
        
        if username != admin_config.username:
            return None
        
        # For initial setup, allow plain text password comparison
        # In production, passwords should be hashed
        if password == admin_config.password:
            return {
                "username": username,
                "role": "admin",
                "permissions": ["read", "write", "admin"]
            }
        
        return None
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.config.app.access_token_expire_minutes
            )
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        
        encoded_jwt = jwt.encode(
            to_encode, 
            self.config.app.secret_key, 
            algorithm="HS256"
        )
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(
                token, 
                self.config.app.secret_key, 
                algorithms=["HS256"]
            )
            
            username: str = payload.get("username")
            if username is None:
                return None
            
            # Check if token is expired
            exp = payload.get("exp")
            if exp and datetime.utcnow() > datetime.fromtimestamp(exp):
                return None
            
            return payload
            
        except JWTError:
            return None
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
        """Get current authenticated user from JWT token."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            payload = self.verify_token(credentials.credentials)
            if payload is None:
                raise credentials_exception
            
            username: str = payload.get("username")
            if username is None:
                raise credentials_exception
                
        except JWTError:
            raise credentials_exception
        
        return payload
    
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
    """Manages user sessions and rate limiting."""
    
    def __init__(self):
        self.config = get_config()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.login_attempts: Dict[str, List[datetime]] = {}
    
    def create_session(self, username: str, token: str) -> str:
        """Create a new user session."""
        session_id = secrets.token_urlsafe(32)
        self.active_sessions[session_id] = {
            "username": username,
            "token": token,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information."""
        session = self.active_sessions.get(session_id)
        if session:
            # Check if session is expired
            timeout_minutes = self.config.security.session_timeout
            if datetime.utcnow() - session["last_activity"] > timedelta(minutes=timeout_minutes):
                self.destroy_session(session_id)
                return None
            
            # Update last activity
            session["last_activity"] = datetime.utcnow()
            return session
        return None
    
    def destroy_session(self, session_id: str) -> bool:
        """Destroy a user session."""
        return self.active_sessions.pop(session_id, None) is not None
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        timeout_minutes = self.config.security.session_timeout
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if datetime.utcnow() - session["last_activity"] > timedelta(minutes=timeout_minutes):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.destroy_session(session_id)
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client IP is within rate limits."""
        rate_limit = self.config.security.rate_limit
        current_time = datetime.utcnow()
        
        # Initialize if not exists
        if client_ip not in self.login_attempts:
            self.login_attempts[client_ip] = []
        
        # Remove attempts older than 1 minute
        self.login_attempts[client_ip] = [
            attempt for attempt in self.login_attempts[client_ip]
            if current_time - attempt < timedelta(minutes=1)
        ]
        
        # Check rate limit
        if len(self.login_attempts[client_ip]) >= rate_limit:
            return False
        
        # Record this attempt
        self.login_attempts[client_ip].append(current_time)
        return True


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
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """FastAPI dependency to get current authenticated user."""
    return get_auth_manager().get_current_user(credentials)


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


def check_rate_limit(request: Request) -> bool:
    """FastAPI dependency to check rate limiting."""
    client_ip = request.client.host
    session_manager = get_session_manager()
    
    if not session_manager.check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    return True