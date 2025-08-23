"""
FastAPI application entry point for the Nginx Site Manager.
Sets up the application, middleware, routes, and handles startup/shutdown events.
"""

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, status, Depends, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from jose import jwt

from app.config import get_config, init_config
from app.models import init_database
from app.auth import get_auth_manager, get_session_manager
from app.api.sites import router as sites_router
from app.api.system import router as system_router
from app.api.ssl import router as ssl_router
from app.api.files import router as files_router


# Initialize configuration and database
try:
    init_config()
    config = get_config()
    
    # Validate configuration
    config_errors = config.validate()
    if config_errors:
        print("Configuration validation errors:")
        for error in config_errors:
            print(f"  - {error}")
        if any("not exist" in error for error in config_errors):
            print("Please run the install.sh script to set up the system properly.")
        exit(1)
    
    init_database()
    
except Exception as e:
    print(f"Failed to initialize application: {e}")
    exit(1)


# Setup logging
logging.basicConfig(
    level=getattr(logging, config.logging.level),
    format=config.logging.format
)
logger = logging.getLogger(__name__)


# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    logger.info("Starting Nginx Site Manager...")
    
    # Clean up expired sessions periodically
    session_manager = get_session_manager()
    session_manager.cleanup_expired_sessions()
    
    yield
    
    # Shutdown
    logger.info("Shutting down Nginx Site Manager...")


# Create FastAPI application
app = FastAPI(
    title="Nginx Site Manager",
    description="A web-based platform for managing nginx sites, SSL certificates, and configurations",
    version="1.0.0",
    docs_url="/docs" if config.app.debug else None,
    redoc_url="/redoc" if config.app.debug else None,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.security.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Setup templates and static files
templates = Jinja2Templates(directory="app/templates/web")

# Mount static files
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Include API routers
app.include_router(sites_router)
app.include_router(system_router)
app.include_router(ssl_router)
app.include_router(files_router)

# Authentication manager
auth_manager = get_auth_manager()
session_manager = get_session_manager()


# Authentication endpoints
@app.post("/auth/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Authenticate user and return JWT token."""
    # Authenticate user
    user = auth_manager.authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = auth_manager.create_access_token(data=user)
    
    # Create session
    session_id = session_manager.create_session(username, access_token)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "session_id": session_id,
        "expires_in": config.app.access_token_expire_minutes * 60
    }


@app.post("/auth/logout")
async def logout(session_id: str = Form(...)):
    """Logout user and destroy session."""
    success = session_manager.destroy_session(session_id)
    return {"message": "Logged out successfully" if success else "Session not found"}


# System status endpoints
@app.get("/api/system/status")
async def get_system_status(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    """Get system and nginx status."""
    from app.services.nginx_service import get_nginx_service
    
    nginx_service = get_nginx_service()
    nginx_status = nginx_service.get_nginx_status()
    
    return {
        "nginx": nginx_status,
        "application": {
            "version": "1.0.0",
            "uptime": "N/A",  # Could implement uptime tracking
            "database": "connected"
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/system/reload")
async def reload_nginx(current_user: Dict[str, Any] = Depends(auth_manager.require_permission("admin"))):
    """Reload nginx service."""
    from app.services.nginx_service import get_nginx_service
    
    nginx_service = get_nginx_service()
    success, message = nginx_service.reload_nginx()
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )
    
    return {"message": message}


# Web interface routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/sites", response_class=HTMLResponse)
async def sites_page(request: Request):
    """Sites management page."""
    return templates.TemplateResponse("sites.html", {"request": request})


@app.get("/sites/new", response_class=HTMLResponse)
async def new_site_page(request: Request):
    """New site creation page."""
    return templates.TemplateResponse("new_site.html", {"request": request})


@app.get("/sites/{site_id}", response_class=HTMLResponse)
async def site_detail_page(request: Request, site_id: int):
    """Site detail and edit page."""
    return templates.TemplateResponse("site_detail.html", {
        "request": request,
        "site_id": site_id
    })


@app.get("/sites/{site_id}/edit", response_class=HTMLResponse)
async def edit_site_page(request: Request, site_id: int):
    """Edit site configuration page."""
    return templates.TemplateResponse("edit_site.html", {
        "request": request,
        "site_id": site_id
    })


@app.get("/ssl", response_class=HTMLResponse)
async def ssl_dashboard_page(request: Request):
    """SSL certificate management dashboard."""
    return templates.TemplateResponse("ssl_dashboard.html", {"request": request})


@app.get("/sites/{site_id}/files", response_class=HTMLResponse)
async def file_manager_page(request: Request, site_id: int):
    """File manager page for static sites."""
    return templates.TemplateResponse("file_manager.html", {
        "request": request,
        "site_id": site_id
    })


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Custom 404 handler."""
    if request.url.path.startswith("/api/"):
        return {"detail": "Not found"}
    return templates.TemplateResponse("404.html", {"request": request}, status_code=404)


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    """Custom 500 handler."""
    logger.error(f"Internal server error: {exc}")
    if request.url.path.startswith("/api/"):
        return {"detail": "Internal server error"}
    return templates.TemplateResponse("500.html", {"request": request}, status_code=500)


# Middleware for logging requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests."""
    start_time = datetime.utcnow()
    
    response = await call_next(request)
    
    process_time = (datetime.utcnow() - start_time).total_seconds()
    
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.3f}s"
    )
    
    return response


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
        log_level=config.logging.level.lower()
    )