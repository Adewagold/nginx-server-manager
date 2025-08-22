"""
System management API endpoints for the Nginx Site Manager.
Provides system operations like nginx reload, status checks, and service management.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel

from app.auth import get_current_user, require_admin
from app.services.nginx_service import get_nginx_service
from app.services.log_service import get_log_service


# Response models
class SystemResponse(BaseModel):
    """Generic system response model."""
    success: bool
    message: str


class NginxStatusResponse(BaseModel):
    """Nginx status response model."""
    running: bool
    version: str
    config_test: bool
    uptime: str
    worker_processes: int


# Response models for logs
class LogEntryResponse(BaseModel):
    """Log entry response model."""
    timestamp: str
    ip_address: str = ""
    method: str = ""
    path: str = ""
    status_code: int = 0
    response_size: str = ""
    referer: str = ""
    user_agent: str = ""
    log_level: str = ""
    message: str = ""
    raw_line: str


class LogResponse(BaseModel):
    """Log response model."""
    entries: List[LogEntryResponse]
    total_entries: int
    log_files: List[str]


class LogStatsResponse(BaseModel):
    """Log statistics response model."""
    access_logs: Dict[str, Any]
    error_logs: Dict[str, Any]


# Router setup
router = APIRouter(prefix="/api/system", tags=["system"])
nginx_service = get_nginx_service()
log_service = get_log_service()


@router.post("/nginx/reload", response_model=SystemResponse)
async def reload_nginx(
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Reload nginx configuration."""
    try:
        success, message = nginx_service.reload_nginx()
        
        if success:
            return SystemResponse(success=True, message=message)
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=message
            )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reloading nginx: {str(e)}"
        )


@router.post("/nginx/restart", response_model=SystemResponse)
async def restart_nginx(
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Restart nginx service."""
    try:
        success, message = nginx_service.restart_nginx()
        
        if success:
            return SystemResponse(success=True, message=message)
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=message
            )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error restarting nginx: {str(e)}"
        )


@router.post("/nginx/test", response_model=SystemResponse)
async def test_nginx_config(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Test nginx configuration."""
    try:
        success, message = nginx_service.test_config()
        
        if success:
            return SystemResponse(success=True, message=message)
        else:
            return SystemResponse(success=False, message=message)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error testing nginx config: {str(e)}"
        )


@router.get("/nginx/status", response_model=Dict[str, Any])
async def get_nginx_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get nginx service status."""
    try:
        status_info = nginx_service.get_nginx_status()
        return status_info
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting nginx status: {str(e)}"
        )


@router.get("/health")
async def system_health():
    """System health check."""
    try:
        nginx_status = nginx_service.get_nginx_status()
        
        return {
            "status": "healthy" if nginx_status.get("running", False) else "degraded",
            "nginx": nginx_status,
            "services": {
                "nginx": "running" if nginx_status.get("running", False) else "stopped"
            }
        }
    
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }


@router.get("/logs/nginx/access", response_model=LogResponse)
async def get_nginx_access_logs(
    lines: int = 100,
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get nginx access logs."""
    try:
        # Validate lines parameter
        if lines < 1 or lines > 5000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Lines parameter must be between 1 and 5000"
            )
        
        entries = log_service.get_access_logs(site_name=None, lines=lines, search=search)
        
        # Convert to response format
        log_entries = []
        for entry in entries:
            log_entries.append(LogEntryResponse(
                timestamp=entry.timestamp,
                ip_address=entry.ip_address,
                method=entry.method,
                path=entry.path,
                status_code=entry.status_code,
                response_size=entry.response_size,
                referer=entry.referer,
                user_agent=entry.user_agent,
                raw_line=entry.raw_line
            ))
        
        # Get log file paths for info
        log_files = log_service._get_access_log_files(None)
        
        return LogResponse(
            entries=log_entries,
            total_entries=len(log_entries),
            log_files=log_files
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading access logs: {str(e)}"
        )


@router.get("/logs/nginx/error", response_model=LogResponse)
async def get_nginx_error_logs(
    lines: int = 100,
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get nginx error logs."""
    try:
        # Validate lines parameter
        if lines < 1 or lines > 5000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Lines parameter must be between 1 and 5000"
            )
        
        entries = log_service.get_error_logs(site_name=None, lines=lines, search=search)
        
        # Convert to response format
        log_entries = []
        for entry in entries:
            log_entries.append(LogEntryResponse(
                timestamp=entry.timestamp,
                log_level=entry.log_level,
                message=entry.message,
                raw_line=entry.raw_line
            ))
        
        # Get log file paths for info
        log_files = log_service._get_error_log_files(None)
        
        return LogResponse(
            entries=log_entries,
            total_entries=len(log_entries),
            log_files=log_files
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading error logs: {str(e)}"
        )


@router.get("/logs/stats", response_model=LogStatsResponse)
async def get_log_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get log file statistics."""
    try:
        stats = log_service.get_log_stats()
        return LogStatsResponse(**stats)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting log stats: {str(e)}"
        )