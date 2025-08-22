"""
System management API endpoints for the Nginx Site Manager.
Provides system operations like nginx reload, status checks, and service management.
"""

from typing import Dict, Any
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel

from app.auth import get_current_user, require_admin
from app.services.nginx_service import get_nginx_service


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


# Router setup
router = APIRouter(prefix="/api/system", tags=["system"])
nginx_service = get_nginx_service()


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