"""
Site management API endpoints for the Nginx Site Manager.
Provides CRUD operations for nginx sites with proper validation and error handling.
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, status, Depends, Query
from pydantic import BaseModel, Field, validator

from app.auth import get_current_user, require_write_permission, require_admin
from app.models import get_site_model
from app.services.nginx_service import get_nginx_service


# Request/Response models
class SiteConfigModel(BaseModel):
    """Site configuration data model."""
    upstream_url: Optional[str] = None
    upstream_servers: Optional[List[str]] = None
    root_path: Optional[str] = None
    index_files: Optional[List[str]] = ["index.html", "index.htm"]
    custom_config: Optional[str] = None


class SiteCreateRequest(BaseModel):
    """Request model for creating a site."""
    name: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    domain: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., pattern=r"^(static|proxy|load_balancer)$")
    config: SiteConfigModel = SiteConfigModel()
    
    @validator('domain')
    def validate_domain(cls, v):
        # Basic domain validation
        if not v or '.' not in v:
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @validator('config')
    def validate_config(cls, v, values):
        site_type = values.get('type')
        if site_type == 'proxy' and not v.upstream_url:
            raise ValueError('upstream_url is required for proxy sites')
        if site_type == 'load_balancer' and not v.upstream_servers:
            raise ValueError('upstream_servers is required for load balancer sites')
        return v


class SiteUpdateRequest(BaseModel):
    """Request model for updating a site."""
    domain: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[SiteConfigModel] = None
    
    @validator('domain')
    def validate_domain(cls, v):
        if v is not None:
            if not v or '.' not in v:
                raise ValueError('Invalid domain format')
            return v.lower()
        return v


class SiteResponse(BaseModel):
    """Response model for site data."""
    id: int
    name: str
    domain: str
    type: str
    enabled: bool
    ssl_enabled: bool
    config_path: Optional[str]
    created_at: datetime
    updated_at: datetime
    config: Dict[str, Any]


class SiteListResponse(BaseModel):
    """Response model for site list."""
    sites: List[SiteResponse]
    total: int


class SiteStatusResponse(BaseModel):
    """Response model for site status."""
    site_id: int
    name: str
    enabled: bool
    nginx_config_exists: bool
    nginx_config_valid: bool
    web_directory_exists: bool


# Router setup
router = APIRouter(prefix="/api/sites", tags=["sites"])
site_model = get_site_model()
nginx_service = get_nginx_service()


@router.get("/", response_model=SiteListResponse)
async def list_sites(
    enabled_only: bool = Query(False, description="Show only enabled sites"),
    search: Optional[str] = Query(None, description="Search sites by name or domain"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List all sites with optional filtering."""
    try:
        if search:
            sites = site_model.search(search)
        else:
            sites = site_model.list_all(enabled_only=enabled_only)
        
        return SiteListResponse(
            sites=[SiteResponse(**site) for site in sites],
            total=len(sites)
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing sites: {str(e)}"
        )


@router.post("/", response_model=SiteResponse, status_code=status.HTTP_201_CREATED)
async def create_site(
    site_data: SiteCreateRequest,
    current_user: Dict[str, Any] = Depends(require_write_permission)
):
    """Create a new site."""
    try:
        # Check if site name already exists
        if site_model.exists(site_data.name):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Site with name '{site_data.name}' already exists"
            )
        
        # Create site in database
        site_id = site_model.create(
            name=site_data.name,
            domain=site_data.domain,
            site_type=site_data.type,
            config_data=site_data.config.dict()
        )
        
        # Generate and save nginx configuration
        site_record = site_model.get_by_id(site_id)
        config_content = nginx_service.generate_config(site_record)
        
        success, message = nginx_service.save_config(site_id, config_content)
        if not success:
            # Rollback: delete the site from database
            site_model.delete(site_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to save nginx configuration: {message}"
            )
        
        # Create web directory for static sites
        if site_data.type == "static":
            success, message = nginx_service.create_web_directory(site_data.name)
            if not success:
                # Log warning but don't fail the creation
                pass
        
        # Return the created site
        created_site = site_model.get_by_id(site_id)
        return SiteResponse(**created_site)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating site: {str(e)}"
        )


@router.get("/{site_id}", response_model=SiteResponse)
async def get_site(
    site_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get a specific site by ID."""
    site = site_model.get_by_id(site_id)
    if not site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Site not found"
        )
    
    return SiteResponse(**site)


@router.put("/{site_id}", response_model=SiteResponse)
async def update_site(
    site_id: int,
    site_data: SiteUpdateRequest,
    current_user: Dict[str, Any] = Depends(require_write_permission)
):
    """Update a site."""
    try:
        # Check if site exists
        existing_site = site_model.get_by_id(site_id)
        if not existing_site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Site not found"
            )
        
        # Prepare update data
        updates = {}
        if site_data.domain is not None:
            updates['domain'] = site_data.domain
        if site_data.config is not None:
            updates['config'] = site_data.config.dict()
        
        # Update site in database
        if updates:
            success = site_model.update(site_id, **updates)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to update site"
                )
        
        # Regenerate nginx configuration if the site is enabled
        updated_site = site_model.get_by_id(site_id)
        if updated_site['enabled']:
            config_content = nginx_service.generate_config(updated_site)
            success, message = nginx_service.save_config(site_id, config_content)
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to update nginx configuration: {message}"
                )
            
            # Reload nginx to apply changes
            success, message = nginx_service.reload_nginx()
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to reload nginx: {message}"
                )
        
        return SiteResponse(**updated_site)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating site: {str(e)}"
        )


@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
    site_id: int,
    current_user: Dict[str, Any] = Depends(require_write_permission)
):
    """Delete a site."""
    try:
        # Check if site exists
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Site not found"
            )
        
        # Delete nginx configuration files
        nginx_service.delete_site_config(site_id)
        
        # Delete site from database
        success = site_model.delete(site_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete site from database"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting site: {str(e)}"
        )


@router.post("/{site_id}/enable", response_model=Dict[str, str])
async def enable_site(
    site_id: int,
    current_user: Dict[str, Any] = Depends(require_write_permission)
):
    """Enable a site."""
    try:
        # Check if site exists
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Site not found"
            )
        
        if site['enabled']:
            return {"message": f"Site {site['name']} is already enabled"}
        
        # Enable site
        success, message = nginx_service.enable_site(site_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        return {"message": message}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error enabling site: {str(e)}"
        )


@router.post("/{site_id}/disable", response_model=Dict[str, str])
async def disable_site(
    site_id: int,
    current_user: Dict[str, Any] = Depends(require_write_permission)
):
    """Disable a site."""
    try:
        # Check if site exists
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Site not found"
            )
        
        if not site['enabled']:
            return {"message": f"Site {site['name']} is already disabled"}
        
        # Disable site
        success, message = nginx_service.disable_site(site_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        
        return {"message": message}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error disabling site: {str(e)}"
        )


@router.get("/{site_id}/status", response_model=SiteStatusResponse)
async def get_site_status(
    site_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get detailed status of a site."""
    try:
        # Check if site exists
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Site not found"
            )
        
        # Check nginx configuration
        config_exists = bool(site.get('config_path')) and os.path.exists(site['config_path'])
        config_valid = False
        
        if config_exists:
            with open(site['config_path'], 'r') as f:
                config_content = f.read()
            config_valid, _ = nginx_service.validate_config(config_content)
        
        # Check web directory (for static sites)
        web_dir_exists = False
        if site['type'] == 'static':
            web_dir = os.path.join(nginx_service.config.paths.web_root, site['name'])
            web_dir_exists = os.path.exists(web_dir)
        
        return SiteStatusResponse(
            site_id=site_id,
            name=site['name'],
            enabled=site['enabled'],
            nginx_config_exists=config_exists,
            nginx_config_valid=config_valid,
            web_directory_exists=web_dir_exists
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting site status: {str(e)}"
        )


@router.get("/{site_id}/config", response_model=Dict[str, str])
async def get_site_config(
    site_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get the nginx configuration for a site."""
    try:
        # Check if site exists
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Site not found"
            )
        
        # Read configuration file
        config_path = site.get('config_path')
        if not config_path or not os.path.exists(config_path):
            # Generate configuration if it doesn't exist
            config_content = nginx_service.generate_config(site)
        else:
            with open(config_path, 'r') as f:
                config_content = f.read()
        
        return {"config": config_content}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting site configuration: {str(e)}"
        )