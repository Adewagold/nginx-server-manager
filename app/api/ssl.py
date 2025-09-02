"""
SSL Certificate API endpoints.
Provides REST API for SSL certificate management with Let's Encrypt.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from typing import Dict, Any, List, Optional

from app.auth import get_current_user
from app.services.ssl_service import get_ssl_service
from app.services.nginx_service import get_nginx_service
from app.models import get_site_model


router = APIRouter(prefix="/api/ssl", tags=["ssl"])


class SSLEnableRequest(BaseModel):
    """Request model for enabling SSL."""
    email: EmailStr
    force_regenerate: bool = False


class SSLRenewalRequest(BaseModel):
    """Request model for certificate renewal."""
    force: bool = False


@router.post("/sites/{site_id}/enable")
async def enable_ssl(
    site_id: int, 
    request: SSLEnableRequest,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Enable SSL for a site."""
    try:
        ssl_service = get_ssl_service()
        nginx_service = get_nginx_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Check if certbot is available
        if not ssl_service.is_certbot_available():
            raise HTTPException(
                status_code=400, 
                detail="Certbot not installed. Please install certbot first."
            )
        
        # Enable SSL for the site
        success, message = ssl_service.enable_ssl_for_site(site_id, request.email)
        
        if success:
            # Regenerate nginx configuration with SSL
            config_success, config_message = nginx_service.generate_site_config(site_id)
            
            if config_success:
                # Test and reload nginx
                test_success, test_message = nginx_service.test_config()
                if test_success:
                    reload_success, reload_message = nginx_service.reload_nginx()
                    if reload_success:
                        cert_info = ssl_service.get_certificate_info(site['domain'])
                        return {
                            "success": True,
                            "message": "SSL enabled successfully",
                            "certificate_info": cert_info.__dict__ if cert_info else None
                        }
                    else:
                        return {
                            "success": False,
                            "message": f"SSL enabled but nginx reload failed: {reload_message}"
                        }
                else:
                    return {
                        "success": False,
                        "message": f"SSL enabled but nginx config test failed: {test_message}"
                    }
            else:
                return {
                    "success": False,
                    "message": f"SSL enabled but nginx config generation failed: {config_message}"
                }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/sites/{site_id}/disable")
async def disable_ssl(
    site_id: int,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Disable SSL for a site."""
    try:
        ssl_service = get_ssl_service()
        nginx_service = get_nginx_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Disable SSL for the site
        success, message = ssl_service.disable_ssl_for_site(site_id)
        
        if success:
            # Regenerate nginx configuration without SSL
            config_success, config_message = nginx_service.generate_site_config(site_id)
            
            if config_success:
                # Test and reload nginx
                test_success, test_message = nginx_service.test_config()
                if test_success:
                    reload_success, reload_message = nginx_service.reload_nginx()
                    if reload_success:
                        return {
                            "success": True,
                            "message": "SSL disabled successfully"
                        }
                    else:
                        return {
                            "success": False,
                            "message": f"SSL disabled but nginx reload failed: {reload_message}"
                        }
                else:
                    return {
                        "success": False,
                        "message": f"SSL disabled but nginx config test failed: {test_message}"
                    }
            else:
                return {
                    "success": False,
                    "message": f"SSL disabled but nginx config generation failed: {config_message}"
                }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/sites/{site_id}/status")
async def get_ssl_status(
    site_id: int,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get SSL status for a site."""
    try:
        ssl_service = get_ssl_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Get certificate information - use primary domain (first one)
        domain = site['domain']
        primary_domain = domain.split()[0] if ' ' in domain else domain
        cert_info = ssl_service.get_certificate_info(primary_domain)
        
        return {
            "site_id": site_id,
            "domain": site['domain'],
            "ssl_enabled": bool(site.get('ssl_enabled', False)),
            "ssl_status": site.get('ssl_status', 'disabled'),
            "certificate": cert_info.__dict__ if cert_info else None,
            "certbot_available": ssl_service.is_certbot_available()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/sites/{site_id}/renew")
async def renew_certificate(
    site_id: int,
    request: SSLRenewalRequest,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Renew SSL certificate for a site."""
    try:
        ssl_service = get_ssl_service()
        nginx_service = get_nginx_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        if not site.get('ssl_enabled', False):
            raise HTTPException(status_code=400, detail="SSL not enabled for this site")
        
        # Set SSL status to pending
        site_model.set_ssl_status(site_id, 'pending')
        
        # Renew certificate
        success, message = ssl_service.renew_certificate(site['domain'])
        
        if success:
            # Update certificate information
            cert_info = ssl_service.get_certificate_info(site['domain'])
            if cert_info:
                ssl_service._update_site_ssl_info(site_id, cert_info)
            
            # Reload nginx to use new certificate
            reload_success, reload_message = nginx_service.reload_nginx()
            
            return {
                "success": True,
                "message": "Certificate renewed successfully",
                "nginx_reload": reload_success,
                "certificate_info": cert_info.__dict__ if cert_info else None
            }
        else:
            # Set SSL status to error
            site_model.set_ssl_status(site_id, 'error')
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        site_model.set_ssl_status(site_id, 'error')
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/certificates")
async def list_certificates(_: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """List all SSL certificates."""
    try:
        ssl_service = get_ssl_service()
        
        certificates = ssl_service.list_certificates()
        
        return {
            "certificates": [cert.__dict__ for cert in certificates],
            "total": len(certificates),
            "certbot_available": ssl_service.is_certbot_available(),
            "certbot_version": ssl_service.get_certbot_version()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/expiring")
async def get_expiring_certificates(_: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Get certificates that are expiring soon."""
    try:
        ssl_service = get_ssl_service()
        
        expiring = ssl_service.check_certificate_expiry()
        
        return {
            "expiring_certificates": expiring,
            "total": len(expiring)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/auto-renewal/setup")
async def setup_auto_renewal(_: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Setup automatic certificate renewal."""
    try:
        ssl_service = get_ssl_service()
        
        success, message = ssl_service.setup_auto_renewal()
        
        if success:
            return {
                "success": True,
                "message": message,
                "renewal_status": ssl_service.get_renewal_status()
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/auto-renewal/status")
async def get_auto_renewal_status(_: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Get automatic renewal status."""
    try:
        ssl_service = get_ssl_service()
        
        return ssl_service.get_renewal_status()
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/install-certbot")
async def install_certbot(_: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Install certbot if not available."""
    try:
        ssl_service = get_ssl_service()
        
        if ssl_service.is_certbot_available():
            return {
                "success": True,
                "message": "Certbot is already installed"
            }
        
        success, message = ssl_service.install_certbot()
        
        if success:
            return {
                "success": True,
                "message": message
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/system/status")
async def get_ssl_system_status(_: dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Get SSL system status and configuration."""
    try:
        ssl_service = get_ssl_service()
        site_model = get_site_model()
        
        # Get SSL sites count
        ssl_sites = site_model.get_ssl_sites()
        
        # Get expiring certificates
        expiring = ssl_service.check_certificate_expiry()
        
        return {
            "certbot_available": ssl_service.is_certbot_available(),
            "certbot_version": ssl_service.get_certbot_version(),
            "letsencrypt_directory": ssl_service.letsencrypt_dir,
            "ssl_sites_count": len(ssl_sites),
            "expiring_certificates_count": len(expiring),
            "auto_renewal": ssl_service.get_renewal_status()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")