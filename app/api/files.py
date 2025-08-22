"""
File Management API endpoints.
Provides REST API for file operations on static sites.
"""

import os
import shutil
import mimetypes
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.auth import get_current_user
from app.services.file_service import get_file_service
from app.models import get_site_model


router = APIRouter(prefix="/api/files", tags=["files"])


class FileInfo(BaseModel):
    """File information model."""
    name: str
    path: str
    relative_path: str
    type: str  # 'file' or 'directory'
    size: int
    modified: datetime
    permissions: str
    mime_type: Optional[str] = None
    is_editable: bool = False


class CreateFileRequest(BaseModel):
    """Request model for creating files/directories."""
    name: str
    type: str  # 'file' or 'directory'
    content: Optional[str] = ""


class EditFileRequest(BaseModel):
    """Request model for editing files."""
    content: str


class RenameRequest(BaseModel):
    """Request model for renaming files/directories."""
    new_name: str


class MoveRequest(BaseModel):
    """Request model for moving files/directories."""
    destination_path: str


@router.get("/sites/{site_id}/files")
async def list_files(
    site_id: int,
    path: str = "/",
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """List files and directories in a site's directory."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # List files in the directory
        files = file_service.list_files(site_id, path)
        
        return {
            "site_id": site_id,
            "site_name": site['name'],
            "current_path": path,
            "files": [file.__dict__ for file in files],
            "total": len(files)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/sites/{site_id}/files/upload")
async def upload_files(
    site_id: int,
    path: str = Form("/"),
    files: List[UploadFile] = File(...),
    extract_zip: bool = Form(False),
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Upload files to a site's directory."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Upload files
        results = []
        for file in files:
            success, message = file_service.upload_file(
                site_id, path, file, extract_zip
            )
            results.append({
                "filename": file.filename,
                "success": success,
                "message": message
            })
        
        successful_uploads = sum(1 for result in results if result["success"])
        
        return {
            "uploaded": successful_uploads,
            "total": len(files),
            "results": results
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/sites/{site_id}/files/create")
async def create_file_or_directory(
    site_id: int,
    path: str,
    request: CreateFileRequest,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Create a new file or directory."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Create file or directory
        success, message = file_service.create_file_or_directory(
            site_id, path, request.name, request.type, request.content
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "created": request.name,
                "type": request.type
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/sites/{site_id}/files/content")
async def get_file_content(
    site_id: int,
    file_path: str,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get file content for editing."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Get file content
        content, encoding = file_service.get_file_content(site_id, file_path)
        
        return {
            "file_path": file_path,
            "content": content,
            "encoding": encoding,
            "editable": file_service.is_file_editable(file_path)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.put("/sites/{site_id}/files/content")
async def edit_file_content(
    site_id: int,
    file_path: str,
    request: EditFileRequest,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Edit file content."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Save file content
        success, message = file_service.save_file_content(
            site_id, file_path, request.content
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "file_path": file_path
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.delete("/sites/{site_id}/files")
async def delete_file_or_directory(
    site_id: int,
    file_path: str,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Delete a file or directory."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Delete file or directory
        success, message = file_service.delete_file_or_directory(site_id, file_path)
        
        if success:
            return {
                "success": True,
                "message": message,
                "deleted": file_path
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/sites/{site_id}/files/rename")
async def rename_file_or_directory(
    site_id: int,
    file_path: str,
    request: RenameRequest,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Rename a file or directory."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Rename file or directory
        success, message, new_path = file_service.rename_file_or_directory(
            site_id, file_path, request.new_name
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "old_path": file_path,
                "new_path": new_path
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/sites/{site_id}/files/move")
async def move_file_or_directory(
    site_id: int,
    file_path: str,
    request: MoveRequest,
    _: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """Move a file or directory to a different location."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Move file or directory
        success, message, new_path = file_service.move_file_or_directory(
            site_id, file_path, request.destination_path
        )
        
        if success:
            return {
                "success": True,
                "message": message,
                "old_path": file_path,
                "new_path": new_path
            }
        else:
            raise HTTPException(status_code=400, detail=message)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.get("/sites/{site_id}/files/download")
async def download_file(
    site_id: int,
    file_path: str,
    _: dict = Depends(get_current_user)
) -> FileResponse:
    """Download a file."""
    try:
        file_service = get_file_service()
        site_model = get_site_model()
        
        # Get site information
        site = site_model.get_by_id(site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Only allow file management for static sites
        if site['type'] != 'static':
            raise HTTPException(
                status_code=400, 
                detail="File management is only available for static sites"
            )
        
        # Get absolute file path
        absolute_path = file_service.get_absolute_path(site_id, file_path)
        
        if not absolute_path.exists() or not absolute_path.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Validate file is within site directory (security check)
        if not file_service.is_path_safe(site_id, file_path):
            raise HTTPException(status_code=403, detail="Access denied")
        
        return FileResponse(
            path=str(absolute_path),
            filename=absolute_path.name,
            media_type='application/octet-stream'
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")