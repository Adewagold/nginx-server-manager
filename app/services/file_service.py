"""
File management service for static sites.
Provides secure file operations with path validation and access control.
"""

import os
import shutil
import mimetypes
import zipfile
import re
from pathlib import Path
from typing import List, Tuple, Optional, Union
from datetime import datetime
from dataclasses import dataclass

from fastapi import UploadFile

from app.config import get_config
from app.models import get_site_model


@dataclass
class FileInfo:
    """File information dataclass."""
    name: str
    path: str
    relative_path: str
    type: str  # 'file' or 'directory'
    size: int
    modified: datetime
    permissions: str
    mime_type: Optional[str] = None
    is_editable: bool = False


class FileService:
    """Service for managing files in static sites."""
    
    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {
        # Web files
        '.html', '.htm', '.css', '.js', '.json', '.xml',
        # Images
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
        # Fonts
        '.woff', '.woff2', '.ttf', '.otf', '.eot',
        # Documents
        '.txt', '.md', '.pdf', '.doc', '.docx',
        # Archives
        '.zip', '.tar', '.gz',
        # Other
        '.robots', '.htaccess', '.webmanifest'
    }
    
    # Editable file extensions
    EDITABLE_EXTENSIONS = {
        '.html', '.htm', '.css', '.js', '.json', '.xml',
        '.txt', '.md', '.htaccess', '.robots', '.webmanifest'
    }
    
    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    def __init__(self):
        self.config = get_config()
        self.site_model = get_site_model()
        self.web_root = Path(self.config.paths.web_root)
    
    def get_site_directory(self, site_id: int) -> Path:
        """Get the root directory for a site."""
        site = self.site_model.get_by_id(site_id)
        if not site:
            raise ValueError("Site not found")
        
        return self.web_root / site['name']
    
    def get_absolute_path(self, site_id: int, relative_path: str) -> Path:
        """Convert relative path to absolute path within site directory."""
        site_dir = self.get_site_directory(site_id)
        
        # Normalize path and ensure it's within site directory
        clean_path = relative_path.strip('/')
        if clean_path:
            absolute_path = site_dir / clean_path
        else:
            absolute_path = site_dir
        
        # Resolve path to handle .. and . components
        try:
            resolved_path = absolute_path.resolve()
        except OSError:
            raise ValueError("Invalid path")
        
        # Ensure path is within site directory (security check)
        if not str(resolved_path).startswith(str(site_dir.resolve())):
            raise ValueError("Path outside site directory")
        
        return resolved_path
    
    def is_path_safe(self, site_id: int, relative_path: str) -> bool:
        """Check if a path is safe (within site directory)."""
        try:
            self.get_absolute_path(site_id, relative_path)
            return True
        except ValueError:
            return False
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent security issues."""
        # Remove any path components
        filename = os.path.basename(filename)
        
        # Replace dangerous characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Remove control characters
        filename = ''.join(char for char in filename if ord(char) >= 32)
        
        # Ensure filename is not empty and doesn't start with dot (hidden files)
        if not filename or filename.startswith('.'):
            filename = 'file_' + filename
        
        return filename
    
    def is_allowed_file(self, filename: str) -> bool:
        """Check if file extension is allowed."""
        ext = Path(filename).suffix.lower()
        return ext in self.ALLOWED_EXTENSIONS or not ext  # Allow files without extension
    
    def is_file_editable(self, filename: str) -> bool:
        """Check if file can be edited in the text editor."""
        ext = Path(filename).suffix.lower()
        return ext in self.EDITABLE_EXTENSIONS
    
    def get_file_info(self, file_path: Path, site_dir: Path) -> FileInfo:
        """Get file information."""
        try:
            stat = file_path.stat()
            relative_path = file_path.relative_to(site_dir)
            
            # Get MIME type
            mime_type = None
            if file_path.is_file():
                mime_type, _ = mimetypes.guess_type(str(file_path))
            
            return FileInfo(
                name=file_path.name,
                path=str(file_path),
                relative_path=str(relative_path),
                type='directory' if file_path.is_dir() else 'file',
                size=stat.st_size if file_path.is_file() else 0,
                modified=datetime.fromtimestamp(stat.st_mtime),
                permissions=oct(stat.st_mode)[-3:],
                mime_type=mime_type,
                is_editable=self.is_file_editable(file_path.name) if file_path.is_file() else False
            )
        except Exception as e:
            # Return basic info if stat fails
            return FileInfo(
                name=file_path.name,
                path=str(file_path),
                relative_path=str(file_path.relative_to(site_dir)),
                type='directory' if file_path.is_dir() else 'file',
                size=0,
                modified=datetime.now(),
                permissions="000",
                mime_type=None,
                is_editable=False
            )
    
    def list_files(self, site_id: int, relative_path: str = "/") -> List[FileInfo]:
        """List files and directories in a path."""
        try:
            directory = self.get_absolute_path(site_id, relative_path)
            site_dir = self.get_site_directory(site_id)
            
            if not directory.exists():
                return []
            
            if not directory.is_dir():
                raise ValueError("Path is not a directory")
            
            files = []
            
            # Add parent directory link if not at root
            if relative_path != "/" and relative_path:
                parent_path = directory.parent
                if parent_path != site_dir.parent:  # Don't go above site root
                    files.append(FileInfo(
                        name="..",
                        path=str(parent_path),
                        relative_path=str(parent_path.relative_to(site_dir)),
                        type="directory",
                        size=0,
                        modified=datetime.now(),
                        permissions="755",
                        mime_type=None,
                        is_editable=False
                    ))
            
            # List directory contents
            for item in sorted(directory.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
                try:
                    file_info = self.get_file_info(item, site_dir)
                    files.append(file_info)
                except Exception:
                    # Skip files that can't be accessed
                    continue
            
            return files
        
        except Exception as e:
            raise ValueError(f"Error listing files: {str(e)}")
    
    def upload_file(self, site_id: int, relative_path: str, file: UploadFile, extract_zip: bool = False) -> Tuple[bool, str]:
        """Upload a file to the site directory."""
        try:
            # Validate file
            if not file.filename:
                return False, "No filename provided"
            
            # Sanitize filename
            filename = self.sanitize_filename(file.filename)
            
            # Check file extension
            if not self.is_allowed_file(filename):
                return False, f"File type not allowed: {Path(filename).suffix}"
            
            # Get target directory
            target_dir = self.get_absolute_path(site_id, relative_path)
            
            # Create directory if it doesn't exist
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Target file path
            target_file = target_dir / filename
            
            # Check file size
            content = file.file.read()
            if len(content) > self.MAX_FILE_SIZE:
                return False, f"File too large. Maximum size: {self.MAX_FILE_SIZE // (1024*1024)}MB"
            
            # Handle ZIP extraction
            if extract_zip and filename.lower().endswith('.zip'):
                return self._extract_zip(content, target_dir, filename)
            
            # Write file
            with open(target_file, 'wb') as f:
                f.write(content)
            
            # Set appropriate permissions
            os.chmod(target_file, 0o644)
            
            return True, f"File '{filename}' uploaded successfully"
        
        except Exception as e:
            return False, f"Error uploading file: {str(e)}"
    
    def _extract_zip(self, zip_content: bytes, target_dir: Path, zip_filename: str) -> Tuple[bool, str]:
        """Extract ZIP file contents."""
        try:
            import io
            
            extracted_files = []
            
            with zipfile.ZipFile(io.BytesIO(zip_content), 'r') as zip_file:
                for member in zip_file.infolist():
                    # Skip directories and hidden files
                    if member.is_dir() or member.filename.startswith('.'):
                        continue
                    
                    # Sanitize filename
                    filename = self.sanitize_filename(os.path.basename(member.filename))
                    
                    # Check if file type is allowed
                    if not self.is_allowed_file(filename):
                        continue
                    
                    # Extract file
                    member_data = zip_file.read(member)
                    if len(member_data) > self.MAX_FILE_SIZE:
                        continue  # Skip files that are too large
                    
                    # Create subdirectories if needed
                    member_path = Path(member.filename)
                    if len(member_path.parts) > 1:
                        subdir = target_dir / Path(*member_path.parts[:-1])
                        subdir.mkdir(parents=True, exist_ok=True)
                        target_file = subdir / filename
                    else:
                        target_file = target_dir / filename
                    
                    # Write extracted file
                    with open(target_file, 'wb') as f:
                        f.write(member_data)
                    
                    # Set permissions
                    os.chmod(target_file, 0o644)
                    extracted_files.append(filename)
            
            if extracted_files:
                return True, f"ZIP extracted: {len(extracted_files)} files extracted from '{zip_filename}'"
            else:
                return False, "No valid files found in ZIP archive"
        
        except Exception as e:
            return False, f"Error extracting ZIP: {str(e)}"
    
    def create_file_or_directory(self, site_id: int, relative_path: str, name: str, item_type: str, content: str = "") -> Tuple[bool, str]:
        """Create a new file or directory."""
        try:
            # Sanitize name
            name = self.sanitize_filename(name)
            
            if not name:
                return False, "Invalid name"
            
            # Get parent directory
            parent_dir = self.get_absolute_path(site_id, relative_path)
            parent_dir.mkdir(parents=True, exist_ok=True)
            
            # Target path
            target_path = parent_dir / name
            
            if target_path.exists():
                return False, f"'{name}' already exists"
            
            if item_type == "directory":
                target_path.mkdir()
                os.chmod(target_path, 0o755)
                return True, f"Directory '{name}' created successfully"
            
            elif item_type == "file":
                # Check file extension
                if not self.is_allowed_file(name):
                    return False, f"File type not allowed: {Path(name).suffix}"
                
                # Create file with content
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                os.chmod(target_path, 0o644)
                return True, f"File '{name}' created successfully"
            
            else:
                return False, "Invalid type. Must be 'file' or 'directory'"
        
        except Exception as e:
            return False, f"Error creating {item_type}: {str(e)}"
    
    def get_file_content(self, site_id: int, relative_path: str) -> Tuple[str, str]:
        """Get file content for editing."""
        try:
            file_path = self.get_absolute_path(site_id, relative_path)
            
            if not file_path.exists() or not file_path.is_file():
                raise ValueError("File not found")
            
            if not self.is_file_editable(file_path.name):
                raise ValueError("File is not editable")
            
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    return content, encoding
                except UnicodeDecodeError:
                    continue
            
            raise ValueError("Could not decode file")
        
        except Exception as e:
            raise ValueError(f"Error reading file: {str(e)}")
    
    def save_file_content(self, site_id: int, relative_path: str, content: str) -> Tuple[bool, str]:
        """Save file content."""
        try:
            file_path = self.get_absolute_path(site_id, relative_path)
            
            if not self.is_file_editable(file_path.name):
                return False, "File is not editable"
            
            # Create backup if file exists
            if file_path.exists():
                backup_path = file_path.with_suffix(file_path.suffix + '.backup')
                shutil.copy2(file_path, backup_path)
            
            # Save content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Set permissions
            os.chmod(file_path, 0o644)
            
            return True, f"File '{file_path.name}' saved successfully"
        
        except Exception as e:
            return False, f"Error saving file: {str(e)}"
    
    def delete_file_or_directory(self, site_id: int, relative_path: str) -> Tuple[bool, str]:
        """Delete a file or directory."""
        try:
            target_path = self.get_absolute_path(site_id, relative_path)
            
            if not target_path.exists():
                return False, "File or directory not found"
            
            if target_path.is_dir():
                shutil.rmtree(target_path)
                return True, f"Directory '{target_path.name}' deleted successfully"
            else:
                target_path.unlink()
                return True, f"File '{target_path.name}' deleted successfully"
        
        except Exception as e:
            return False, f"Error deleting: {str(e)}"
    
    def rename_file_or_directory(self, site_id: int, relative_path: str, new_name: str) -> Tuple[bool, str, str]:
        """Rename a file or directory."""
        try:
            old_path = self.get_absolute_path(site_id, relative_path)
            
            if not old_path.exists():
                return False, "File or directory not found", ""
            
            # Sanitize new name
            new_name = self.sanitize_filename(new_name)
            
            if not new_name:
                return False, "Invalid name", ""
            
            # Check file extension for files
            if old_path.is_file() and not self.is_allowed_file(new_name):
                return False, f"File type not allowed: {Path(new_name).suffix}", ""
            
            new_path = old_path.parent / new_name
            
            if new_path.exists():
                return False, f"'{new_name}' already exists", ""
            
            old_path.rename(new_path)
            
            # Get new relative path
            site_dir = self.get_site_directory(site_id)
            new_relative_path = str(new_path.relative_to(site_dir))
            
            return True, f"Renamed to '{new_name}' successfully", new_relative_path
        
        except Exception as e:
            return False, f"Error renaming: {str(e)}", ""
    
    def move_file_or_directory(self, site_id: int, relative_path: str, destination_path: str) -> Tuple[bool, str, str]:
        """Move a file or directory to a different location."""
        try:
            source_path = self.get_absolute_path(site_id, relative_path)
            dest_dir = self.get_absolute_path(site_id, destination_path)
            
            if not source_path.exists():
                return False, "Source file or directory not found", ""
            
            if not dest_dir.exists() or not dest_dir.is_dir():
                return False, "Destination directory not found", ""
            
            dest_path = dest_dir / source_path.name
            
            if dest_path.exists():
                return False, f"'{source_path.name}' already exists in destination", ""
            
            shutil.move(str(source_path), str(dest_path))
            
            # Get new relative path
            site_dir = self.get_site_directory(site_id)
            new_relative_path = str(dest_path.relative_to(site_dir))
            
            return True, f"Moved '{source_path.name}' successfully", new_relative_path
        
        except Exception as e:
            return False, f"Error moving: {str(e)}", ""


# Global service instance
_file_service: Optional[FileService] = None


def get_file_service() -> FileService:
    """Get the global file service instance."""
    global _file_service
    if _file_service is None:
        _file_service = FileService()
    return _file_service