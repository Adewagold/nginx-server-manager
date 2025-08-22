"""
Log service for reading and parsing nginx log files.
Provides efficient access to nginx access and error logs with filtering and parsing.
"""

import os
import re
import gzip
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from app.config import get_config


@dataclass
class LogEntry:
    """Represents a parsed log entry."""
    timestamp: str
    raw_timestamp: Optional[datetime] = None
    ip_address: str = ""
    method: str = ""
    path: str = ""
    status_code: int = 0
    response_size: str = ""
    referer: str = ""
    user_agent: str = ""
    raw_line: str = ""
    log_level: str = ""  # For error logs
    message: str = ""    # For error logs


class LogService:
    """Service for managing nginx log files."""
    
    def __init__(self):
        self.config = get_config()
    
    def get_access_logs(self, site_name: Optional[str] = None, lines: int = 100, 
                       search: Optional[str] = None, site_domain: Optional[str] = None) -> List[LogEntry]:
        """Get nginx access logs."""
        log_files = self._get_access_log_files(site_name)
        return self._read_and_parse_logs(log_files, lines, search, log_type="access", site_domain=site_domain)
    
    def get_error_logs(self, site_name: Optional[str] = None, lines: int = 100,
                      search: Optional[str] = None) -> List[LogEntry]:
        """Get nginx error logs."""
        log_files = self._get_error_log_files(site_name)
        return self._read_and_parse_logs(log_files, lines, search, log_type="error")
    
    def _get_access_log_files(self, site_name: Optional[str] = None) -> List[str]:
        """Get list of access log files to read."""
        log_files = []
        
        if site_name:
            # Try site-specific log files first
            site_log_patterns = [
                f"/var/log/nginx/{site_name}_access.log",
                f"/var/log/nginx/{site_name}.access.log",
                f"/var/log/nginx/access_{site_name}.log"
            ]
            
            for pattern in site_log_patterns:
                if os.path.exists(pattern):
                    log_files.append(pattern)
                    # Also check for rotated logs
                    for i in range(1, 5):  # Check .1, .2, .3, .4
                        rotated = f"{pattern}.{i}"
                        if os.path.exists(rotated):
                            log_files.append(rotated)
                        rotated_gz = f"{pattern}.{i}.gz"
                        if os.path.exists(rotated_gz):
                            log_files.append(rotated_gz)
        
        # Always include main access log
        main_log = "/var/log/nginx/access.log"
        if os.path.exists(main_log):
            log_files.append(main_log)
            # Check for rotated main logs
            for i in range(1, 5):
                rotated = f"{main_log}.{i}"
                if os.path.exists(rotated):
                    log_files.append(rotated)
                rotated_gz = f"{main_log}.{i}.gz"
                if os.path.exists(rotated_gz):
                    log_files.append(rotated_gz)
        
        return log_files
    
    def _get_error_log_files(self, site_name: Optional[str] = None) -> List[str]:
        """Get list of error log files to read."""
        log_files = []
        
        if site_name:
            # Try site-specific error log files
            site_log_patterns = [
                f"/var/log/nginx/{site_name}_error.log",
                f"/var/log/nginx/{site_name}.error.log",
                f"/var/log/nginx/error_{site_name}.log"
            ]
            
            for pattern in site_log_patterns:
                if os.path.exists(pattern):
                    log_files.append(pattern)
                    # Check for rotated logs
                    for i in range(1, 5):
                        rotated = f"{pattern}.{i}"
                        if os.path.exists(rotated):
                            log_files.append(rotated)
                        rotated_gz = f"{pattern}.{i}.gz"
                        if os.path.exists(rotated_gz):
                            log_files.append(rotated_gz)
        
        # Always include main error log
        main_log = "/var/log/nginx/error.log"
        if os.path.exists(main_log):
            log_files.append(main_log)
            # Check for rotated main logs
            for i in range(1, 5):
                rotated = f"{main_log}.{i}"
                if os.path.exists(rotated):
                    log_files.append(rotated)
                rotated_gz = f"{main_log}.{i}.gz"
                if os.path.exists(rotated_gz):
                    log_files.append(rotated_gz)
        
        return log_files
    
    def _read_and_parse_logs(self, log_files: List[str], lines: int, 
                           search: Optional[str], log_type: str, site_domain: Optional[str] = None) -> List[LogEntry]:
        """Read and parse log files efficiently."""
        all_entries = []
        
        for log_file in log_files:
            try:
                entries = self._read_log_file(log_file, lines, search, log_type, site_domain)
                all_entries.extend(entries)
            except Exception as e:
                # Log the error but continue with other files
                print(f"Error reading log file {log_file}: {e}")
                continue
        
        # Sort by timestamp (newest first) and limit to requested lines
        all_entries.sort(key=lambda x: x.raw_timestamp or datetime.min, reverse=True)
        return all_entries[:lines]
    
    def _read_log_file(self, log_file: str, lines: int, search: Optional[str], 
                      log_type: str, site_domain: Optional[str] = None) -> List[LogEntry]:
        """Read a single log file efficiently using tail."""
        entries = []
        
        try:
            # Use tail to get the last N lines efficiently
            if log_file.endswith('.gz'):
                # For compressed files, use zcat + tail
                cmd = f"zcat {log_file} | tail -n {lines * 2}"  # Get more lines for filtering
            else:
                cmd = f"tail -n {lines * 2} {log_file}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return entries
            
            lines_data = result.stdout.strip().split('\n')
            
            for line in lines_data:
                if not line.strip():
                    continue
                
                # Apply search filter if provided
                if search and search.lower() not in line.lower():
                    continue
                
                # Apply domain filter for site-specific logs
                if site_domain and log_type == "access":
                    # Check if the log line contains the site domain
                    # This works for both Host header and server_name matching
                    if site_domain.lower() not in line.lower():
                        continue
                
                # Parse the log entry
                if log_type == "access":
                    entry = self._parse_access_log_line(line)
                else:
                    entry = self._parse_error_log_line(line)
                
                if entry:
                    # Double-check domain filtering after parsing for access logs
                    if site_domain and log_type == "access" and entry.path:
                        # Extract Host header from nginx logs or check if line contains domain
                        if not self._matches_site_domain(line, entry, site_domain):
                            continue
                    
                    entries.append(entry)
        
        except Exception as e:
            print(f"Error reading log file {log_file}: {e}")
        
        return entries
    
    def _matches_site_domain(self, line: str, entry: LogEntry, site_domain: str) -> bool:
        """Check if a log entry matches the specified site domain."""
        # Method 1: Check if domain is directly in the log line (most reliable)
        if site_domain.lower() in line.lower():
            return True
        
        # Method 2: Check for common nginx log format variations
        # Some nginx logs might have the host in the request line or elsewhere
        
        # Method 3: For now, use simple string matching as nginx doesn't always log Host header
        # in the standard access log format. The line-level check above should catch most cases.
        
        return False
    
    def _parse_access_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse nginx access log line."""
        # Standard nginx log format:
        # IP - - [timestamp] "METHOD path HTTP/1.1" status size "referer" "user_agent"
        
        # More flexible regex pattern for nginx access logs
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) \S+" (\d+) (\S+) "([^"]*)" "([^"]*)"'
        
        match = re.match(pattern, line)
        if match:
            ip, timestamp_str, method, path, status, size, referer, user_agent = match.groups()
            
            # Parse timestamp
            try:
                # Nginx timestamp format: 22/Aug/2025:15:30:45 +0000
                parsed_time = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                formatted_timestamp = parsed_time.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_timestamp = timestamp_str
                parsed_time = None
            
            return LogEntry(
                timestamp=formatted_timestamp,
                raw_timestamp=parsed_time,
                ip_address=ip,
                method=method,
                path=path,
                status_code=int(status) if status.isdigit() else 0,
                response_size=size,
                referer=referer if referer != "-" else "",
                user_agent=user_agent,
                raw_line=line
            )
        
        # If standard format doesn't match, return raw line
        return LogEntry(
            timestamp="",
            ip_address="",
            method="",
            path="",
            status_code=0,
            response_size="",
            referer="",
            user_agent="",
            raw_line=line
        )
    
    def _parse_error_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse nginx error log line."""
        # Error log format: timestamp [level] PID#TID: message
        pattern = r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \d+#\d+: (.*)'
        
        match = re.match(pattern, line)
        if match:
            timestamp_str, level, message = match.groups()
            
            # Parse timestamp
            try:
                parsed_time = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                formatted_timestamp = parsed_time.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_timestamp = timestamp_str
                parsed_time = None
            
            return LogEntry(
                timestamp=formatted_timestamp,
                raw_timestamp=parsed_time,
                log_level=level,
                message=message,
                raw_line=line
            )
        
        # If standard format doesn't match, return raw line
        return LogEntry(
            timestamp="",
            log_level="info",
            message=line,
            raw_line=line
        )
    
    def get_log_stats(self, site_name: Optional[str] = None) -> Dict[str, Any]:
        """Get log statistics and metadata."""
        stats = {
            "access_logs": {
                "files": [],
                "total_size": 0,
                "last_modified": None
            },
            "error_logs": {
                "files": [],
                "total_size": 0,
                "last_modified": None
            }
        }
        
        # Get access log files info
        access_files = self._get_access_log_files(site_name)
        for file_path in access_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                stats["access_logs"]["files"].append({
                    "path": file_path,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
                stats["access_logs"]["total_size"] += stat.st_size
                
                if not stats["access_logs"]["last_modified"] or stat.st_mtime > stats["access_logs"]["last_modified"]:
                    stats["access_logs"]["last_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        
        # Get error log files info
        error_files = self._get_error_log_files(site_name)
        for file_path in error_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                stats["error_logs"]["files"].append({
                    "path": file_path,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
                stats["error_logs"]["total_size"] += stat.st_size
                
                if not stats["error_logs"]["last_modified"] or stat.st_mtime > stats["error_logs"]["last_modified"]:
                    stats["error_logs"]["last_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        
        return stats


# Global instance
_log_service = None

def get_log_service() -> LogService:
    """Get the global log service instance."""
    global _log_service
    if _log_service is None:
        _log_service = LogService()
    return _log_service