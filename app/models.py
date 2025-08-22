"""
Database models for the Nginx Site Manager.
Uses SQLite with SQLAlchemy ORM for data persistence.
"""

import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
from contextlib import contextmanager

from app.config import get_config


class DatabaseManager:
    """SQLite database manager with connection handling."""
    
    def __init__(self):
        self.config = get_config()
        self.db_path = self._get_db_path()
        self._init_database()
    
    def _get_db_path(self) -> str:
        """Get the database file path."""
        db_url = self.config.get_database_url()
        if db_url.startswith("sqlite:///"):
            return db_url[10:]  # Remove "sqlite:///"
        raise ValueError(f"Unsupported database URL: {db_url}")
    
    def _init_database(self):
        """Initialize the database with required tables."""
        # Ensure the data directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with self.get_connection() as conn:
            self._create_tables(conn)
    
    def _create_tables(self, conn: sqlite3.Connection):
        """Create database tables if they don't exist."""
        cursor = conn.cursor()
        
        # Sites table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                type TEXT NOT NULL CHECK (type IN ('static', 'proxy', 'load_balancer')),
                config_path TEXT,
                enabled BOOLEAN DEFAULT 0,
                ssl_enabled BOOLEAN DEFAULT 0,
                ssl_certificate_path TEXT,
                ssl_certificate_key_path TEXT,
                ssl_expiry_date TIMESTAMP,
                ssl_status TEXT DEFAULT 'disabled' CHECK (ssl_status IN ('disabled', 'pending', 'active', 'expired', 'error')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Site configurations table (JSON storage)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS site_configs (
                site_id INTEGER PRIMARY KEY,
                config_data TEXT NOT NULL,
                FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE
            )
        """)
        
        # Add SSL columns to existing sites table if they don't exist
        cursor.execute("PRAGMA table_info(sites)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'ssl_certificate_path' not in columns:
            cursor.execute("ALTER TABLE sites ADD COLUMN ssl_certificate_path TEXT")
        if 'ssl_certificate_key_path' not in columns:
            cursor.execute("ALTER TABLE sites ADD COLUMN ssl_certificate_key_path TEXT")
        if 'ssl_expiry_date' not in columns:
            cursor.execute("ALTER TABLE sites ADD COLUMN ssl_expiry_date TIMESTAMP")
        if 'ssl_status' not in columns:
            cursor.execute("ALTER TABLE sites ADD COLUMN ssl_status TEXT DEFAULT 'disabled'")
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sites_name ON sites (name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sites_domain ON sites (domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sites_enabled ON sites (enabled)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sites_ssl_status ON sites (ssl_status)")
        
        conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with automatic closing."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
        try:
            yield conn
        finally:
            conn.close()


class Site:
    """Model for nginx sites."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def create(self, name: str, domain: str, site_type: str, config_data: Dict[str, Any]) -> int:
        """Create a new site."""
        if site_type not in ['static', 'proxy', 'load_balancer']:
            raise ValueError(f"Invalid site type: {site_type}")
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Insert site record
            cursor.execute("""
                INSERT INTO sites (name, domain, type, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, (name, domain, site_type, datetime.now(), datetime.now()))
            
            site_id = cursor.lastrowid
            
            # Insert configuration data
            cursor.execute("""
                INSERT INTO site_configs (site_id, config_data)
                VALUES (?, ?)
            """, (site_id, json.dumps(config_data)))
            
            conn.commit()
            return site_id
    
    def get_by_id(self, site_id: int) -> Optional[Dict[str, Any]]:
        """Get a site by ID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, sc.config_data
                FROM sites s
                LEFT JOIN site_configs sc ON s.id = sc.site_id
                WHERE s.id = ?
            """, (site_id,))
            
            row = cursor.fetchone()
            if row:
                site_data = dict(row)
                if site_data['config_data']:
                    site_data['config'] = json.loads(site_data['config_data'])
                    del site_data['config_data']
                return site_data
            return None
    
    def get_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a site by name."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, sc.config_data
                FROM sites s
                LEFT JOIN site_configs sc ON s.id = sc.site_id
                WHERE s.name = ?
            """, (name,))
            
            row = cursor.fetchone()
            if row:
                site_data = dict(row)
                if site_data['config_data']:
                    site_data['config'] = json.loads(site_data['config_data'])
                    del site_data['config_data']
                return site_data
            return None
    
    def list_all(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List all sites."""
        query = """
            SELECT s.*, sc.config_data
            FROM sites s
            LEFT JOIN site_configs sc ON s.id = sc.site_id
        """
        params = []
        
        if enabled_only:
            query += " WHERE s.enabled = ?"
            params.append(1)
        
        query += " ORDER BY s.created_at DESC"
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            sites = []
            for row in cursor.fetchall():
                site_data = dict(row)
                if site_data['config_data']:
                    site_data['config'] = json.loads(site_data['config_data'])
                    del site_data['config_data']
                sites.append(site_data)
            
            return sites
    
    def update(self, site_id: int, **updates) -> bool:
        """Update a site."""
        if not updates:
            return False
        
        # Separate config data from other fields
        config_data = updates.pop('config', None)
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Update site fields
            if updates:
                set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
                values = list(updates.values())
                values.append(datetime.now())  # updated_at
                values.append(site_id)
                
                cursor.execute(f"""
                    UPDATE sites 
                    SET {set_clause}, updated_at = ?
                    WHERE id = ?
                """, values)
            
            # Update configuration data
            if config_data is not None:
                cursor.execute("""
                    UPDATE site_configs 
                    SET config_data = ?
                    WHERE site_id = ?
                """, (json.dumps(config_data), site_id))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def delete(self, site_id: int) -> bool:
        """Delete a site."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Delete site (will cascade to site_configs due to foreign key)
            cursor.execute("DELETE FROM sites WHERE id = ?", (site_id,))
            
            conn.commit()
            return cursor.rowcount > 0
    
    def enable(self, site_id: int) -> bool:
        """Enable a site."""
        return self.update(site_id, enabled=True)
    
    def disable(self, site_id: int) -> bool:
        """Disable a site."""
        return self.update(site_id, enabled=False)
    
    def set_ssl_enabled(self, site_id: int, ssl_enabled: bool) -> bool:
        """Set SSL status for a site."""
        return self.update(site_id, ssl_enabled=ssl_enabled)
    
    def update_ssl_certificate(self, site_id: int, cert_path: str, key_path: str, 
                             expiry_date: datetime, status: str = 'active') -> bool:
        """Update SSL certificate information for a site."""
        return self.update(site_id, 
                         ssl_certificate_path=cert_path,
                         ssl_certificate_key_path=key_path,
                         ssl_expiry_date=expiry_date,
                         ssl_status=status)
    
    def set_ssl_status(self, site_id: int, status: str) -> bool:
        """Update SSL status for a site."""
        valid_statuses = ['disabled', 'pending', 'active', 'expired', 'error']
        if status not in valid_statuses:
            raise ValueError(f"Invalid SSL status: {status}. Must be one of {valid_statuses}")
        return self.update(site_id, ssl_status=status)
    
    def get_ssl_sites(self) -> List[Dict[str, Any]]:
        """Get all sites with SSL enabled."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, sc.config_data
                FROM sites s
                LEFT JOIN site_configs sc ON s.id = sc.site_id
                WHERE s.ssl_enabled = 1
                ORDER BY s.ssl_expiry_date ASC
            """)
            
            sites = []
            for row in cursor.fetchall():
                site_data = dict(row)
                if site_data['config_data']:
                    site_data['config'] = json.loads(site_data['config_data'])
                    del site_data['config_data']
                sites.append(site_data)
            
            return sites
    
    def get_expiring_certificates(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get sites with certificates expiring within specified days."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, sc.config_data
                FROM sites s
                LEFT JOIN site_configs sc ON s.id = sc.site_id
                WHERE s.ssl_enabled = 1 
                AND s.ssl_expiry_date IS NOT NULL
                AND datetime(s.ssl_expiry_date) <= datetime('now', '+{} days')
                ORDER BY s.ssl_expiry_date ASC
            """.format(days))
            
            sites = []
            for row in cursor.fetchall():
                site_data = dict(row)
                if site_data['config_data']:
                    site_data['config'] = json.loads(site_data['config_data'])
                    del site_data['config_data']
                sites.append(site_data)
            
            return sites
    
    def set_config_path(self, site_id: int, config_path: str) -> bool:
        """Set the nginx config file path for a site."""
        return self.update(site_id, config_path=config_path)
    
    def exists(self, name: str) -> bool:
        """Check if a site with the given name exists."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM sites WHERE name = ?", (name,))
            return cursor.fetchone() is not None
    
    def get_enabled_sites(self) -> List[Dict[str, Any]]:
        """Get all enabled sites."""
        return self.list_all(enabled_only=True)
    
    def search(self, query: str) -> List[Dict[str, Any]]:
        """Search sites by name or domain."""
        search_pattern = f"%{query}%"
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.*, sc.config_data
                FROM sites s
                LEFT JOIN site_configs sc ON s.id = sc.site_id
                WHERE s.name LIKE ? OR s.domain LIKE ?
                ORDER BY s.name
            """, (search_pattern, search_pattern))
            
            sites = []
            for row in cursor.fetchall():
                site_data = dict(row)
                if site_data['config_data']:
                    site_data['config'] = json.loads(site_data['config_data'])
                    del site_data['config_data']
                sites.append(site_data)
            
            return sites


# Global database instance
_db_manager: Optional[DatabaseManager] = None
_site_model: Optional[Site] = None


def get_db() -> DatabaseManager:
    """Get the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def get_site_model() -> Site:
    """Get the global site model instance."""
    global _site_model
    if _site_model is None:
        _site_model = Site(get_db())
    return _site_model


def init_database():
    """Initialize the database (called at startup)."""
    get_db()  # This will trigger database initialization