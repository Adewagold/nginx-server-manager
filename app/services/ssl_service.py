"""
SSL Certificate Service for managing Let's Encrypt certificates.
Provides certificate generation, renewal, and management functionality.
"""

import os
import re
import subprocess
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass

from app.config import get_config
from app.models import get_site_model


@dataclass
class CertificateInfo:
    """Information about an SSL certificate."""
    domain: str
    path: str
    key_path: str
    expiry_date: datetime
    status: str
    issuer: str = ""
    serial_number: str = ""


class SSLService:
    """Service for managing SSL certificates with Let's Encrypt."""
    
    def __init__(self):
        self.config = get_config()
        self.site_model = get_site_model()
        self.certbot_path = self._find_certbot()
        # Use user-accessible directories
        import os
        self.home_dir = os.path.expanduser("~")
        self.letsencrypt_dir = os.path.join(self.home_dir, ".letsencrypt")
        self.webroot_path = "/var/www/html"
        self.config_dir = os.path.join(self.home_dir, ".letsencrypt")
        self.work_dir = os.path.join(self.home_dir, ".letsencrypt/work")
        self.logs_dir = os.path.join(self.home_dir, ".letsencrypt/logs")
        # Get SSL staging setting from config (default to production certificates)
        self.use_staging = self.config.ssl.staging if hasattr(self.config, 'ssl') else False
        
        # Create directories if they don't exist
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, "live"), exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, "archive"), exist_ok=True)
    
    def _find_certbot(self) -> str:
        """Find certbot executable path."""
        certbot_paths = [
            "/usr/bin/certbot",
            "/usr/local/bin/certbot",
            "/snap/bin/certbot",
            shutil.which("certbot")
        ]
        
        for path in certbot_paths:
            if path and os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        raise RuntimeError("Certbot not found. Please install certbot first.")
    
    def is_certbot_available(self) -> bool:
        """Check if certbot is available."""
        try:
            self._find_certbot()
            return True
        except RuntimeError:
            return False
    
    def get_certbot_version(self) -> Optional[str]:
        """Get certbot version string."""
        try:
            certbot_path = self._find_certbot()
            result = subprocess.run([certbot_path, "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                # Extract version from output like "certbot 2.9.0"
                version_line = result.stdout.strip()
                if version_line.startswith("certbot"):
                    return version_line.split()[1] if len(version_line.split()) > 1 else version_line
                return version_line
            return None
        except Exception:
            return None
    
    def install_certbot(self) -> Tuple[bool, str]:
        """Install certbot using system package manager."""
        try:
            # Try different installation methods
            install_commands = [
                ["apt-get", "update", "&&", "apt-get", "install", "-y", "certbot"],
                ["yum", "install", "-y", "certbot"],
                ["dnf", "install", "-y", "certbot"],
                ["snap", "install", "--classic", "certbot"]
            ]
            
            for cmd in install_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                    if result.returncode == 0:
                        return True, "Certbot installed successfully"
                except Exception:
                    continue
            
            return False, "Failed to install certbot. Please install manually."
        
        except Exception as e:
            return False, f"Error installing certbot: {str(e)}"
    
    def generate_certificate(self, domain: str, email: str, webroot_path: Optional[str] = None) -> Tuple[bool, str, Optional[CertificateInfo]]:
        """Generate a new SSL certificate using Let's Encrypt."""
        try:
            if not self.is_certbot_available():
                return False, "Certbot not available", None
            
            # Determine webroot path - try site-specific first, then default
            if webroot_path:
                webroot = webroot_path
            else:
                # Try site-specific webroot first
                site_webroot = f"/var/www/{domain.replace('.', '-')}"
                if os.path.exists(site_webroot):
                    webroot = site_webroot
                else:
                    # Use default webroot
                    webroot = self.webroot_path
            
            # Ensure webroot directory exists
            Path(webroot).mkdir(parents=True, exist_ok=True)
            
            # Create a temporary validation file to test webroot access
            test_dir = os.path.join(webroot, '.well-known', 'acme-challenge')
            Path(test_dir).mkdir(parents=True, exist_ok=True)
            test_file = os.path.join(test_dir, 'test.txt')
            with open(test_file, 'w') as f:
                f.write('test')
            os.chmod(test_file, 0o644)
            
            # Parse multiple domains (space or comma separated)
            domains = []
            if ',' in domain:
                domains = [d.strip() for d in domain.split(',') if d.strip()]
            else:
                domains = [d.strip() for d in domain.split() if d.strip()]
            
            if not domains:
                domains = [domain.strip()]  # fallback to original domain if parsing fails
            
            # Build certbot command with custom directories
            cmd = [
                self.certbot_path,
                "certonly",
                "--webroot",
                "--webroot-path", webroot,
                "--email", email,
                "--agree-tos",
                "--non-interactive",
                "--expand",
                "--config-dir", self.config_dir,
                "--work-dir", self.work_dir,
                "--logs-dir", self.logs_dir
            ]
            
            # Add each domain as a separate -d parameter
            for domain_name in domains:
                cmd.extend(["-d", domain_name])
            
            # Add staging flag if configured
            if self.use_staging:
                cmd.insert(-2, "--staging")
            
            # Run certbot
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Certificate generated successfully - use primary domain (first one)
                primary_domain = domains[0]
                cert_info = self.get_certificate_info(primary_domain)
                if cert_info:
                    # Set proper permissions for nginx to read certificates
                    self._set_certificate_permissions(primary_domain)
                    return True, "Certificate generated successfully", cert_info
                else:
                    return False, "Certificate generated but could not retrieve info", None
            else:
                error_msg = result.stderr or result.stdout
                # Check for common errors and provide helpful messages
                primary_domain = domains[0]
                if "NXDOMAIN" in error_msg or "DNS problem" in error_msg:
                    return False, f"DNS verification failed. Ensure {primary_domain} (and other domains) point to this server's IP address.", None
                elif "Unauthorized" in error_msg or "404" in error_msg:
                    return False, f"Domain validation failed. Ensure nginx is configured to serve {webroot}/.well-known/acme-challenge/ for all domains", None
                elif "rate limit" in error_msg.lower():
                    return False, "Let's Encrypt rate limit exceeded. Please wait before retrying.", None
                else:
                    return False, f"Certificate generation failed: {error_msg}", None
        
        except Exception as e:
            return False, f"Error generating certificate: {str(e)}", None
    
    def renew_certificate(self, domain: str) -> Tuple[bool, str]:
        """Renew an existing certificate."""
        try:
            if not self.is_certbot_available():
                return False, "Certbot not available"
            
            # Use primary domain for certificate name (certbot uses first domain as cert name)
            primary_domain = domain.split()[0] if ' ' in domain else domain
            
            cmd = [
                self.certbot_path,
                "renew",
                "--cert-name", primary_domain,
                "--non-interactive",
                "--config-dir", self.config_dir,
                "--work-dir", self.work_dir,
                "--logs-dir", self.logs_dir
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Copy renewed certificate to system location
                self._install_certificate_to_system(domain)
                return True, "Certificate renewed successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Certificate renewal failed: {error_msg}"
        
        except Exception as e:
            return False, f"Error renewing certificate: {str(e)}"
    
    def revoke_certificate(self, domain: str) -> Tuple[bool, str]:
        """Revoke a certificate."""
        try:
            if not self.is_certbot_available():
                return False, "Certbot not available"
            
            # Use primary domain for certificate path
            primary_domain = domain.split()[0] if ' ' in domain else domain
            cert_path = f"{self.letsencrypt_dir}/live/{primary_domain}/cert.pem"
            
            if not os.path.exists(cert_path):
                return False, f"Certificate not found for domain {domain}"
            
            cmd = [
                self.certbot_path,
                "revoke",
                "--cert-path", cert_path,
                "--non-interactive"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, "Certificate revoked successfully"
            else:
                error_msg = result.stderr or result.stdout
                return False, f"Certificate revocation failed: {error_msg}"
        
        except Exception as e:
            return False, f"Error revoking certificate: {str(e)}"
    
    def get_certificate_info(self, domain: str) -> Optional[CertificateInfo]:
        """Get information about a certificate."""
        try:
            # Use primary domain for certificate path (certbot stores by first domain)
            primary_domain = domain.split()[0] if ' ' in domain else domain
            cert_path = f"{self.config_dir}/live/{primary_domain}/fullchain.pem"
            key_path = f"{self.config_dir}/live/{primary_domain}/privkey.pem"
            
            if not os.path.exists(cert_path):
                return None
            
            # Get certificate expiry date using openssl
            cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            # Parse expiry date
            expiry_line = result.stdout.strip()
            expiry_match = re.search(r"notAfter=(.+)", expiry_line)
            if not expiry_match:
                return None
            
            # Parse the date string
            expiry_str = expiry_match.group(1)
            try:
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                # Try alternative format
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y GMT")
            
            # Determine status
            now = datetime.now()
            if expiry_date <= now:
                status = "expired"
            elif expiry_date <= now + timedelta(days=30):
                status = "expiring"
            else:
                status = "active"
            
            return CertificateInfo(
                domain=primary_domain,  # Use primary domain for consistency
                path=cert_path,
                key_path=key_path,
                expiry_date=expiry_date,
                status=status
            )
        
        except Exception as e:
            print(f"Error getting certificate info for {domain}: {e}")
            return None
    
    def list_certificates(self) -> List[CertificateInfo]:
        """List all available certificates."""
        certificates = []
        
        try:
            live_dir = Path(self.config_dir) / "live"
            if not live_dir.exists():
                return certificates
            
            for domain_dir in live_dir.iterdir():
                if domain_dir.is_dir():
                    cert_info = self.get_certificate_info(domain_dir.name)
                    if cert_info:
                        certificates.append(cert_info)
        
        except Exception as e:
            print(f"Error listing certificates: {e}")
        
        return certificates
    
    def _install_certificate_to_system(self, domain: str) -> bool:
        """Install certificate to system location if possible."""
        try:
            # Use primary domain for certificate path
            primary_domain = domain.split()[0] if ' ' in domain else domain
            source_cert = f"{self.config_dir}/live/{primary_domain}/fullchain.pem"
            source_key = f"{self.config_dir}/live/{primary_domain}/privkey.pem"
            
            # Try to copy to system location for nginx to use
            system_cert_dir = f"/etc/letsencrypt/live/{primary_domain}"
            
            if not os.path.exists(source_cert):
                return False
            
            try:
                # Try to create system directory and copy files
                import shutil
                os.makedirs(system_cert_dir, exist_ok=True)
                shutil.copy2(source_cert, f"{system_cert_dir}/fullchain.pem")
                shutil.copy2(source_key, f"{system_cert_dir}/privkey.pem")
                return True
            except PermissionError:
                # If we can't copy to system location, that's okay
                # nginx templates will need to use the user directory paths
                print(f"Could not copy certificates to system location for {domain}")
                return False
        
        except Exception as e:
            print(f"Error installing certificate to system for {domain}: {e}")
            return False
    
    def _set_certificate_permissions(self, domain: str) -> bool:
        """Set proper permissions for nginx to read certificates."""
        try:
            import stat
            # Use primary domain for certificate path
            primary_domain = domain.split()[0] if ' ' in domain else domain
            cert_dir = f"{self.config_dir}/live/{primary_domain}"
            cert_file = f"{cert_dir}/fullchain.pem"
            key_file = f"{cert_dir}/privkey.pem"
            
            if os.path.exists(cert_dir):
                # Make directory readable by nginx (www-data group)
                os.chmod(cert_dir, 0o755)
                
                if os.path.exists(cert_file):
                    os.chmod(cert_file, 0o644)
                    
                if os.path.exists(key_file):
                    os.chmod(key_file, 0o600)
                    
                return True
        except Exception as e:
            print(f"Could not set certificate permissions for {domain}: {e}")
            return False
    
    def enable_ssl_for_site(self, site_id: int, email: str) -> Tuple[bool, str]:
        """Enable SSL for a site by generating certificate and updating configuration."""
        try:
            # Get site information
            site = self.site_model.get_by_id(site_id)
            if not site:
                return False, "Site not found"
            
            domain = site['domain']
            
            # Set SSL status to pending
            self.site_model.set_ssl_status(site_id, 'pending')
            
            # Check if certificate already exists
            cert_info = self.get_certificate_info(domain)
            if cert_info and cert_info.status in ['active', 'expiring']:
                # Certificate exists and is valid
                self._update_site_ssl_info(site_id, cert_info)
                self.site_model.set_ssl_enabled(site_id, True)
                return True, "SSL enabled with existing certificate"
            
            # Generate new certificate
            success, message, cert_info = self.generate_certificate(domain, email)
            
            if success and cert_info:
                # Update site with certificate information
                self._update_site_ssl_info(site_id, cert_info)
                self.site_model.set_ssl_enabled(site_id, True)
                return True, "SSL certificate generated and enabled successfully"
            else:
                # Set SSL status to error
                self.site_model.set_ssl_status(site_id, 'error')
                return False, f"Failed to generate certificate: {message}"
        
        except Exception as e:
            self.site_model.set_ssl_status(site_id, 'error')
            return False, f"Error enabling SSL: {str(e)}"
    
    def disable_ssl_for_site(self, site_id: int) -> Tuple[bool, str]:
        """Disable SSL for a site."""
        try:
            # Update site to disable SSL
            self.site_model.set_ssl_enabled(site_id, False)
            self.site_model.set_ssl_status(site_id, 'disabled')
            
            return True, "SSL disabled successfully"
        
        except Exception as e:
            return False, f"Error disabling SSL: {str(e)}"
    
    def _update_site_ssl_info(self, site_id: int, cert_info: CertificateInfo):
        """Update site with SSL certificate information."""
        # Use the user directory paths since that's where our certificates are
        domain = cert_info.domain
        cert_path = f"{self.config_dir}/live/{domain}/fullchain.pem"
        key_path = f"{self.config_dir}/live/{domain}/privkey.pem"
        
        self.site_model.update_ssl_certificate(
            site_id,
            cert_path,
            key_path,
            cert_info.expiry_date,
            cert_info.status
        )
    
    def check_certificate_expiry(self) -> List[Dict[str, Any]]:
        """Check for expiring certificates."""
        expiring_sites = []
        
        try:
            # Get sites with SSL enabled
            ssl_sites = self.site_model.get_ssl_sites()
            
            for site in ssl_sites:
                cert_info = self.get_certificate_info(site['domain'])
                if cert_info:
                    days_until_expiry = (cert_info.expiry_date - datetime.now()).days
                    
                    if days_until_expiry <= 30:  # Expiring within 30 days
                        expiring_sites.append({
                            'site_id': site['id'],
                            'domain': site['domain'],
                            'expiry_date': cert_info.expiry_date,
                            'days_until_expiry': days_until_expiry,
                            'status': cert_info.status
                        })
        
        except Exception as e:
            print(f"Error checking certificate expiry: {e}")
        
        return expiring_sites
    
    def setup_auto_renewal(self) -> Tuple[bool, str]:
        """Setup automatic certificate renewal using systemd timer."""
        try:
            # First check if there's already a system certbot timer
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "certbot.timer"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    return True, "Auto-renewal is already configured using system certbot timer"
            except:
                pass
            
            # Try to create systemd service and timer
            try:
                # Create systemd service file
                service_content = f"""[Unit]
Description=Let's Encrypt certificate renewal
After=network.target

[Service]
Type=oneshot
ExecStart={self.certbot_path} renew --quiet --config-dir {self.config_dir} --work-dir {self.work_dir} --logs-dir {self.logs_dir} --post-hook "sudo systemctl reload nginx"
"""
                
                service_path = "/etc/systemd/system/certbot-renewal.service"
                with open(service_path, 'w') as f:
                    f.write(service_content)
                
                # Create systemd timer file
                timer_content = """[Unit]
Description=Run certbot renewal twice daily
Requires=certbot-renewal.service

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
"""
                
                timer_path = "/etc/systemd/system/certbot-renewal.timer"
                with open(timer_path, 'w') as f:
                    f.write(timer_content)
                
                # Enable and start the timer
                subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
                subprocess.run(["sudo", "systemctl", "enable", "certbot-renewal.timer"], check=True)
                subprocess.run(["sudo", "systemctl", "start", "certbot-renewal.timer"], check=True)
                
                return True, "Automatic renewal setup successfully using systemd"
                
            except (subprocess.CalledProcessError, OSError, PermissionError):
                # Fall back to crontab if systemd setup fails
                return self._setup_cron_renewal()
        
        except Exception as e:
            return False, f"Error setting up auto renewal: {str(e)}"
    
    def _setup_cron_renewal(self) -> Tuple[bool, str]:
        """Setup certificate renewal using crontab as fallback."""
        try:
            # Create renewal script in user directory
            script_dir = os.path.expanduser("~/.nginx-manager")
            os.makedirs(script_dir, exist_ok=True)
            
            script_path = os.path.join(script_dir, "renew-certs.sh")
            script_content = f"""#!/bin/bash
# Nginx Site Manager SSL Renewal Script
{self.certbot_path} renew --quiet --config-dir {self.config_dir} --work-dir {self.work_dir} --logs-dir {self.logs_dir} --post-hook "sudo systemctl reload nginx" >> {script_dir}/renewal.log 2>&1
"""
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            os.chmod(script_path, 0o755)
            
            # Add cron job
            import crontab
            from crontab import CronTab
            
            # Get current user's crontab
            cron = CronTab(user=True)
            
            # Remove existing renewal jobs
            cron.remove_all(comment='nginx-manager-ssl-renewal')
            
            # Add new renewal job (run twice daily at 2 AM and 2 PM)
            job = cron.new(command=script_path, comment='nginx-manager-ssl-renewal')
            job.hour.on(2, 14)
            job.minute.on(0)
            
            cron.write()
            
            return True, "Automatic renewal setup successfully using crontab. Certificates will be renewed twice daily at 2:00 AM and 2:00 PM."
        
        except ImportError:
            # python-crontab not available, suggest manual setup
            return False, ("Automatic renewal setup failed. The system certbot timer is recommended. "
                          "You can enable it manually with: sudo systemctl enable --now certbot.timer")
        except Exception as e:
            # Handle read-only filesystem or other cron issues
            if "read-only" in str(e).lower() or "mkstemp" in str(e):
                return False, ("Cron setup failed due to filesystem permissions. "
                              "The system certbot timer is already running and will handle renewals automatically.")
            return False, f"Error setting up cron renewal: {str(e)}"
    
    def get_renewal_status(self) -> Dict[str, Any]:
        """Get status of automatic renewal setup."""
        try:
            # First check for system certbot timer
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "certbot.timer"],
                    capture_output=True, text=True
                )
                
                if result.returncode == 0 and result.stdout.strip() == "active":
                    # System certbot timer is active
                    try:
                        result = subprocess.run(
                            ["systemctl", "list-timers", "certbot.timer", "--no-pager"],
                            capture_output=True, text=True
                        )
                        
                        next_run = None
                        if result.returncode == 0:
                            lines = result.stdout.strip().split('\n')
                            for line in lines:
                                if "certbot.timer" in line:
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        next_run = f"{parts[0]} {parts[1]}"
                                    break
                        
                        return {
                            "auto_renewal_enabled": True,
                            "renewal_method": "system-certbot",
                            "next_run": next_run,
                            "service_status": "active"
                        }
                    except:
                        return {
                            "auto_renewal_enabled": True,
                            "renewal_method": "system-certbot",
                            "next_run": "Unknown",
                            "service_status": "active"
                        }
            except:
                pass
            
            # Check for custom systemd timer
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "certbot-renewal.timer"],
                    capture_output=True, text=True
                )
                
                timer_active = result.returncode == 0 and result.stdout.strip() == "active"
                
                if timer_active:
                    # Get next run time for systemd
                    next_run = None
                    try:
                        result = subprocess.run(
                            ["systemctl", "list-timers", "certbot-renewal.timer", "--no-pager"],
                            capture_output=True, text=True
                        )
                        
                        if result.returncode == 0:
                            lines = result.stdout.strip().split('\n')
                            for line in lines:
                                if "certbot-renewal.timer" in line:
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        next_run = f"{parts[0]} {parts[1]}"
                                    break
                    except:
                        pass
                    
                    return {
                        "auto_renewal_enabled": True,
                        "renewal_method": "systemd",
                        "next_run": next_run,
                        "service_status": "active"
                    }
            except:
                pass
            
            # Check for cron-based renewal
            try:
                from crontab import CronTab
                cron = CronTab(user=True)
                renewal_jobs = [job for job in cron if job.comment == 'nginx-manager-ssl-renewal']
                
                if renewal_jobs:
                    job = renewal_jobs[0]
                    return {
                        "auto_renewal_enabled": True,
                        "renewal_method": "crontab",
                        "schedule": f"Daily at {job.hour} hours, {job.minute} minutes",
                        "service_status": "active"
                    }
            except ImportError:
                pass
            except Exception:
                pass
            
            # No automatic renewal found
            return {
                "auto_renewal_enabled": False,
                "renewal_method": "none",
                "next_run": None,
                "service_status": "inactive"
            }
        
        except Exception as e:
            return {
                "auto_renewal_enabled": False,
                "next_run": None,
                "service_status": "error",
                "error": str(e)
            }


# Global instance
_ssl_service = None

def get_ssl_service() -> SSLService:
    """Get the global SSL service instance."""
    global _ssl_service
    if _ssl_service is None:
        _ssl_service = SSLService()
    return _ssl_service