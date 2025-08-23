#!/usr/bin/env python3
"""
Packaging and Distribution Script for Nginx Site Manager
Creates distribution packages, Docker images, and deployment artifacts.
"""

import os
import sys
import subprocess
import shutil
import tarfile
import zipfile
import json
from datetime import datetime
from pathlib import Path
import argparse

# Package metadata
PACKAGE_NAME = "nginx-manager"
PACKAGE_VERSION = "1.0.0"
PACKAGE_DESCRIPTION = "Web-based nginx management platform"
PACKAGE_AUTHOR = "Nginx Site Manager Team"
PACKAGE_EMAIL = "admin@nginx-manager.local"
PACKAGE_URL = "https://github.com/your-username/nginx-manager"

class PackageBuilder:
    """Builds various package formats for Nginx Site Manager."""
    
    def __init__(self, version=None, build_dir="build"):
        self.version = version or PACKAGE_VERSION
        self.build_dir = Path(build_dir)
        self.project_root = Path(__file__).parent
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create build directory
        self.build_dir.mkdir(exist_ok=True)
        
        # Package info
        self.package_info = {
            "name": PACKAGE_NAME,
            "version": self.version,
            "description": PACKAGE_DESCRIPTION,
            "author": PACKAGE_AUTHOR,
            "author_email": PACKAGE_EMAIL,
            "url": PACKAGE_URL,
            "build_date": datetime.utcnow().isoformat(),
            "build_timestamp": self.timestamp
        }
    
    def log(self, message, level="INFO"):
        """Log a message with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    def run_command(self, command, cwd=None, check=True):
        """Run a shell command and return the result."""
        self.log(f"Running: {command}")
        result = subprocess.run(
            command, 
            shell=True, 
            cwd=cwd or self.project_root,
            capture_output=True, 
            text=True
        )
        
        if check and result.returncode != 0:
            self.log(f"Command failed: {command}", "ERROR")
            self.log(f"Error output: {result.stderr}", "ERROR")
            raise subprocess.CalledProcessError(result.returncode, command)
        
        return result
    
    def create_source_package(self):
        """Create source distribution package."""
        self.log("Creating source package...")
        
        package_name = f"{PACKAGE_NAME}-{self.version}-src"
        package_dir = self.build_dir / package_name
        
        # Create package directory
        package_dir.mkdir(exist_ok=True)
        
        # Files to include in source package
        include_files = [
            "app/",
            "static/",
            "docker/",
            "k8s/",
            "docs/",
            "requirements.txt",
            "config.yaml.example",
            "install.sh",
            "uninstall.sh",
            "security_audit.py",
            "Dockerfile",
            "docker-compose.yml",
            ".env.example",
            "README.md",
            "TECHNICAL_SPECIFICATION.md",
            "CLAUDE.md"
        ]
        
        # Copy files
        for item in include_files:
            src = self.project_root / item
            dst = package_dir / item
            
            if src.exists():
                if src.is_dir():
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
        
        # Create package metadata
        metadata = {
            **self.package_info,
            "package_type": "source",
            "contents": include_files
        }
        
        with open(package_dir / "package.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Create installation script
        install_script = package_dir / "install.sh"
        install_script.chmod(0o755)
        
        # Create tar.gz archive
        archive_path = self.build_dir / f"{package_name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(package_dir, arcname=package_name)
        
        # Create zip archive
        zip_path = self.build_dir / f"{package_name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(package_dir):
                for file in files:
                    file_path = Path(root) / file
                    arc_path = Path(package_name) / file_path.relative_to(package_dir)
                    zipf.write(file_path, arc_path)
        
        self.log(f"Source package created: {archive_path}")
        self.log(f"Source package created: {zip_path}")
        
        return {
            "tar_gz": archive_path,
            "zip": zip_path,
            "metadata": metadata
        }
    
    def create_binary_package(self):
        """Create binary distribution package (Python wheel)."""
        self.log("Creating binary package...")
        
        # Create setup.py
        setup_py = self.create_setup_py()
        
        # Build wheel
        result = self.run_command("python setup.py bdist_wheel")
        
        # Move wheel to build directory
        dist_dir = self.project_root / "dist"
        if dist_dir.exists():
            for wheel_file in dist_dir.glob("*.whl"):
                shutil.move(wheel_file, self.build_dir)
                self.log(f"Binary package created: {self.build_dir / wheel_file.name}")
        
        # Cleanup
        for cleanup_dir in ["build", "dist", f"{PACKAGE_NAME}.egg-info"]:
            cleanup_path = self.project_root / cleanup_dir
            if cleanup_path.exists():
                shutil.rmtree(cleanup_path)
    
    def create_setup_py(self):
        """Create setup.py for Python packaging."""
        setup_content = f'''#!/usr/bin/env python3
"""
Setup script for {PACKAGE_NAME}
"""

from setuptools import setup, find_packages
import os

# Read requirements
with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Read README
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="{PACKAGE_NAME}",
    version="{self.version}",
    description="{PACKAGE_DESCRIPTION}",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="{PACKAGE_AUTHOR}",
    author_email="{PACKAGE_EMAIL}",
    url="{PACKAGE_URL}",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={{
        "console_scripts": [
            "nginx-manager=app.main:main",
        ],
    }},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    keywords="nginx web server management ssl certificates",
    project_urls={{
        "Bug Reports": "{PACKAGE_URL}/issues",
        "Source": "{PACKAGE_URL}",
        "Documentation": "{PACKAGE_URL}/blob/main/docs/",
    }},
)
'''
        
        setup_py_path = self.project_root / "setup.py"
        with open(setup_py_path, "w") as f:
            f.write(setup_content)
        
        return setup_py_path
    
    def create_docker_package(self):
        """Build Docker image and create Docker package."""
        self.log("Creating Docker package...")
        
        # Build Docker image
        image_name = f"{PACKAGE_NAME}:{self.version}"
        build_cmd = f"docker build -t {image_name} ."
        
        try:
            self.run_command(build_cmd)
            
            # Export Docker image
            export_path = self.build_dir / f"{PACKAGE_NAME}-{self.version}-docker.tar"
            export_cmd = f"docker save -o {export_path} {image_name}"
            self.run_command(export_cmd)
            
            # Compress the image
            compressed_path = self.build_dir / f"{PACKAGE_NAME}-{self.version}-docker.tar.gz"
            with open(export_path, 'rb') as f_in:
                with tarfile.open(compressed_path, 'w:gz') as f_out:
                    tarinfo = tarfile.TarInfo(name=f"{PACKAGE_NAME}-{self.version}-docker.tar")
                    tarinfo.size = export_path.stat().st_size
                    f_out.addfile(tarinfo, f_in)
            
            # Remove uncompressed tar file
            export_path.unlink()
            
            self.log(f"Docker package created: {compressed_path}")
            
            return {
                "image": image_name,
                "package": compressed_path
            }
            
        except subprocess.CalledProcessError:
            self.log("Docker build failed, skipping Docker package", "WARNING")
            return None
    
    def create_k8s_package(self):
        """Create Kubernetes deployment package."""
        self.log("Creating Kubernetes package...")
        
        package_name = f"{PACKAGE_NAME}-{self.version}-k8s"
        k8s_dir = self.build_dir / package_name
        
        # Copy Kubernetes manifests
        shutil.copytree(self.project_root / "k8s", k8s_dir)
        
        # Update image version in manifests
        for yaml_file in k8s_dir.glob("*.yaml"):
            content = yaml_file.read_text()
            content = content.replace("nginx-manager:1.0.0", f"nginx-manager:{self.version}")
            yaml_file.write_text(content)
        
        # Create deployment script
        deploy_script = k8s_dir / "deploy.sh"
        deploy_content = f'''#!/bin/bash
# Kubernetes deployment script for {PACKAGE_NAME} {self.version}

set -e

echo "Deploying {PACKAGE_NAME} {self.version} to Kubernetes..."

# Apply manifests
kubectl apply -f namespace.yaml
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml

echo "Please update secret.yaml with your credentials before continuing."
read -p "Press Enter to continue after updating secrets..."

kubectl apply -f secret.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

read -p "Do you want to create ingress? (y/n): " create_ingress
if [[ $create_ingress =~ ^[Yy]$ ]]; then
    kubectl apply -f ingress.yaml
fi

echo "Deployment completed!"
echo "Check status: kubectl get pods -n nginx-manager"
'''
        
        deploy_script.write_text(deploy_content)
        deploy_script.chmod(0o755)
        
        # Create archive
        archive_path = self.build_dir / f"{package_name}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(k8s_dir, arcname=package_name)
        
        self.log(f"Kubernetes package created: {archive_path}")
        
        return {
            "directory": k8s_dir,
            "archive": archive_path
        }
    
    def run_security_audit(self):
        """Run security audit and include results in package."""
        self.log("Running security audit...")
        
        try:
            result = self.run_command("python security_audit.py", check=False)
            
            # Save audit results
            audit_file = self.build_dir / f"security-audit-{self.timestamp}.json"
            audit_report = {
                "audit_date": datetime.utcnow().isoformat(),
                "version": self.version,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            with open(audit_file, "w") as f:
                json.dump(audit_report, f, indent=2)
            
            self.log(f"Security audit completed: {audit_file}")
            
            return audit_report
            
        except Exception as e:
            self.log(f"Security audit failed: {e}", "WARNING")
            return None
    
    def create_release_notes(self):
        """Create release notes file."""
        release_notes = f"""# {PACKAGE_NAME} {self.version} Release Notes

## Release Information
- **Version**: {self.version}
- **Build Date**: {self.package_info['build_date']}
- **Build ID**: {self.timestamp}

## Package Contents

### Source Package
- Complete source code
- Installation scripts
- Documentation
- Configuration examples

### Docker Package
- Pre-built Docker image
- Docker Compose configuration
- Environment templates

### Kubernetes Package
- Complete Kubernetes manifests
- Deployment scripts
- Configuration examples

## Installation Methods

### 1. Traditional Installation
```bash
# Extract source package
tar -xzf {PACKAGE_NAME}-{self.version}-src.tar.gz
cd {PACKAGE_NAME}-{self.version}-src

# Run installer
chmod +x install.sh
./install.sh
```

### 2. Docker Installation
```bash
# Load Docker image
docker load -i {PACKAGE_NAME}-{self.version}-docker.tar.gz

# Run with Docker Compose
docker-compose up -d
```

### 3. Kubernetes Installation
```bash
# Extract Kubernetes package
tar -xzf {PACKAGE_NAME}-{self.version}-k8s.tar.gz
cd {PACKAGE_NAME}-{self.version}-k8s

# Deploy to cluster
./deploy.sh
```

## Security Notes

- Change all default passwords and secret keys
- Review security configuration before production use
- Enable SSL/TLS for all public deployments
- Regularly update and patch the system

## Support

- Documentation: {PACKAGE_URL}/docs
- Issues: {PACKAGE_URL}/issues
- Security: See docs/security.md

## Checksums

Generated during package creation - see checksums.txt file.
"""
        
        notes_file = self.build_dir / f"RELEASE_NOTES_{self.version}.md"
        notes_file.write_text(release_notes)
        
        return notes_file
    
    def create_checksums(self):
        """Create checksums for all package files."""
        import hashlib
        
        checksums = {}
        
        for file_path in self.build_dir.glob("*"):
            if file_path.is_file() and file_path.suffix in ['.tar.gz', '.zip', '.whl']:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                checksums[file_path.name] = {
                    "md5": hashlib.md5(content).hexdigest(),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content)
                }
        
        # Write checksums file
        checksums_file = self.build_dir / "checksums.txt"
        with open(checksums_file, "w") as f:
            f.write(f"# {PACKAGE_NAME} {self.version} Checksums\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n\n")
            
            for filename, hashes in checksums.items():
                f.write(f"## {filename}\n")
                f.write(f"Size: {hashes['size']} bytes\n")
                f.write(f"MD5: {hashes['md5']}\n")
                f.write(f"SHA256: {hashes['sha256']}\n\n")
        
        return checksums_file
    
    def build_all(self, include_docker=True, include_k8s=True, include_binary=False):
        """Build all package types."""
        self.log(f"Building all packages for {PACKAGE_NAME} {self.version}")
        self.log("=" * 60)
        
        results = {}
        
        # Source package (always create)
        results['source'] = self.create_source_package()
        
        # Binary package (optional)
        if include_binary:
            try:
                results['binary'] = self.create_binary_package()
            except Exception as e:
                self.log(f"Binary package creation failed: {e}", "WARNING")
        
        # Docker package
        if include_docker:
            results['docker'] = self.create_docker_package()
        
        # Kubernetes package
        if include_k8s:
            results['kubernetes'] = self.create_k8s_package()
        
        # Security audit
        results['security_audit'] = self.run_security_audit()
        
        # Release documentation
        results['release_notes'] = self.create_release_notes()
        results['checksums'] = self.create_checksums()
        
        self.log("=" * 60)
        self.log("Package build completed!")
        self.log(f"Build directory: {self.build_dir.absolute()}")
        
        # List created files
        package_files = list(self.build_dir.glob("*"))
        self.log(f"Created {len(package_files)} files:")
        for file_path in sorted(package_files):
            if file_path.is_file():
                size = file_path.stat().st_size
                self.log(f"  {file_path.name} ({size:,} bytes)")
        
        return results


def main():
    """Main function for package building."""
    parser = argparse.ArgumentParser(description="Build Nginx Site Manager packages")
    parser.add_argument("--version", default=PACKAGE_VERSION, help="Package version")
    parser.add_argument("--build-dir", default="build", help="Build directory")
    parser.add_argument("--no-docker", action="store_true", help="Skip Docker package")
    parser.add_argument("--no-k8s", action="store_true", help="Skip Kubernetes package")
    parser.add_argument("--binary", action="store_true", help="Create binary package")
    parser.add_argument("--clean", action="store_true", help="Clean build directory first")
    
    args = parser.parse_args()
    
    # Clean build directory if requested
    if args.clean:
        build_path = Path(args.build_dir)
        if build_path.exists():
            shutil.rmtree(build_path)
            print(f"Cleaned build directory: {build_path}")
    
    # Create package builder
    builder = PackageBuilder(version=args.version, build_dir=args.build_dir)
    
    # Build packages
    try:
        builder.build_all(
            include_docker=not args.no_docker,
            include_k8s=not args.no_k8s,
            include_binary=args.binary
        )
        print("✅ Package building completed successfully!")
        
    except Exception as e:
        print(f"❌ Package building failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()