# Nginx Site Manager Demo Materials

This directory contains demo materials, sample configurations, and user guides to help you quickly get started with Nginx Site Manager.

## 📁 Contents

- **`sites/`** - Sample website templates and configurations
- **`screenshots/`** - UI screenshots and visual guides  
- **`videos/`** - Video tutorials and walkthroughs
- **`guides/`** - Step-by-step interactive guides

## 🚀 Quick Demo

### 1. Basic Setup Demo

Try these commands to set up a quick demo environment:

```bash
# Clone and setup
git clone https://github.com/your-username/nginx-manager.git
cd nginx-manager

# Quick installation
./install.sh --demo

# Access the demo
open http://localhost:8080
# Login: demo / DemoPassword123!
```

### 2. Docker Demo

```bash
# Quick Docker setup
docker-compose -f docker-compose.demo.yml up -d

# Access demo environment
open http://localhost:8080
```

### 3. Sample Sites

The demo includes several pre-configured sample sites:

1. **Static Portfolio Site** - HTML/CSS/JS showcase
2. **React Application** - Reverse proxy to Node.js backend  
3. **WordPress Site** - PHP application with SSL
4. **API Gateway** - Load balancer configuration
5. **Documentation Site** - Static site with custom domain

## 📖 Interactive Guides

### For Beginners
- [Your First Site](guides/first-site.md) - Create your first website in 5 minutes
- [SSL Setup Guide](guides/ssl-setup.md) - Enable HTTPS with one click
- [File Management](guides/file-management.md) - Upload and edit files

### For Developers  
- [Reverse Proxy Setup](guides/reverse-proxy.md) - Connect to backend applications
- [Load Balancing](guides/load-balancing.md) - Distribute traffic across servers
- [API Integration](guides/api-integration.md) - Programmatic site management

### For System Administrators
- [Security Hardening](guides/security-hardening.md) - Production security setup
- [Monitoring Setup](guides/monitoring.md) - Health checks and alerts
- [Backup Strategy](guides/backup-strategy.md) - Data protection best practices

## 🎥 Video Tutorials

### Getting Started Series
1. **Installation & Setup** (5 min) - `videos/01-installation.mp4`
2. **Creating Your First Site** (3 min) - `videos/02-first-site.mp4` 
3. **SSL Certificate Setup** (4 min) - `videos/03-ssl-setup.mp4`
4. **File Management** (6 min) - `videos/04-file-management.mp4`

### Advanced Features
5. **Reverse Proxy Configuration** (8 min) - `videos/05-reverse-proxy.mp4`
6. **Load Balancer Setup** (10 min) - `videos/06-load-balancer.mp4`
7. **Monitoring & Logs** (7 min) - `videos/07-monitoring.mp4`
8. **Security Best Practices** (12 min) - `videos/08-security.mp4`

*Note: Videos are available on our [YouTube channel](https://youtube.com/nginx-site-manager)*

## 🖼️ Screenshots

### Main Dashboard
![Dashboard](screenshots/dashboard.png)
*Overview of all your sites and system status*

### Site Creation  
![Create Site](screenshots/create-site.png)
*Simple wizard for creating new websites*

### SSL Management
![SSL Dashboard](screenshots/ssl-dashboard.png) 
*One-click SSL certificate management*

### File Manager
![File Manager](screenshots/file-manager.png)
*Built-in file browser and editor*

### System Monitoring
![Monitoring](screenshots/monitoring.png)
*Real-time logs and performance metrics*

## 🎯 Use Cases & Examples

### 1. Personal Portfolio
Perfect for showcasing your work with automatic SSL and easy file management.

**Features Used:**
- Static site hosting
- Custom domain 
- SSL certificates
- File upload/editing

**Setup Time:** 5 minutes

### 2. Small Business Website
Professional website with contact forms and content management.

**Features Used:**
- Static site hosting
- Custom error pages  
- Security headers
- Backup management

**Setup Time:** 15 minutes

### 3. Development Environment
Host multiple development sites and APIs with load balancing.

**Features Used:**
- Reverse proxy
- Load balancing
- Subdomain routing
- Development SSL

**Setup Time:** 20 minutes

### 4. Production Application
High-traffic application with SSL, monitoring, and security hardening.

**Features Used:**
- Load balancing
- SSL management
- Security hardening
- Monitoring & alerts
- Automated backups

**Setup Time:** 45 minutes

## 🛠️ Demo Environment Setup

### Prerequisites
- Linux server (Ubuntu/Debian/CentOS)
- Docker (for containerized demo)
- Domain name (optional, for SSL demo)

### Option 1: Full Installation Demo

```bash
# Download demo setup script
curl -L https://github.com/your-username/nginx-manager/raw/main/demo/setup-demo.sh -o setup-demo.sh
chmod +x setup-demo.sh

# Run demo setup
./setup-demo.sh
```

### Option 2: Docker Demo Environment

```bash
# Clone repository
git clone https://github.com/your-username/nginx-manager.git
cd nginx-manager

# Start demo environment
docker-compose -f demo/docker-compose.demo.yml up -d

# Load sample data
docker-compose exec nginx-manager python demo/load-sample-data.py
```

### Option 3: Kubernetes Demo

```bash
# Apply demo configuration
kubectl apply -f demo/k8s-demo/

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=nginx-manager-demo

# Port forward to access
kubectl port-forward svc/nginx-manager-demo 8080:8080
```

## 📚 Learning Path

### Beginner Path (30 minutes)
1. Watch "Installation & Setup" video
2. Follow [Your First Site](guides/first-site.md) guide
3. Try the SSL setup walkthrough
4. Explore the file management interface

### Intermediate Path (1 hour)
1. Complete beginner path
2. Set up a reverse proxy to a sample application
3. Configure custom domains and subdomains
4. Explore monitoring and logging features

### Advanced Path (2 hours)
1. Complete intermediate path
2. Set up load balancing with health checks
3. Implement security hardening measures
4. Configure automated backups
5. Set up monitoring and alerting

## 🎮 Interactive Demo

Try our online interactive demo (no installation required):

**🌐 [Live Demo](https://demo.nginx-manager.com)**
- Username: `demo`
- Password: `DemoPassword123!`

*The demo environment resets every hour and includes sample sites and data.*

## 💡 Tips for Demo Success

### Before Your Demo
- [ ] Test all features in advance
- [ ] Prepare sample sites and content
- [ ] Have backup plans for technical issues
- [ ] Practice the key workflows

### During Your Demo
- [ ] Start with the dashboard overview
- [ ] Show the simple site creation process
- [ ] Demonstrate the SSL "one-click" setup
- [ ] Highlight the file management capabilities
- [ ] Show real-time monitoring features

### Common Demo Scenarios

**Scenario 1: Small Business Owner**
- "You need a professional website with SSL"
- Show: Site creation → File upload → SSL setup → Custom domain

**Scenario 2: Developer** 
- "You have a React app that needs to be hosted"
- Show: Reverse proxy setup → SSL → Custom domain → Monitoring

**Scenario 3: Agency/Consultant**
- "You manage multiple client websites"  
- Show: Dashboard → Multiple sites → Bulk operations → Monitoring

## 🤝 Contributing to Demos

We welcome contributions to improve our demo materials:

### Adding New Demos
1. Create sample configuration in `sites/`
2. Add screenshots to `screenshots/`  
3. Write step-by-step guide in `guides/`
4. Update this README

### Improving Existing Content
1. Update screenshots with latest UI
2. Improve guide clarity and accuracy
3. Add more detailed explanations
4. Include troubleshooting tips

### Guidelines
- Keep demos simple and focused
- Use real-world scenarios
- Include both success and error handling
- Test all steps thoroughly
- Use consistent formatting and style

## 🔗 Additional Resources

- **Main Documentation**: [docs/](../docs/)
- **API Reference**: [docs/api-documentation.md](../docs/api-documentation.md)
- **Troubleshooting**: [docs/troubleshooting.md](../docs/troubleshooting.md)  
- **Security Guide**: [docs/security.md](../docs/security.md)
- **Community**: [GitHub Discussions](https://github.com/your-username/nginx-manager/discussions)

## 📞 Support

If you need help with demos or have suggestions:

- 📧 Email: demo-support@nginx-manager.com
- 💬 Discord: [Nginx Site Manager Community](https://discord.gg/nginx-manager)
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/nginx-manager/issues)

---

**Happy demoing! 🎉**

*Last updated: December 2024*