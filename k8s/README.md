# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying Nginx Site Manager on Kubernetes clusters.

## Quick Start

1. **Create the namespace and deploy:**
   ```bash
   kubectl apply -f namespace.yaml
   kubectl apply -f .
   ```

2. **Or use Kustomize:**
   ```bash
   kubectl apply -k .
   ```

## Prerequisites

- Kubernetes cluster (v1.19+)
- kubectl configured to access your cluster
- Storage provisioner for PersistentVolumes
- Ingress controller (optional, for external access)
- cert-manager (optional, for automatic SSL certificates)

## Configuration

### 1. Update Secrets

Edit `secret.yaml` and update the following:

```bash
# Generate secure secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Update the secret file with:
# - SECRET_KEY: Your generated secret key
# - ADMIN_PASSWORD: Strong admin password
# - ADMIN_EMAIL: Your admin email
# - SSL_EMAIL: Email for SSL certificate registration
```

### 2. Configure Storage

Update `pvc.yaml` to match your storage requirements:

- **Data volume**: Database and application data (default: 5Gi)
- **Web volume**: Website files and content (default: 10Gi)  
- **SSL volume**: SSL certificates (default: 1Gi)
- **Sites volume**: Nginx site configurations (default: 1Gi)

Specify storage class if needed:
```yaml
spec:
  storageClassName: "fast-ssd"  # Your storage class
```

### 3. Configure Ingress

Update `ingress.yaml` with your domain:

```yaml
spec:
  tls:
  - hosts:
    - your-domain.com
    secretName: nginx-manager-tls
  rules:
  - host: your-domain.com
```

### 4. Resource Limits

Adjust resource requests and limits in `deployment.yaml`:

```yaml
resources:
  requests:
    cpu: 200m      # Increase for higher traffic
    memory: 512Mi  # Increase for more sites
  limits:
    cpu: 1000m
    memory: 1Gi
```

## Deployment Options

### Option 1: Direct Apply

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Apply all manifests
kubectl apply -f rbac.yaml
kubectl apply -f configmap.yaml
kubectl apply -f secret.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
```

### Option 2: Kustomize

```bash
# Deploy with kustomize
kubectl apply -k .

# Or build first and then apply
kubectl kustomize . | kubectl apply -f -
```

### Option 3: Helm (Coming Soon)

```bash
helm install nginx-manager ./helm-chart
```

## Accessing the Application

### Via Ingress (Recommended)

If you configured ingress with your domain:
```
https://your-domain.com
```

### Via NodePort

```bash
# Get NodePort service ports
kubectl get svc nginx-manager-nodeport -n nginx-manager

# Access via any node IP
http://NODE_IP:30800  # Management interface
http://NODE_IP:30080  # HTTP sites
https://NODE_IP:30443 # HTTPS sites
```

### Via Port Forward

```bash
# Forward management interface
kubectl port-forward -n nginx-manager svc/nginx-manager 8080:8080

# Access at http://localhost:8080
```

## Monitoring

### Health Checks

The deployment includes comprehensive health checks:

- **Startup Probe**: Allows slow application startup
- **Readiness Probe**: Ensures pod is ready to receive traffic
- **Liveness Probe**: Restarts pod if application becomes unhealthy

### Logs

```bash
# View application logs
kubectl logs -n nginx-manager deployment/nginx-manager -f

# View nginx logs
kubectl exec -n nginx-manager deployment/nginx-manager -- tail -f /var/log/nginx/access.log

# View all pod logs
kubectl logs -n nginx-manager -l app.kubernetes.io/name=nginx-manager --all-containers=true -f
```

### Metrics

If metrics are enabled, they're available at:
```
http://pod-ip:8080/metrics
```

## Scaling

### Vertical Scaling (Recommended)

Increase resources for the single pod:

```bash
kubectl patch deployment nginx-manager -n nginx-manager -p '
{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "nginx-manager",
          "resources": {
            "requests": {"cpu": "500m", "memory": "1Gi"},
            "limits": {"cpu": "2000m", "memory": "2Gi"}
          }
        }]
      }
    }
  }
}'
```

### Horizontal Scaling (Future)

Currently limited to 1 replica due to SQLite database. Future PostgreSQL support will enable multiple replicas.

## Backup and Recovery

### Manual Backup

```bash
# Create backup of persistent volumes
kubectl exec -n nginx-manager deployment/nginx-manager -- tar -czf /tmp/backup.tar.gz /app/data /var/www /home/nginx-manager/.letsencrypt

# Copy backup from pod
kubectl cp nginx-manager/nginx-manager-pod:/tmp/backup.tar.gz ./nginx-manager-backup-$(date +%Y%m%d).tar.gz
```

### Automated Backup (Velero)

```bash
# Install Velero for cluster backups
velero install --provider aws --bucket velero-backups

# Create backup
velero backup create nginx-manager-backup --include-namespaces nginx-manager
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n nginx-manager

# Check pod events
kubectl describe pod -n nginx-manager <pod-name>

# Check logs
kubectl logs -n nginx-manager <pod-name>
```

### Storage Issues

```bash
# Check PVC status
kubectl get pvc -n nginx-manager

# Check PV details
kubectl describe pv <pv-name>
```

### Network Issues

```bash
# Check services
kubectl get svc -n nginx-manager

# Check ingress
kubectl get ingress -n nginx-manager
kubectl describe ingress nginx-manager -n nginx-manager

# Test internal connectivity
kubectl exec -n nginx-manager deployment/nginx-manager -- curl http://localhost:8080/api/health
```

### SSL Issues

```bash
# Check cert-manager (if using)
kubectl get certificaterequests -n nginx-manager
kubectl get certificates -n nginx-manager

# Check TLS secret
kubectl get secret nginx-manager-tls -n nginx-manager -o yaml
```

## Security Considerations

1. **Update secrets**: Change default passwords and keys
2. **Network policies**: Implement network policies for isolation
3. **RBAC**: Review and restrict service account permissions
4. **Pod security**: Consider pod security policies or standards
5. **Image scanning**: Scan container images for vulnerabilities
6. **Resource limits**: Set appropriate resource limits
7. **Ingress security**: Configure security headers and rate limiting

## Cleanup

```bash
# Delete all resources
kubectl delete -k .

# Or delete namespace (removes everything)
kubectl delete namespace nginx-manager
```

## Advanced Configuration

### Custom Storage Class

```yaml
# custom-storage.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nginx-manager-storage
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3
  fsType: ext4
```

### Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nginx-manager-netpol
  namespace: nginx-manager
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: nginx-manager
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 8080
```

## Support

For issues specific to Kubernetes deployment:

1. Check the troubleshooting section above
2. Review Kubernetes cluster logs
3. Ensure all prerequisites are met
4. Check resource quotas and limits

For application issues, see the main [troubleshooting guide](../docs/troubleshooting.md).