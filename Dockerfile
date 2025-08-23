# Nginx Site Manager - Production Docker Image
# Multi-stage build for optimized production container

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.0.0

# Add labels for better container management
LABEL maintainer="Nginx Site Manager Team"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="nginx-manager"
LABEL org.label-schema.description="Web-based nginx management platform"
LABEL org.label-schema.url="https://github.com/your-username/nginx-manager"
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.vcs-url="https://github.com/your-username/nginx-manager"
LABEL org.label-schema.vendor="Nginx Site Manager Team"
LABEL org.label-schema.version=$VERSION
LABEL org.label-schema.schema-version="1.0"

# Install system dependencies needed for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV APP_ENV=production
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    certbot \
    python3-certbot-nginx \
    sqlite3 \
    curl \
    supervisor \
    cron \
    logrotate \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user
RUN groupadd -r nginx-manager && \
    useradd -r -g nginx-manager -d /app -s /bin/bash nginx-manager && \
    usermod -a -G www-data nginx-manager

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create necessary directories
RUN mkdir -p /app/data \
             /app/static \
             /var/www \
             /var/log/nginx-manager \
             /var/log/supervisor \
             /run/nginx \
    && chown -R nginx-manager:www-data /app \
    && chown -R nginx-manager:www-data /var/www \
    && chown -R nginx-manager:www-data /var/log/nginx-manager \
    && chown nginx-manager:nginx-manager /home/nginx-manager

# Copy application code
COPY --chown=nginx-manager:www-data . /app

# Copy Docker-specific configuration files
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/healthcheck.sh /healthcheck.sh

# Make scripts executable
RUN chmod +x /entrypoint.sh /healthcheck.sh

# Configure nginx
RUN rm -f /etc/nginx/sites-enabled/default && \
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

# Set up SSL directory structure for the nginx-manager user
RUN mkdir -p /home/nginx-manager/.letsencrypt/{live,work,logs,renewal} && \
    chown -R nginx-manager:www-data /home/nginx-manager/.letsencrypt && \
    chmod 755 /home/nginx-manager/.letsencrypt && \
    find /home/nginx-manager/.letsencrypt -type d -exec chmod 755 {} \;

# Setup logrotate
COPY docker/logrotate.conf /etc/logrotate.d/nginx-manager

# Create default configuration if none exists
RUN if [ ! -f /app/config.yaml ]; then cp /app/config.yaml.example /app/config.yaml; fi

# Fix permissions
RUN chown -R nginx-manager:www-data /app && \
    chmod 600 /app/config.yaml && \
    chmod 755 /app/security_audit.py

# Switch to nginx-manager user for security
USER nginx-manager

# Initialize database
RUN cd /app && python -c "from app.models import init_database; init_database()" || true

# Switch back to root for service management
USER root

# Expose ports
EXPOSE 80 443 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /healthcheck.sh

# Set up volumes
VOLUME ["/app/data", "/var/www", "/home/nginx-manager/.letsencrypt"]

# Entry point
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]