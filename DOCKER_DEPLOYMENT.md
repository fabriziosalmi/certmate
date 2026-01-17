# Docker Build and Deployment Guide

## Building a Secure Docker Image

This guide explains how to build and deploy CertMate as a Docker container while ensuring no sensitive environment variables or secrets are included in the image.

### Prerequisites

1. Docker installed on your system
2. DockerHub account (if pushing to DockerHub)
3. No `.env` file in the build context (handled by `.dockerignore`)

### Security Features

- **No secrets in image**: The `.dockerignore` file excludes all `.env` files and sensitive data
- **Runtime configuration**: Environment variables are provided at container runtime, not build time
- **Minimal attack surface**: Only essential application files are included in the image

### Building the Docker Image

#### 1. Local Build

```bash
# Build the image locally
docker build -t certmate:latest .

# Or with a specific tag
docker build -t certmate:v1.0.0 .
```

#### 2. Build for DockerHub

```bash
# Replace 'yourusername' with your DockerHub username
docker build -t yourusername/certmate:latest .
docker build -t yourusername/certmate:v1.0.0 .
```

### Pushing to DockerHub

#### 1. Login to DockerHub

```bash
docker login
```

#### 2. Push the Images

```bash
# Push latest tag
docker push yourusername/certmate:latest

# Push version tag
docker push yourusername/certmate:v1.0.0
```

### Running the Container

#### 1. Create Environment File (Host System)

Create a `.env` file on your host system (NOT in the Docker image):

```bash
# Create .env file with your settings
cat > .env << 'EOF'
SECRET_KEY=your-super-secret-key-here
ADMIN_TOKEN=your-admin-token-here
CLOUDFLARE_EMAIL=your-email@example.com
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
LOG_LEVEL=INFO
EOF
```

#### 2. Run with Environment File

```bash
# Run with environment file
docker run -d \
 --name certmate \
 --env-file .env \
 -p 8000:8000 \
 -v certmate_certificates:/app/certificates \
 -v certmate_data:/app/data \
 -v certmate_logs:/app/logs \
 yourusername/certmate:latest
```

#### 3. Run with Direct Environment Variables

```bash
# Run with individual environment variables
docker run -d \
 --name certmate \
 -e SECRET_KEY="your-super-secret-key-here" \
 -e ADMIN_TOKEN="your-admin-token-here" \
 -e CLOUDFLARE_EMAIL="your-email@example.com" \
 -e CLOUDFLARE_API_TOKEN="your-cloudflare-api-token" \
 -e LOG_LEVEL="INFO" \
 -p 8000:8000 \
 -v certmate_certificates:/app/certificates \
 -v certmate_data:/app/data \
 -v certmate_logs:/app/logs \
 yourusername/certmate:latest
```

### Docker Compose Deployment

#### 1. Create docker-compose.yml

```yaml
version: '3.8'

services:
 certmate:
 image: yourusername/certmate:latest
 container_name: certmate
 ports:
 - "8000:8000"
 environment:
 - SECRET_KEY=${SECRET_KEY}
 - ADMIN_TOKEN=${ADMIN_TOKEN}
 - CLOUDFLARE_EMAIL=${CLOUDFLARE_EMAIL}
 - CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN}
 - LOG_LEVEL=${LOG_LEVEL:-INFO}
 volumes:
 - certmate_certificates:/app/certificates
 - certmate_data:/app/data
 - certmate_logs:/app/logs
 restart: unless-stopped
 healthcheck:
 test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
 interval: 30s
 timeout: 10s
 retries: 3
 start_period: 40s

volumes:
 certmate_certificates:
 certmate_data:
 certmate_logs:
```

#### 2. Run with Docker Compose

```bash
# With .env file in the same directory
docker-compose up -d

# Or specify environment file
docker-compose --env-file /path/to/.env up -d
```

### Security Verification

#### 1. Verify No Secrets in Image

```bash
# Inspect the image layers
docker history yourusername/certmate:latest

# Check for environment variables in image
docker inspect yourusername/certmate:latest | grep -i env

# Run container and check for .env files
docker run --rm yourusername/certmate:latest find / -name "*.env" 2>/dev/null
```

#### 2. Verify Container Runtime

```bash
# Check running container environment
docker exec certmate env | grep -E "(SECRET_KEY|ADMIN_TOKEN|CLOUDFLARE)"

# Check health status
docker exec certmate curl -f http://localhost:8000/health
```

### Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SECRET_KEY` | Yes | Flask secret key for sessions | `your-super-secret-key-here` |
| `ADMIN_TOKEN` | Yes | Authentication token for admin access | `your-admin-token-here` |
| `CLOUDFLARE_EMAIL` | Yes | Cloudflare account email | `user@example.com` |
| `CLOUDFLARE_API_TOKEN` | Yes | Cloudflare API token with DNS permissions | `your-api-token` |
| `LOG_LEVEL` | No | Logging level | `INFO` (default), `DEBUG`, `WARNING`, `ERROR` |

### Production Deployment Tips

1. **Use secrets management**: In production, use Docker secrets, Kubernetes secrets, or a secrets manager
2. **Enable TLS**: Run behind a reverse proxy with TLS termination
3. **Monitor resources**: Set appropriate CPU and memory limits
4. **Backup volumes**: Regularly backup the certificate and data volumes
5. **Update regularly**: Keep the image updated with latest security patches

### Troubleshooting

#### Container Won't Start
```bash
# Check logs
docker logs certmate

# Check if environment variables are set
docker exec certmate env
```

#### Health Check Fails
```bash
# Check application logs
docker logs certmate

# Test health endpoint manually
docker exec certmate curl -v http://localhost:8000/health
```

#### Permission Issues
```bash
# Check file permissions in container
docker exec certmate ls -la /app/certificates
docker exec certmate ls -la /app/data
```

## Summary

This setup ensures:
- No secrets are baked into the Docker image
- Environment variables are provided at runtime
- Sensitive files are excluded via `.dockerignore`
- Image can be safely pushed to public registries
- Production-ready deployment configuration
