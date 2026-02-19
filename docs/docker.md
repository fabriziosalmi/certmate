# Docker Build & Deployment

This guide covers building, deploying, and running CertMate in Docker — including multi-platform support for ARM and AMD64.

---

## Quick Start

### Pull and Run

```bash
# Docker automatically selects the right architecture
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_data:/app/data \
  -v certmate_certificates:/app/certificates \
  fabriziosalmi/certmate:latest
```

### Build and Run Locally

```bash
docker build -t certmate:latest .
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  certmate:latest
```

---

## Security

The build process ensures no secrets are included in the image:

- `.dockerignore` excludes all `.env` files and sensitive data
- Environment variables are provided at **runtime**, not build time
- Only essential application files are included
- Images can be safely pushed to public registries

### Verify No Secrets in Image

```bash
docker history certmate:latest
docker inspect certmate:latest | grep -i env
docker run --rm certmate:latest find / -name "*.env" 2>/dev/null
```

---

## Runtime Configuration

### Option 1: Environment File

Create a `.env` file on your host (not in the Docker image):

```bash
SECRET_KEY=your-super-secret-key-here
ADMIN_TOKEN=your-admin-token-here
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
LOG_LEVEL=INFO
```

```bash
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  certmate:latest
```

### Option 2: Direct Environment Variables

```bash
docker run -d --name certmate \
  -e SECRET_KEY="your-secret-key" \
  -e ADMIN_TOKEN="your-admin-token" \
  -e CLOUDFLARE_API_TOKEN="your-api-token" \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  certmate:latest
```

### Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key for sessions |
| `ADMIN_TOKEN` | Yes | Authentication token for admin access |
| `LOG_LEVEL` | No | `INFO` (default), `DEBUG`, `WARNING`, `ERROR` |
| `CLOUDFLARE_API_TOKEN` | No | Cloudflare DNS provider token |
| `AWS_ACCESS_KEY_ID` | No | AWS Route53 access key |
| `AWS_SECRET_ACCESS_KEY` | No | AWS Route53 secret key |

See the [Installation Guide](./installation.md#environment-variables) for the complete list.

---

## Docker Compose

### Basic Setup

```yaml
version: '3.8'

services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - ADMIN_TOKEN=${ADMIN_TOKEN}
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

```bash
# Start with .env file in the same directory
docker-compose up -d

# Or specify a different env file
docker-compose --env-file /path/to/.env up -d
```

---

## Multi-Platform Builds

CertMate supports multi-platform Docker images for both ARM and AMD64 architectures.

### Supported Architectures

| Platform | Description | Common Use Cases |
|----------|-------------|------------------|
| `linux/amd64` | Intel/AMD 64-bit | Most cloud servers, desktops |
| `linux/arm64` | ARM 64-bit | Apple Silicon, ARM cloud instances |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ |
| `linux/arm/v6` | ARM 32-bit v6 | Raspberry Pi 1, Zero |

### Build Scripts

```bash
# Build for current platform only
./build-docker.sh

# Build for multiple platforms (ARM64 + AMD64)
./build-docker.sh -m

# Build and push to Docker Hub
./build-docker.sh -m -p -r YOUR_DOCKERHUB_USERNAME

# Dedicated multi-platform script
./build-multiplatform.sh -r USERNAME -v v1.0.0 -p

# Build for Raspberry Pi
./build-multiplatform.sh --platforms linux/arm/v7 -r USERNAME -p
```

### Manual Docker Buildx

```bash
# Create and use buildx builder
docker buildx create --name certmate-builder --use

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest .

# Build and push
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest --push .
```

### Prerequisites for Multi-Platform

```bash
# Verify buildx support
docker buildx version
docker buildx inspect --bootstrap

# Enable QEMU emulation (if needed)
docker run --privileged --rm tonistiigi/binfmt --install all
```

### Force Specific Platform

```bash
# Force AMD64 (e.g., on Apple Silicon for testing)
docker run --platform linux/amd64 --rm \
  --env-file .env -p 8000:8000 certmate:latest

# Auto-detect (recommended)
docker run --rm --env-file .env -p 8000:8000 certmate:latest
```

---

## Pushing to Docker Hub

```bash
# Login
docker login

# Tag and push
docker build -t USERNAME/certmate:latest .
docker push USERNAME/certmate:latest

# With version tag
docker build -t USERNAME/certmate:v1.0.0 .
docker push USERNAME/certmate:v1.0.0
```

---

## CI/CD Integration

### GitHub Actions

Required secrets:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

```bash
# Manual trigger with custom platforms
gh workflow run docker-multiplatform.yml \
  -f platforms="linux/amd64,linux/arm64,linux/arm/v7" \
  -f push_to_registry=true
```

---

## Production Tips

1. **Use secrets management**: Docker secrets, Kubernetes secrets, or a secrets manager
2. **Enable TLS**: Run behind a reverse proxy with TLS termination
3. **Monitor resources**: Set CPU and memory limits
4. **Backup volumes**: Regularly backup certificate and data volumes
5. **Update regularly**: Keep the image updated with security patches
6. **Use layer caching** for faster builds:
   ```bash
   docker buildx build --cache-from type=registry,ref=USERNAME/certmate:cache .
   ```

---

## Troubleshooting

### Container Won't Start

```bash
docker logs certmate
docker exec certmate env
```

### Health Check Fails

```bash
docker logs certmate
docker exec certmate curl -v http://localhost:8000/health
```

### Permission Issues

```bash
docker exec certmate ls -la /app/certificates
docker exec certmate ls -la /app/data
```

### Multi-Platform Build Issues

| Error | Solution |
|-------|----------|
| "multiple platforms not supported for docker driver" | `docker buildx create --name multiplatform --use` |
| "exec format error" | `docker run --privileged --rm tonistiigi/binfmt --install all` |
| Slow non-native builds | Normal due to emulation; use GitHub Actions for production |
| Cannot load multi-platform to local Docker | Use `--load` with single platform for local testing |

---

## Image Sizes

Typical sizes per architecture:
- **AMD64**: ~200-300 MB
- **ARM64**: ~200-300 MB
- **ARM v7**: ~180-250 MB

---

<div align="center">

[← Back to Documentation](./README.md) • [Installation →](./installation.md) • [Architecture →](./architecture.md)

</div>
