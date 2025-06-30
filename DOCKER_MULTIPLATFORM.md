# 🐳 Docker Multi-Platform Guide

This guide explains how to build and use CertMate Docker images that work on both ARM and non-ARM architectures.

## 🎯 Quick Start

### For Users (Pull and Run)

The easiest way to use CertMate is to pull the pre-built multi-platform image:

```bash
# Pull and run - Docker automatically selects the right architecture
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_data:/app/data \
  USERNAME/certmate:latest
```

### For Developers (Build Multi-Platform)

#### Option 1: Use the Enhanced Build Script

```bash
# Build for current platform only (fastest)
./build-docker.sh

# Build for multiple platforms (ARM64 + AMD64)
./build-docker.sh -m

# Build and push to Docker Hub
./build-docker.sh -m -p -r YOUR_DOCKERHUB_USERNAME

# Build with custom platforms
./build-docker.sh --platforms linux/amd64,linux/arm64,linux/arm/v7 -m -p -r USERNAME
```

#### Option 2: Use the Dedicated Multi-Platform Script

```bash
# Make executable (first time only)
chmod +x build-multiplatform.sh

# Build locally for AMD64 and ARM64
./build-multiplatform.sh

# Build and push to Docker Hub
./build-multiplatform.sh -r YOUR_DOCKERHUB_USERNAME -p

# Build specific version
./build-multiplatform.sh -r USERNAME -v v1.0.0 -p

# Build for Raspberry Pi (ARM v7)
./build-multiplatform.sh --platforms linux/arm/v7 -r USERNAME -p
```

#### Option 3: Manual Docker Buildx Commands

```bash
# Create and use buildx builder
docker buildx create --name certmate-builder --use

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t USERNAME/certmate:latest .

# Build and push
docker buildx build --platform linux/amd64,linux/arm64 -t USERNAME/certmate:latest --push .
```

## 🏗️ Supported Architectures

| Platform | Description | Common Use Cases |
|----------|-------------|------------------|
| `linux/amd64` | Intel/AMD 64-bit | Most cloud servers, desktops, laptops |
| `linux/arm64` | ARM 64-bit | Apple Silicon Macs, ARM cloud instances, modern ARM servers |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+, some IoT devices |
| `linux/arm/v6` | ARM 32-bit v6 | Raspberry Pi 1, Zero |

## 🔧 Setup Instructions

### Prerequisites

1. **Docker with Buildx** (Docker Desktop includes this)
2. **Multi-platform emulation** (QEMU, included in Docker Desktop)

### Verify Buildx Support

```bash
# Check if buildx is available
docker buildx version

# List available builders
docker buildx ls

# Check supported platforms
docker buildx inspect --bootstrap
```

### Enable Multi-Platform Emulation

If you see limited platforms, enable emulation:

```bash
# Install QEMU emulators
docker run --privileged --rm tonistiigi/binfmt --install all

# Verify available platforms
docker buildx inspect --bootstrap
```

## 🚀 Usage Examples

### Running on Specific Platforms

```bash
# Force AMD64 (useful for performance testing)
docker run --platform linux/amd64 --rm \
  --env-file .env -p 8000:8000 USERNAME/certmate:latest

# Force ARM64 (useful on Apple Silicon)
docker run --platform linux/arm64 --rm \
  --env-file .env -p 8000:8000 USERNAME/certmate:latest

# Auto-detect platform (recommended)
docker run --rm --env-file .env -p 8000:8000 USERNAME/certmate:latest
```

### Docker Compose Multi-Platform

Update your `docker-compose.yml` to specify platform if needed:

```yaml
services:
  certmate:
    image: USERNAME/certmate:latest
    platform: linux/amd64  # Optional: force specific platform
    # ... rest of your config
```

### Checking Image Platforms

```bash
# View available architectures
docker manifest inspect USERNAME/certmate:latest

# Pull specific platform
docker pull --platform linux/arm64 USERNAME/certmate:latest
```

## 🔨 Building Custom Images

### Environment Variables for Builds

```bash
# Set target platforms
export DOCKER_BUILDKIT=1
export BUILDX_PLATFORMS="linux/amd64,linux/arm64"

# Build with environment
docker buildx build --platform $BUILDX_PLATFORMS -t certmate:custom .
```

### Build Arguments

```bash
# Use different requirements file
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg REQUIREMENTS_FILE=requirements.txt \
  -t certmate:full .

# Build with specific Python version
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg PYTHON_VERSION=3.11 \
  -t certmate:py311 .
```

## 🐛 Troubleshooting

### Common Issues

1. **"multiple platforms feature is currently not supported for docker driver"**
   ```bash
   # Create a new builder
   docker buildx create --name multiplatform --use
   ```

2. **"exec format error" when running**
   ```bash
   # Enable emulation
   docker run --privileged --rm tonistiigi/binfmt --install all
   ```

3. **Slow builds on non-native platforms**
   - This is normal due to emulation
   - Use GitHub Actions for production builds
   - Consider building on native hardware for each platform

4. **Cannot load multi-platform image to local Docker**
   ```bash
   # Multi-platform images must be pushed to registry
   # For local testing, build single platform:
   docker buildx build --platform linux/amd64 --load -t certmate:test .
   ```

### Performance Tips

1. **Use layer caching**:
   ```bash
   docker buildx build --cache-from type=registry,ref=USERNAME/certmate:cache .
   ```

2. **Parallel builds**: Use GitHub Actions or multiple machines for faster builds

3. **Minimal base images**: The current Dockerfile already uses `python:3.11-slim`

## 🤖 CI/CD Integration

### GitHub Actions

The repository includes `.github/workflows/docker-multiplatform.yml` for automated builds.

Required secrets:
- `DOCKERHUB_USERNAME`: Your Docker Hub username
- `DOCKERHUB_TOKEN`: Docker Hub access token

### Manual Triggers

```bash
# Trigger workflow with custom platforms
gh workflow run docker-multiplatform.yml \
  -f platforms="linux/amd64,linux/arm64,linux/arm/v7" \
  -f push_to_registry=true
```

## 📊 Image Information

### Size Comparison

Typical image sizes:
- AMD64: ~200-300 MB
- ARM64: ~200-300 MB
- ARM v7: ~180-250 MB

### Manifest Example

```json
{
  "manifests": [
    {
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "platform": {
        "architecture": "arm64",
        "os": "linux"
      }
    }
  ]
}
```

## 🔗 Useful Commands

```bash
# Clean up builders
docker buildx prune
docker buildx rm certmate-builder

# Inspect image details
docker buildx imagetools inspect USERNAME/certmate:latest

# Check platform of running container
docker inspect CONTAINER_ID | grep Architecture

# Force rebuild without cache
docker buildx build --no-cache --platform linux/amd64,linux/arm64 .
```

## 🎯 Best Practices

1. **Always test on target platforms** before releasing
2. **Use registry caching** for faster CI/CD builds
3. **Pin base image versions** for reproducible builds
4. **Monitor image sizes** across architectures
5. **Document platform-specific requirements** if any
6. **Use health checks** to verify container startup
7. **Test with different DNS providers** on each platform

## 📚 Additional Resources

- [Docker Buildx Documentation](https://docs.docker.com/buildx/)
- [Multi-platform Images](https://docs.docker.com/build/building/multi-platform/)
- [GitHub Actions Docker Build](https://github.com/docker/build-push-action)
- [Docker Hub Multi-arch](https://docs.docker.com/docker-hub/builds/advanced/)
