#!/bin/bash

# CertMate Multi-Platform Docker Build Script
# This script builds CertMate for multiple architectures (ARM64 + AMD64)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 CertMate Multi-Platform Build${NC}"
echo -e "${BLUE}===============================${NC}"

# Check if Docker Buildx is available
if ! docker buildx version >/dev/null 2>&1; then
    echo -e "${RED}❌ Error: Docker Buildx is not available!${NC}"
    echo "Please install Docker Buildx or use Docker Desktop which includes it."
    echo ""
    echo "Installation options:"
    echo "1. Docker Desktop (includes Buildx)"
    echo "2. Docker CLI with Buildx plugin"
    echo "3. Standalone Buildx installation"
    exit 1
fi

echo -e "${GREEN}✅ Docker Buildx is available${NC}"

# Default values
REGISTRY=""
VERSION="latest"
PUSH=false
PLATFORMS="linux/amd64,linux/arm64"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -p|--push)
            PUSH=true
            shift
            ;;
        --platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -r, --registry USER     DockerHub username or registry URL"
            echo "  -v, --version VERSION   Tag version (default: latest)"
            echo "  -p, --push              Push to registry after building"
            echo "  --platforms PLATFORMS   Target platforms (default: linux/amd64,linux/arm64)"
            echo "  -h, --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Build for AMD64 and ARM64 locally"
            echo "  $0 -r myuser -p                      # Build and push to DockerHub"
            echo "  $0 -r myuser -v v1.0.0 -p           # Build, tag as v1.0.0, and push"
            echo "  $0 --platforms linux/arm64          # Build for ARM64 only"
            echo ""
            echo "Supported platforms:"
            echo "  • linux/amd64     - Intel/AMD 64-bit (most servers)"
            echo "  • linux/arm64     - ARM 64-bit (Apple Silicon, ARM servers)"
            echo "  • linux/arm/v7    - ARM 32-bit v7 (Raspberry Pi 3+)"
            echo "  • linux/arm/v6    - ARM 32-bit v6 (Raspberry Pi 1, Zero)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Set image names
IMAGE_NAME="certmate"
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE_NAME="${REGISTRY}/${IMAGE_NAME}:${VERSION}"
    LATEST_IMAGE_NAME="${REGISTRY}/${IMAGE_NAME}:latest"
else
    FULL_IMAGE_NAME="${IMAGE_NAME}:${VERSION}"
    LATEST_IMAGE_NAME="${IMAGE_NAME}:latest"
fi

echo -e "${YELLOW}Configuration:${NC}"
echo "  Image: $FULL_IMAGE_NAME"
echo "  Platforms: $PLATFORMS"
echo "  Push: $PUSH"
echo ""

# Verify environment
if [ ! -f "Dockerfile" ]; then
    echo -e "${RED}❌ Error: Dockerfile not found in current directory${NC}"
    exit 1
fi

if [ ! -f ".dockerignore" ]; then
    echo -e "${YELLOW}⚠️  Warning: .dockerignore not found${NC}"
fi

# Create and use buildx builder
BUILDER_NAME="certmate-multiplatform"
echo -e "${YELLOW}🔨 Setting up buildx builder...${NC}"

if ! docker buildx ls | grep -q "$BUILDER_NAME"; then
    echo "Creating new buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use --bootstrap
else
    echo "Using existing buildx builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

# Bootstrap the builder
echo "Bootstrapping builder..."
docker buildx inspect --bootstrap

# Build arguments
BUILD_ARGS="--platform $PLATFORMS"

if [ "$PUSH" = true ]; then
    if [ -z "$REGISTRY" ]; then
        echo -e "${RED}❌ Error: Cannot push without registry (-r option)${NC}"
        exit 1
    fi
    
    # Check if logged in
    if ! docker info | grep -q "Username:"; then
        echo -e "${YELLOW}🔑 Please login to Docker registry:${NC}"
        docker login
    fi
    
    BUILD_ARGS="$BUILD_ARGS --push"
    echo -e "${YELLOW}🚀 Building and pushing multi-platform image...${NC}"
else
    echo -e "${YELLOW}🔨 Building multi-platform image (local build)...${NC}"
    echo -e "${BLUE}ℹ️  Note: Multi-platform images can't be loaded locally.${NC}"
    echo -e "${BLUE}   Use --push to push to registry for distribution.${NC}"
fi

# Build the image
echo ""
echo -e "${GREEN}Building: $FULL_IMAGE_NAME${NC}"
echo -e "${GREEN}Platforms: $PLATFORMS${NC}"
echo ""

docker buildx build $BUILD_ARGS -t "$FULL_IMAGE_NAME" .

# Tag as latest if not already latest
if [ "$VERSION" != "latest" ] && [ "$PUSH" = true ]; then
    echo -e "${YELLOW}Tagging and pushing latest...${NC}"
    docker buildx build $BUILD_ARGS -t "$LATEST_IMAGE_NAME" .
fi

echo ""
echo -e "${GREEN}✅ Multi-platform build completed successfully!${NC}"
echo ""

if [ "$PUSH" = true ]; then
    echo -e "${GREEN}🎉 Images pushed to registry:${NC}"
    echo "  $FULL_IMAGE_NAME"
    if [ "$VERSION" != "latest" ]; then
        echo "  $LATEST_IMAGE_NAME"
    fi
    echo ""
    echo -e "${BLUE}Usage examples:${NC}"
    echo ""
    echo "# Run on any supported platform:"
    echo "docker run --rm --env-file .env -p 8000:8000 $FULL_IMAGE_NAME"
    echo ""
    echo "# Force specific platform:"
    echo "docker run --platform linux/amd64 --rm --env-file .env -p 8000:8000 $FULL_IMAGE_NAME"
    echo "docker run --platform linux/arm64 --rm --env-file .env -p 8000:8000 $FULL_IMAGE_NAME"
    echo ""
    echo "# Check available platforms:"
    echo "docker manifest inspect $FULL_IMAGE_NAME"
else
    echo -e "${BLUE}Next steps:${NC}"
    echo ""
    echo "To push the multi-platform image to a registry:"
    echo "  $0 -r YOUR_DOCKERHUB_USERNAME -p"
    echo ""
    echo "To test locally (will build for current platform):"
    echo "  docker buildx build --load -t $IMAGE_NAME:test ."
    echo "  docker run --rm --env-file .env -p 8000:8000 $IMAGE_NAME:test"
fi

echo ""
echo -e "${GREEN}🌍 Supported architectures:${NC}"
echo "  • AMD64 (Intel/AMD) - Most cloud servers, desktops"
echo "  • ARM64 - Apple Silicon Macs, ARM cloud instances"
echo "  • ARM v7 - Raspberry Pi 3+, some ARM devices"
echo ""
echo -e "${BLUE}💡 Pro tip: Use Docker Compose for easier deployment:${NC}"
echo "  docker-compose up -d"
