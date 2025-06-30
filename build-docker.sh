#!/bin/bash

# CertMate Docker Build Script
# This script builds and optionally pushes the CertMate Docker image

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="certmate"
DOCKER_REGISTRY=""  # Set to your DockerHub username or registry URL
VERSION="latest"

# Parse command line arguments
PUSH=false
TAG_VERSION=""
MULTIPLATFORM=false
PLATFORMS="linux/amd64,linux/arm64"

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--push)
            PUSH=true
            shift
            ;;
        -r|--registry)
            DOCKER_REGISTRY="$2"
            shift 2
            ;;
        -v|--version)
            TAG_VERSION="$2"
            shift 2
            ;;
        -m|--multiplatform)
            MULTIPLATFORM=true
            shift
            ;;
        --platforms)
            PLATFORMS="$2"
            MULTIPLATFORM=true
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -p, --push              Push image to registry after building"
            echo "  -r, --registry USER     DockerHub username or registry URL"
            echo "  -v, --version VERSION   Tag version (default: latest)"
            echo "  -m, --multiplatform     Build for multiple platforms (linux/amd64,linux/arm64)"
            echo "  --platforms PLATFORMS   Specify custom platforms (comma-separated)"
            echo "  -h, --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Build for current platform only"
            echo "  $0 -m                                 # Build for AMD64 and ARM64"
            echo "  $0 -m -p -r username                  # Build multi-platform and push"
            echo "  $0 --platforms linux/amd64           # Build for AMD64 only"
            echo "  $0 --platforms linux/arm64,linux/arm/v7  # Build for ARM64 and ARMv7"
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Set image tag
if [ -n "$TAG_VERSION" ]; then
    VERSION="$TAG_VERSION"
fi

# Build full image name
if [ -n "$DOCKER_REGISTRY" ]; then
    FULL_IMAGE_NAME="${DOCKER_REGISTRY}/${IMAGE_NAME}:${VERSION}"
    LATEST_IMAGE_NAME="${DOCKER_REGISTRY}/${IMAGE_NAME}:latest"
else
    FULL_IMAGE_NAME="${IMAGE_NAME}:${VERSION}"
    LATEST_IMAGE_NAME="${IMAGE_NAME}:latest"
fi

echo -e "${YELLOW}Building CertMate Docker Image${NC}"
echo "Image name: $FULL_IMAGE_NAME"

# Check if multiplatform build is requested
if [ "$MULTIPLATFORM" = true ]; then
    echo "Platforms: $PLATFORMS"
    
    # Check if buildx is available
    if ! docker buildx version >/dev/null 2>&1; then
        echo -e "${RED}Error: Docker Buildx is not available!${NC}"
        echo "Please install Docker Buildx or use Docker Desktop which includes it."
        exit 1
    fi
    
    # Create and use buildx builder if it doesn't exist
    BUILDER_NAME="certmate-builder"
    if ! docker buildx ls | grep -q "$BUILDER_NAME"; then
        echo -e "${YELLOW}Creating new buildx builder: $BUILDER_NAME${NC}"
        docker buildx create --name "$BUILDER_NAME" --use
    else
        echo -e "${YELLOW}Using existing buildx builder: $BUILDER_NAME${NC}"
        docker buildx use "$BUILDER_NAME"
    fi
    
    # Bootstrap the builder
    docker buildx inspect --bootstrap
fi

# Verify .dockerignore exists
if [ ! -f ".dockerignore" ]; then
    echo -e "${RED}Error: .dockerignore file not found!${NC}"
    echo "This file is required to exclude sensitive files from the Docker image."
    exit 1
fi

# Verify .env is excluded
if grep -q "^\.env$" .dockerignore; then
    echo -e "${GREEN}✓ .env files are properly excluded${NC}"
else
    echo -e "${RED}Warning: .env files may not be excluded from Docker image${NC}"
fi

# Check if .env exists and warn about it
if [ -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file exists in build context${NC}"
    echo "Ensure it's listed in .dockerignore to prevent inclusion in image"
fi

# Build the Docker image
echo -e "${YELLOW}Building Docker image...${NC}"

if [ "$MULTIPLATFORM" = true ]; then
    # Multi-platform build using buildx
    BUILD_ARGS="--platform $PLATFORMS"
    
    if [ "$PUSH" = true ]; then
        if [ -z "$DOCKER_REGISTRY" ]; then
            echo -e "${RED}Error: Cannot push multi-platform build without registry (-r option)${NC}"
            exit 1
        fi
        
        # Check if logged in to Docker Hub
        if ! docker info | grep -q "Username:"; then
            echo -e "${YELLOW}Not logged in to Docker registry. Please login:${NC}"
            docker login
        fi
        
        # Build and push multi-platform
        BUILD_ARGS="$BUILD_ARGS --push"
        docker buildx build $BUILD_ARGS -t "$FULL_IMAGE_NAME" .
        
        # Tag as latest if not already latest
        if [ "$VERSION" != "latest" ]; then
            docker buildx build $BUILD_ARGS -t "$LATEST_IMAGE_NAME" .
            echo -e "${GREEN}✓ Built and pushed: $LATEST_IMAGE_NAME${NC}"
        fi
        
        echo -e "${GREEN}✓ Built and pushed multi-platform: $FULL_IMAGE_NAME${NC}"
        echo "Platforms: $PLATFORMS"
    else
        # Build multi-platform but don't push (load to local docker)
        # Note: Multi-platform images can't be loaded to local docker
        # We'll build for current platform only when not pushing
        echo -e "${YELLOW}Multi-platform build without push - building for current platform only${NC}"
        docker buildx build --load -t "$FULL_IMAGE_NAME" .
        
        # Tag as latest if not already latest
        if [ "$VERSION" != "latest" ] && [ -n "$DOCKER_REGISTRY" ]; then
            docker tag "$FULL_IMAGE_NAME" "$LATEST_IMAGE_NAME"
            echo -e "${GREEN}✓ Tagged as latest: $LATEST_IMAGE_NAME${NC}"
        fi
        
        echo -e "${GREEN}✓ Successfully built (current platform): $FULL_IMAGE_NAME${NC}"
    fi
else
    # Traditional single-platform build
    docker build -t "$FULL_IMAGE_NAME" .
    
    # Tag as latest if not already latest
    if [ "$VERSION" != "latest" ] && [ -n "$DOCKER_REGISTRY" ]; then
        docker tag "$FULL_IMAGE_NAME" "$LATEST_IMAGE_NAME"
        echo -e "${GREEN}✓ Tagged as latest: $LATEST_IMAGE_NAME${NC}"
    fi
    
    echo -e "${GREEN}✓ Successfully built: $FULL_IMAGE_NAME${NC}"
fi

# Verify no secrets in image
echo -e "${YELLOW}Verifying no secrets in image...${NC}"
if [ "$MULTIPLATFORM" = true ] && [ "$PUSH" = true ]; then
    echo -e "${YELLOW}Skipping secret verification for multi-platform pushed image${NC}"
    echo "(Multi-platform images are not available locally for inspection)"
else
    SECRET_CHECK=$(docker run --rm "$FULL_IMAGE_NAME" find / -name "*.env" 2>/dev/null || true)
    if [ -z "$SECRET_CHECK" ]; then
        echo -e "${GREEN}✓ No .env files found in image${NC}"
    else
        echo -e "${RED}Warning: Found .env files in image:${NC}"
        echo "$SECRET_CHECK"
    fi
    
    # Check image size
    IMAGE_SIZE=$(docker images "$FULL_IMAGE_NAME" --format "table {{.Size}}" | tail -n +2)
    echo "Image size: $IMAGE_SIZE"
fi

# Push if requested
if [ "$PUSH" = true ] && [ "$MULTIPLATFORM" = false ]; then
    if [ -z "$DOCKER_REGISTRY" ]; then
        echo -e "${RED}Error: Cannot push without registry (-r option)${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Pushing to registry...${NC}"
    
    # Check if logged in to Docker Hub
    if ! docker info | grep -q "Username:"; then
        echo -e "${YELLOW}Not logged in to Docker registry. Please login:${NC}"
        docker login
    fi
    
    docker push "$FULL_IMAGE_NAME"
    echo -e "${GREEN}✓ Pushed: $FULL_IMAGE_NAME${NC}"
    
    if [ "$VERSION" != "latest" ]; then
        docker push "$LATEST_IMAGE_NAME"
        echo -e "${GREEN}✓ Pushed: $LATEST_IMAGE_NAME${NC}"
    fi
elif [ "$PUSH" = true ] && [ "$MULTIPLATFORM" = true ]; then
    echo -e "${GREEN}✓ Multi-platform images already pushed during build${NC}"
fi

echo -e "${GREEN}Build completed successfully!${NC}"
echo ""
if [ "$MULTIPLATFORM" = true ]; then
    echo "Multi-platform build completed for: $PLATFORMS"
    echo ""
fi
echo "To run the container:"
echo "docker run -d --name certmate --env-file .env -p 8000:8000 -v certmate_data:/app/data $FULL_IMAGE_NAME"
echo ""
echo "To test locally:"
echo "docker run --rm --env-file .env -p 8000:8000 $FULL_IMAGE_NAME"
echo ""
if [ "$MULTIPLATFORM" = true ]; then
    echo "Multi-platform usage examples:"
    echo "# Pull and run on ARM64 (Apple Silicon, ARM servers):"
    echo "docker run --platform linux/arm64 --rm --env-file .env -p 8000:8000 $FULL_IMAGE_NAME"
    echo ""
    echo "# Pull and run on AMD64 (Intel/AMD servers):"
    echo "docker run --platform linux/amd64 --rm --env-file .env -p 8000:8000 $FULL_IMAGE_NAME"
    echo ""
    echo "# Check available platforms:"
    echo "docker manifest inspect $FULL_IMAGE_NAME"
fi
