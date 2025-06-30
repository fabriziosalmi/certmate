#!/bin/bash

# CertMate Multi-Platform Test Script
# Tests Docker images across different architectures

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🧪 CertMate Multi-Platform Test${NC}"
echo -e "${BLUE}===============================${NC}"

# Configuration
IMAGE_NAME="certmate:test"
PLATFORMS=("linux/amd64" "linux/arm64")
TEST_PORT=8080

# Check if Docker Buildx is available
if ! docker buildx version >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker Buildx not available${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker Buildx available${NC}"

# Build test images for each platform
echo -e "${YELLOW}🔨 Building test images...${NC}"
for platform in "${PLATFORMS[@]}"; do
    echo "Building for $platform..."
    docker buildx build --platform "$platform" --load -t "${IMAGE_NAME}-$(echo $platform | tr '/' '-')" . || {
        echo -e "${YELLOW}⚠️  Failed to build for $platform (emulation may not be available)${NC}"
        continue
    }
    echo -e "${GREEN}✅ Built for $platform${NC}"
done

# Test each platform
echo -e "${YELLOW}🧪 Testing platforms...${NC}"
for platform in "${PLATFORMS[@]}"; do
    platform_tag=$(echo $platform | tr '/' '-')
    image_name="${IMAGE_NAME}-${platform_tag}"
    
    if ! docker images -q "$image_name" >/dev/null; then
        echo -e "${YELLOW}⏭️  Skipping $platform (image not available)${NC}"
        continue
    fi
    
    echo "Testing $platform..."
    
    # Create minimal test environment
    cat > .env.test << EOF
API_BEARER_TOKEN=test-token-12345
CLOUDFLARE_TOKEN=dummy-token
FLASK_ENV=production
HOST=0.0.0.0
PORT=8000
EOF
    
    # Start container
    container_id=$(docker run -d --env-file .env.test -p $TEST_PORT:8000 "$image_name")
    
    # Wait for startup
    echo "Waiting for container to start..."
    sleep 10
    
    # Test health endpoint
    if curl -sf "http://localhost:$TEST_PORT/health" >/dev/null; then
        echo -e "${GREEN}✅ Health check passed for $platform${NC}"
        
        # Test API endpoint
        if curl -sf -H "Authorization: Bearer test-token-12345" "http://localhost:$TEST_PORT/api/certificates" >/dev/null; then
            echo -e "${GREEN}✅ API check passed for $platform${NC}"
        else
            echo -e "${YELLOW}⚠️  API check failed for $platform${NC}"
        fi
    else
        echo -e "${RED}❌ Health check failed for $platform${NC}"
    fi
    
    # Get container info
    arch=$(docker exec "$container_id" uname -m 2>/dev/null || echo "unknown")
    echo "Container architecture: $arch"
    
    # Cleanup
    docker stop "$container_id" >/dev/null
    docker rm "$container_id" >/dev/null
    
    # Increment port for next test
    ((TEST_PORT++))
done

# Cleanup
rm -f .env.test

echo ""
echo -e "${GREEN}🎉 Multi-platform testing completed!${NC}"
echo ""
echo -e "${BLUE}💡 To build and push multi-platform images:${NC}"
echo "  ./build-multiplatform.sh -r YOUR_DOCKERHUB_USERNAME -p"
echo ""
echo -e "${BLUE}💡 To run on specific platform:${NC}"
echo "  docker run --platform linux/amd64 certmate:test"
echo "  docker run --platform linux/arm64 certmate:test"
