#!/bin/bash
# Quick fix for existing certificates not showing in Docker

echo "🔧 Quick fix for certificates not showing in Docker..."

# Stop any running containers
docker-compose down 2>/dev/null || true

# Check local certificates
local_domains=$(find ./certificates -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
echo "📁 Local domains found: $local_domains"

if [ $local_domains -gt 0 ]; then
    echo "📋 Local certificate domains:"
    ls -1 certificates/
fi

# Start with docker-compose
echo "🚀 Starting with docker-compose..."
docker-compose up -d

# Wait and check
sleep 5

if docker-compose ps | grep -q "Up"; then
    echo "✅ Container is running"
    
    # Check container certificates
    echo "🔍 Checking certificates in container..."
    docker-compose exec certmate ls -la /app/certificates
    
    echo ""
    echo "🌐 Open http://localhost:8000 to see your certificates"
    echo "🔑 Check /app/data/settings.json for API token if needed"
    
else
    echo "❌ Container failed to start. Checking logs..."
    docker-compose logs certmate
fi
