#!/bin/bash
# Debug script to check certificate visibility in Docker container

echo "=== Local Certificate Check ==="
echo "Certificates in local folder:"
ls -la certificates/ 2>/dev/null || echo "No certificates folder found locally"

echo ""
echo "=== Docker Container Check ==="
if docker ps | grep -q certmate; then
    echo "CertMate container is running. Checking certificates inside container:"
    docker exec certmate ls -la /app/certificates 2>/dev/null || echo "Cannot access container certificates"
    
    echo ""
    echo "Checking container data directory:"
    docker exec certmate ls -la /app/data 2>/dev/null || echo "Cannot access container data"
    
    echo ""
    echo "Checking if container can read settings:"
    docker exec certmate cat /app/data/settings.json 2>/dev/null || echo "Cannot read settings from container"
else
    echo "CertMate container is not running"
    echo "Available containers:"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
fi

echo ""
echo "=== Docker Compose Service Check ==="
if command -v docker-compose >/dev/null 2>&1; then
    docker-compose ps 2>/dev/null || echo "No docker-compose services running"
else
    echo "docker-compose not available"
fi
