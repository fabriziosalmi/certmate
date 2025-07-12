#!/bin/bash
# Docker run script with proper volume mounts

docker run -d \
  --name certmate \
  -p 8000:8000 \
  -v "$(pwd)/certificates:/app/certificates" \
  -v "$(pwd)/data:/app/data" \
  -v "$(pwd)/logs:/app/logs" \
  -e FLASK_ENV=production \
  -e API_BEARER_TOKEN="${API_BEARER_TOKEN}" \
  certmate:latest
