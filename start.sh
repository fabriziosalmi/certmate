#!/bin/bash

# CertMate Startup Script

echo "🛡️  Starting CertMate SSL Certificate Manager..."
echo ""

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment and start the application
source .venv/bin/activate
echo "✅ Virtual environment activated"
echo "🚀 Starting Flask application..."
echo ""
echo "Open your browser and go to: http://localhost:8000"
echo "Press Ctrl+C to stop the application"
echo ""

python app.py
