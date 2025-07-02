#!/bin/bash

# CertMate Setup Script

echo "🛡️  Setting up CertMate SSL Certificate Manager..."
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
source .venv/bin/activate
echo "✅ Virtual environment activated"

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt
echo "✅ Dependencies installed"

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo ""
    echo "⚠️  certbot is not installed globally."
    echo "Please install certbot using one of these methods:"
    echo ""
    echo "macOS (with Homebrew):"
    echo "  brew install certbot"
    echo ""
    echo "Ubuntu/Debian:"
    echo "  sudo apt-get install certbot python3-certbot-dns-cloudflare"
    echo ""
    echo "CentOS/RHEL:"
    echo "  sudo yum install certbot python3-certbot-dns-cloudflare"
    echo ""
else
    echo "✅ certbot found: $(certbot --version)"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps (if you have DNS at Cloudflare):"
echo "1. Get your Cloudflare API token from: https://dash.cloudflare.com/profile/api-tokens"
echo "2. Run: ./start.sh"
echo "3. Open http://localhost:8000 in your browser"
echo "4. Go to Settings and configure your API token and email"
echo "5. Same process can be used for others DNS providers"
echo ""
