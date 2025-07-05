#!/bin/bash
# Quick API test script for CertMate
# This script runs endpoint tests and provides a confidence check before commits

echo "🧪 CertMate API Quick Test"
echo "=========================="

# Check if server is running
if ! curl -s http://127.0.0.1:8000/health > /dev/null; then
    echo "❌ Server not running on http://127.0.0.1:8000"
    echo "💡 Start the server with: python app.py"
    exit 1
fi

echo "✅ Server is running"

# Run the comprehensive test
python3 test_all_endpoints.py --auto-token "$@"

# Store exit code
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo ""
    echo "🎉 All tests passed! You're good to commit! 🚀"
else
    echo ""
    echo "⚠️  Some tests failed. Please review before committing."
fi

exit $exit_code
