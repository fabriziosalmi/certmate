#!/bin/bash

# Simple test runner for CertMate
echo "🧪 Running CertMate tests..."

# Set test environment
export FLASK_ENV=testing
export TESTING=true

# Run tests
echo "Running test suite..."
pytest -v --tb=short

if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
    
    # Run with coverage if requested
    if [ "$1" = "--coverage" ]; then
        echo "📊 Generating coverage report..."
        pytest --cov=. --cov-report=term-missing --cov-report=html
        echo "Coverage report saved to htmlcov/index.html"
    fi
else
    echo "❌ Some tests failed!"
    exit 1
fi
