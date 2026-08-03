#!/bin/bash

# Simple test runner for CertMate
echo "🧪 Running CertMate tests..."

# Set test environment
export FLASK_ENV=testing
export TESTING=true

# The same selection `make test` and scripts/release.sh use.
#
# Without it this script ran the whole suite in one process and reported four
# failures on a clean checkout: the `ui` tests drive Playwright against a live
# server and cannot share a process with the rest, and `e2e` needs a running
# instance. Both pass when run on their own — so the only thing a bare `pytest`
# proved was that this script was wrong. Run the UI suite separately with
# `pytest -m ui` (see .github/workflows/ui-tests.yml).
MARKERS='not ui and not e2e'

echo "Running test suite (${MARKERS})..."
pytest -v --tb=short -m "$MARKERS"

if [ $? -eq 0 ]; then
    echo "✅ All tests passed!"
    
    # Run with coverage if requested
    if [ "$1" = "--coverage" ]; then
        echo "📊 Generating coverage report..."
        pytest --cov=. --cov-report=term-missing --cov-report=html -m "$MARKERS"
        echo "Coverage report saved to htmlcov/index.html"
    fi
else
    echo "❌ Some tests failed!"
    exit 1
fi
