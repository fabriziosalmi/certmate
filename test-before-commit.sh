#!/bin/bash

# Pre-commit test script for CertMate
# Run this before committing to ensure code quality

set -e  # Exit on any error

echo "🧪 Running CertMate pre-commit checks..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" == "" ]]; then
    print_warning "Virtual environment not detected. Please activate your venv."
    echo "Run: source .venv/bin/activate"
    exit 1
fi

print_status "Virtual environment is active"

# Install/update dependencies
echo "📦 Installing/updating dependencies..."
pip install -q -r requirements.txt
pip install -q -r requirements-test.txt

# Run linting
echo "🔍 Running code linting..."
if command -v flake8 &> /dev/null; then
    flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
    print_status "Linting passed"
else
    pip install -q flake8
    flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
    print_status "Linting passed"
fi

# Run security checks
echo "🔒 Running security checks..."
if command -v bandit &> /dev/null; then
    bandit -r . --severity-level medium -q || print_warning "Security issues found (non-blocking)"
else
    pip install -q bandit
    bandit -r . --severity-level medium -q || print_warning "Security issues found (non-blocking)"
fi
print_status "Security check completed"

# Run tests
echo "🧪 Running test suite..."
pytest -v --tb=short

print_status "All tests passed"

# Generate coverage report
echo "📊 Generating coverage report..."
pytest --cov=. --cov-report=term-missing --quiet

print_status "Coverage report generated"

# Check for TODO/FIXME comments
echo "📝 Checking for TODO/FIXME comments..."
TODO_COUNT=$(grep -r "TODO\|FIXME" --include="*.py" . | wc -l || echo "0")
if [ "$TODO_COUNT" -gt 0 ]; then
    print_warning "Found $TODO_COUNT TODO/FIXME comments"
    grep -r "TODO\|FIXME" --include="*.py" . || true
else
    print_status "No TODO/FIXME comments found"
fi

echo ""
echo "🎉 All pre-commit checks passed! Ready to commit."
echo ""
echo "To commit your changes:"
echo "  git add ."
echo "  git commit -m 'Your commit message'"
echo ""
echo "To set up automatic pre-commit hooks:"
echo "  pip install pre-commit"
echo "  pre-commit install"
