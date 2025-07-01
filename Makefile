.PHONY: test test-unit test-integration test-coverage test-watch install-dev lint format security check pre-commit clean help

# Default target
help:
	@echo "Available commands:"
	@echo "  install-dev     Install development dependencies"
	@echo "  test           Run all tests"
	@echo "  test-unit      Run unit tests only"
	@echo "  test-integration Run integration tests only"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  test-watch     Run tests in watch mode"
	@echo "  lint           Run linting checks"
	@echo "  format         Format code with black and isort"
	@echo "  security       Run security checks"
	@echo "  check          Run all checks (lint, security, tests)"
	@echo "  pre-commit     Install and run pre-commit hooks"
	@echo "  clean          Clean up temporary files"

# Install development dependencies
install-dev:
	pip install -r requirements.txt
	pip install -r requirements-test.txt
	pip install pre-commit black isort flake8 bandit safety

# Run all tests
test:
	pytest

# Run only unit tests
test-unit:
	pytest -m "not integration and not slow"

# Run only integration tests
test-integration:
	pytest -m integration

# Run tests with coverage
test-coverage:
	pytest --cov=. --cov-report=html --cov-report=term-missing --cov-report=xml

# Run tests in watch mode (requires pytest-watch)
test-watch:
	pip install pytest-watch
	ptw

# Linting
lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

# Format code
format:
	black .
	isort . --profile black

# Security checks
security:
	bandit -r . --severity-level medium
	safety check

# Run all checks
check: lint security test

# Pre-commit setup
pre-commit:
	pre-commit install
	pre-commit run --all-files

# Clean up
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name ".pytest_cache" -delete
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/

# CI simulation (what runs in GitHub Actions)
ci: lint security test-coverage
