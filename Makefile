# CertMate Development Makefile
# ========================================================================
# Single source of truth for build/test/lint/deploy commands.
# All targets use the local .venv (Python 3.12) to match CI and Docker.
#
# Quick start:
#   make setup          Create .venv + install all deps
#   make test           Run unit/integration tests (same as CI)
#   make docker-build   Build the Docker image
#   make docker-test    Build + run tests inside Docker
#   make clean          Remove caches and temp files
# ========================================================================

.PHONY: help setup test test-unit test-integration test-coverage test-watch \
        lint format security check ci \
        docker-build docker-test docker-run docker-stop \
        clean clean-venv clean-all pre-commit

# Python 3.12 — must match Dockerfile base image
PYTHON_BIN ?= $(shell command -v python3.12 2>/dev/null || echo python3)
VENV := .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/python -m pytest
PYTHON := $(VENV)/bin/python
DOCKER_IMAGE := certmate
DOCKER_TAG := dev

# Default target
help:
	@echo ""
	@echo "  CertMate Development Commands"
	@echo "  =============================="
	@echo ""
	@echo "  Setup & Dependencies"
	@echo "    make setup            Create .venv (Python 3.12) + install all deps"
	@echo "    make install-dev      Install deps into existing .venv"
	@echo ""
	@echo "  Testing"
	@echo "    make test             Run all tests (unit + integration, no UI)"
	@echo "    make test-unit        Run unit tests only"
	@echo "    make test-integration Run integration tests only"
	@echo "    make test-coverage    Run tests with coverage report"
	@echo "    make test-watch       Run tests in watch mode"
	@echo ""
	@echo "  Code Quality"
	@echo "    make lint             Run flake8 linting"
	@echo "    make format           Format with black + isort"
	@echo "    make security         Run bandit security scan"
	@echo "    make check            Run lint + security + tests"
	@echo "    make ci               Simulate full CI pipeline locally"
	@echo ""
	@echo "  Docker"
	@echo "    make docker-build     Build Docker image ($(DOCKER_IMAGE):$(DOCKER_TAG))"
	@echo "    make docker-test      Build + run tests inside Docker"
	@echo "    make docker-run       Start CertMate in Docker"
	@echo "    make docker-stop      Stop CertMate Docker container"
	@echo ""
	@echo "  Cleanup"
	@echo "    make clean            Remove caches and temp files"
	@echo "    make clean-venv       Delete .venv entirely"
	@echo "    make clean-all        clean + clean-venv"
	@echo ""

# ── Setup ──────────────────────────────────────────────────────────────

$(VENV)/bin/activate:
	@echo "Creating .venv with $(PYTHON_BIN)..."
	$(PYTHON_BIN) -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel

setup: $(VENV)/bin/activate install-dev
	@echo ""
	@echo "✅ .venv ready. Activate with:"
	@echo "   source .venv/bin/activate"

install-dev: $(VENV)/bin/activate
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-test.txt
	$(PIP) install flake8 bandit black isort

# ── Testing ────────────────────────────────────────────────────────────

test: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m "not ui and not e2e"

test-unit: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m "unit"

test-integration: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m "integration"

test-coverage: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short --cov=. --cov-report=html --cov-report=term-missing --cov-report=xml -m "not ui and not e2e"

test-watch: $(VENV)/bin/activate
	$(PIP) install -q pytest-watch
	$(VENV)/bin/ptw

# ── Code Quality ───────────────────────────────────────────────────────

lint: $(VENV)/bin/activate
	$(VENV)/bin/flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	$(VENV)/bin/flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

format: $(VENV)/bin/activate
	$(VENV)/bin/black .
	$(VENV)/bin/isort . --profile black

security: $(VENV)/bin/activate
	$(VENV)/bin/bandit -r modules/ app.py --severity-level medium

check: lint security test

# CI simulation — identical to what GitHub Actions runs
ci: lint security test-coverage
	@echo ""
	@echo "✅ CI simulation passed"

# ── Docker ─────────────────────────────────────────────────────────────

docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo ""
	@echo "✅ Built $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@docker images $(DOCKER_IMAGE):$(DOCKER_TAG) --format "   Size: {{.Size}}"

docker-test: docker-build
	@echo "Running tests inside Docker..."
	docker run --rm \
		-e FLASK_ENV=testing \
		-e TESTING=true \
		-v $(CURDIR)/tests:/app/tests:ro \
		-v $(CURDIR)/requirements-test.txt:/app/requirements-test.txt:ro \
		$(DOCKER_IMAGE):$(DOCKER_TAG) \
		sh -c "pip install -q -r requirements-test.txt && python -m pytest tests/ -v --tb=short -m 'not ui and not e2e'"
	@echo ""
	@echo "✅ Docker tests passed"

docker-run:
	docker compose up -d certmate
	@echo ""
	@echo "✅ CertMate running at http://localhost:8000"

docker-stop:
	docker compose down

# ── Pre-commit ─────────────────────────────────────────────────────────

pre-commit: $(VENV)/bin/activate
	$(PIP) install -q pre-commit
	$(VENV)/bin/pre-commit install
	$(VENV)/bin/pre-commit run --all-files

# ── Cleanup ────────────────────────────────────────────────────────────

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml dist/ build/ *.egg-info/ pytest.log

clean-venv:
	rm -rf $(VENV)

clean-all: clean clean-venv
