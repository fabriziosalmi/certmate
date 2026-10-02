# CertMate Development Makefile
# ========================================================================
# The commands a contributor runs, kept equal to the ones CI and the release
# gate run. "Equal" is checked, not promised: tests/test_the_makefile_runs_
# what_ci_runs.py fails when a check CI runs is missing here or in
# CONTRIBUTING.md, when a pinned tool version differs from ci.yml, or when the
# real-certificate test list differs from scripts/release.sh.
#
# All targets use the local .venv (Python 3.12) to match CI and Docker.
#
# Quick start:
#   make setup          Create .venv + install the locked runtime and the test deps
#   make check          lint + security + tests (the everyday gate)
#   make ci             What the CI test job runs (needs Docker and Node)
#   make test-e2e       The release gate's real-certificate step
# ========================================================================

.PHONY: help setup install-dev \
        run test test-unit test-integration test-coverage test-ci test-ui test-network test-e2e test-watch \
        lint security check ci coverage-floors \
        docker-build docker-run docker-stop \
        clean clean-venv clean-all

# Python 3.12 — must match Dockerfile base image
PYTHON_BIN ?= $(shell command -v python3.12 2>/dev/null || echo python3)
VENV := .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/python -m pytest
PYTHON := $(VENV)/bin/python
DOCKER_IMAGE := certmate
DOCKER_TAG := dev

# Pinned the way ci.yml pins them. flake8 is pinned in requirements-test.txt.
BANDIT_VERSION := 1.9.4

# The flake8 selection CI enforces: syntax errors and undefined names (E9, F63,
# F7, F82) and the bug classes that are clean today and must stay clean (#428).
FLAKE8_SELECT := E9,F63,F7,F82,F811,F632,E711,E712,E713,E714,F401,F841,E722

# Real-certificate end-to-end files, the list scripts/release.sh runs.
E2E_FILES := tests/test_health_ready_e2e.py tests/test_cert_lifecycle.py tests/test_async_issuance_e2e.py \
             tests/test_ari_staging_e2e.py tests/test_renewal_uses_todays_settings_e2e.py \
             tests/test_ca_account_email_e2e.py

# Default target
help:
	@echo ""
	@echo "  CertMate Development Commands"
	@echo "  =============================="
	@echo ""
	@echo "  Setup"
	@echo "    make setup            Create .venv (Python 3.12), install requirements.lock + test deps"
	@echo "    make install-dev      Install into an existing .venv"
	@echo ""
	@echo "  Run"
	@echo "    make run              Start CertMate from the .venv on http://localhost:8000"
	@echo ""
	@echo "  Testing"
	@echo "    make test             Unit + integration, no UI, no e2e (what scripts/release.sh runs)"
	@echo "    make test-unit        Unit tests only"
	@echo "    make test-integration Integration tests only"
	@echo "    make test-coverage    make test, with a coverage report"
	@echo "    make test-ci          What the CI test job runs: needs Docker (e2e fixtures) and Node"
	@echo "    make test-ui          Playwright suite (needs Docker)"
	@echo "    make test-network     CA-reachability checks (outbound HTTPS; CI runs them weekly)"
	@echo "    make test-e2e         Real certificates against Let's Encrypt staging (needs .env)"
	@echo ""
	@echo "  Code Quality"
	@echo "    make lint             flake8 (CI selection) + complexity, exception and ruff budgets"
	@echo "    make security         bandit (medium and above)"
	@echo "    make check            lint + security + test"
	@echo "    make ci               lint + security + test-ci + coverage floors"
	@echo ""
	@echo "  Docker"
	@echo "    make docker-build     Build Docker image ($(DOCKER_IMAGE):$(DOCKER_TAG))"
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

# The locked set is what the image and the installer run; the test requirements
# go on top with the lock as a constraint, so a test dependency cannot move
# a runtime pin (the same way the Dockerfile layers the extras, #686).
install-dev: $(VENV)/bin/activate
	$(PIP) install -r requirements.lock
	$(PIP) install -c requirements.lock -r requirements-test.txt
	$(PIP) install bandit==$(BANDIT_VERSION)

# ── Run ────────────────────────────────────────────────────────────────

run: $(VENV)/bin/activate
	$(PYTHON) app.py

# ── Testing ────────────────────────────────────────────────────────────
# `test` is the selection CONTRIBUTING.md documents and scripts/release.sh runs.
# CI's own is wider (it runs the e2e-marked tests too, with the fixtures Docker
# provides, and leaves out only ui and network), which is test-ci.

test: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m "not ui and not e2e"

test-unit: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m "unit"

test-integration: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m "integration"

test-coverage: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short --cov=modules --cov-report=html --cov-report=term-missing --cov-report=xml -m "not ui and not e2e"

# Character for character what ci.yml's "Run tests with coverage" runs. Node is
# required, as there, so the frontend tests cannot skip without being noticed.
test-ci: $(VENV)/bin/activate
	FLASK_ENV=testing TESTING=true CERTMATE_REQUIRE_NODE=1 \
	$(PYTEST) -v --tb=short --cov=modules --cov-report=xml --cov-report=html --cov-report=json:coverage.json --cov-fail-under=75 -m "not ui and not network"
	$(MAKE) coverage-floors

coverage-floors: $(VENV)/bin/activate
	$(PYTHON) scripts/check_coverage_floors.py coverage.json

test-ui: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m ui

test-network: $(VENV)/bin/activate
	$(PYTEST) -v --tb=short -m network

# The release gate's real-certificate step: Let's Encrypt staging through
# Cloudflare DNS-01. Needs Docker and a .env with CLOUDFLARE_API_TOKEN and
# CERTMATE_TEST_DOMAIN.
test-e2e: $(VENV)/bin/activate
	@test -f .env || { echo ".env with CLOUDFLARE_API_TOKEN and CERTMATE_TEST_DOMAIN is required"; exit 1; }
	set -a; . ./.env; set +a; \
	CERTMATE_E2E_CA_PROVIDER=letsencrypt_staging $(PYTEST) -q -m e2e $(E2E_FILES) -p no:cacheprovider

test-watch: $(VENV)/bin/activate
	$(PIP) install -q pytest-watch
	$(VENV)/bin/ptw

# ── Code Quality ───────────────────────────────────────────────────────
# What the lint step of ci.yml fails on. Its last line, the full flake8 style
# pass with --exit-zero, is informational and is not repeated here.

lint: $(VENV)/bin/activate
	$(VENV)/bin/flake8 . --count --select=$(FLAKE8_SELECT) --show-source --statistics
	$(PYTHON) scripts/check_complexity_budget.py
	$(PYTHON) scripts/check_exception_budget.py
	$(PYTHON) scripts/check_ruff_budget.py

security: $(VENV)/bin/activate
	$(VENV)/bin/bandit -r modules/ app.py --severity-level medium

check: lint security test

ci: lint security test-ci
	@echo ""
	@echo "✅ CI test job simulated: lint, security, tests with coverage, coverage floors"

# ── Docker ─────────────────────────────────────────────────────────────

docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo ""
	@echo "✅ Built $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@docker images $(DOCKER_IMAGE):$(DOCKER_TAG) --format "   Size: {{.Size}}"

docker-run:
	docker compose up -d certmate
	@echo ""
	@echo "✅ CertMate running at http://localhost:8000"

docker-stop:
	docker compose down

# ── Cleanup ────────────────────────────────────────────────────────────

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml coverage.json dist/ build/ *.egg-info/ pytest.log

clean-venv:
	rm -rf $(VENV)

clean-all: clean clean-venv
