#!/usr/bin/env bash
#
# CertMate test runner — suitable for pre-commit hooks.
#
# Usage:
#   ./tests/run_tests.sh              # Fast tests only (no real certs)
#   ./tests/run_tests.sh --full       # Full suite with real Cloudflare certs
#   ./tests/run_tests.sh --ui         # Include Playwright UI tests
#
# Environment variables:
#   CLOUDFLARE_API_TOKEN    Required for --full (real cert tests)
#   CERTMATE_TEST_DOMAIN    Domain for cert tests (default: test.gpfree.org)
#   CERTMATE_TEST_PORT      Port to use (default: 18888)
#   CERTMATE_SKIP_BUILD     Set to "1" to skip docker build
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Defaults
FAST_ONLY=true
RUN_UI=false
PORT="${CERTMATE_TEST_PORT:-18888}"
IMAGE="${CERTMATE_IMAGE:-certmate:test}"
CONTAINER="certmate-test-suite"

# Parse args
for arg in "$@"; do
    case "$arg" in
        --full) FAST_ONLY=false ;;
        --ui) RUN_UI=true ;;
        --help|-h)
            echo "Usage: $0 [--full] [--ui]"
            echo "  --full  Run all tests including real cert creation (needs CLOUDFLARE_API_TOKEN)"
            echo "  --ui    Include Playwright browser tests"
            exit 0
            ;;
    esac
done

echo "=== CertMate Test Suite ==="
echo "Port: $PORT | Image: $IMAGE"

# 1. Build Docker image
if [ "${CERTMATE_SKIP_BUILD:-}" != "1" ]; then
    echo ""
    echo "--- Building Docker image ---"
    docker build -t "$IMAGE" . 2>&1 | tail -3
fi

# 2. Start container
echo ""
echo "--- Starting container ---"
docker rm -f "$CONTAINER" 2>/dev/null || true
docker run -d --name "$CONTAINER" -p "${PORT}:8000" "$IMAGE"

# 3. Wait for healthy
echo "Waiting for container to be healthy..."
for i in $(seq 1 60); do
    if curl -sf "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        echo "Container healthy after ${i}s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: Container not healthy after 60s"
        docker logs --tail 30 "$CONTAINER"
        docker rm -f "$CONTAINER"
        exit 1
    fi
    sleep 1
done

# 4. Run tests
echo ""
echo "--- Running tests ---"
EXIT_CODE=0

# Build pytest args
PYTEST_ARGS=(-v --tb=short -x)
PYTEST_ARGS+=(tests/test_static_csp.py tests/test_auth.py tests/test_settings.py tests/test_pages.py tests/test_backup.py)

if [ "$FAST_ONLY" = false ]; then
    if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
        echo "WARNING: CLOUDFLARE_API_TOKEN not set — skipping cert lifecycle tests"
    else
        PYTEST_ARGS+=(tests/test_cert_lifecycle.py)
    fi
fi

if [ "$RUN_UI" = true ]; then
    PYTEST_ARGS+=(tests/test_ui.py)
fi

export CERTMATE_TEST_PORT="$PORT"
export CERTMATE_SKIP_BUILD=1

python -m pytest "${PYTEST_ARGS[@]}" || EXIT_CODE=$?

# 5. Cleanup
echo ""
echo "--- Cleanup ---"
docker rm -f "$CONTAINER" 2>/dev/null || true

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "=== ALL TESTS PASSED ==="
else
    echo ""
    echo "=== TESTS FAILED (exit code: $EXIT_CODE) ==="
fi

exit $EXIT_CODE
