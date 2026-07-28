# Multi-stage build for optimized image size and faster builds.
# Base image pinned by sha256 digest (not just the tag): the tag is a
# moving target on Docker Hub, the digest is content-addressed and
# guarantees byte-identical bytes. Bump deliberately when there's a
# CVE fix or feature reason — not implicitly on every rebuild.
FROM python:3.12-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

# Set working directory for build stage
WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y -o Acquire::Retries=3 gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy every requirements*.txt so REQUIREMENTS_FILE and EXTRA_REQUIREMENTS
# can point at any of the optional sets (storage backends, cloud DNS,
# extended providers, …) without rebuilding the COPY layer for each one.
COPY requirements*.txt ./

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install minimal requirements by default (fastest build)
# Override with --build-arg REQUIREMENTS_FILE=requirements.txt for full install
ARG REQUIREMENTS_FILE=requirements.txt
# Optional extra pip installs layered on top of the main requirements.
# Accepts a SPACE-SEPARATED list so a single image can bundle e.g. the
# Azure DNS plugin AND every remote storage backend at once. Quote the
# value when invoking buildx so the shell preserves the spaces:
#
#   --build-arg EXTRA_REQUIREMENTS="requirements-azure.txt requirements-storage-all.txt"
#   --build-arg EXTRA_REQUIREMENTS="requirements-aws.txt requirements-gcp.txt"
#   --build-arg EXTRA_REQUIREMENTS=requirements-storage-all.txt   (single file)
#
# Empty by default → no second install, layer cached.
ARG EXTRA_REQUIREMENTS=
# shellcheck disable=SC2086 — intentional word-splitting to iterate the list.
RUN pip install -U pip setuptools wheel && \
    pip install --no-cache-dir -r ${REQUIREMENTS_FILE} && \
    if [ -n "${EXTRA_REQUIREMENTS}" ]; then \
        for req in ${EXTRA_REQUIREMENTS}; do \
            echo "==> Installing extras from ${req}"; \
            pip install --no-cache-dir -r "${req}"; \
        done; \
    fi

# Production stage — same digest pin as the builder stage above.
FROM python:3.12-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# Set working directory
WORKDIR /app

# Install runtime dependencies + tini for proper PID 1 signal handling.
# bash is needed because: (a) the certmate user is created with /bin/bash as
# its login shell on the line below, and (b) operator-provided deploy hooks
# routinely start with `#!/bin/bash` — without bash the kernel cannot resolve
# the shebang and the script returns exit 127 (issue #207).
# apt-get upgrade pulls security patches for glibc, zlib, etc.
RUN apt-get update && \
    apt-get upgrade -y -o Acquire::Retries=3 && \
    apt-get install -y -o Acquire::Retries=3 bash curl tini && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --create-home --shell /bin/bash certmate

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY . .

# Create the runtime-writable directories and make them arbitrary-UID ready.
#
# Under rootless podman (issue #380, Rocky Linux) and OpenShift the container
# process is remapped and runs as an ARBITRARY UID that is NOT 1000 and is not
# present in /etc/passwd; that UID is, however, always a member of the root
# group (GID 0). Follow the OpenShift "arbitrary UID" pattern: give these trees
# group 0 and make them group-writable + setgid, so ANY such UID can create and
# rename files here, while the default USER 1000 (plain docker/compose) keeps
# working exactly as before. A named volume created from this image inherits
# these perms, so `--user <anyuid>:0` works out of the box.
#
# Security: this opens only the DIRECTORIES to the root group (mode 2770 — no
# world access). Every secret the app writes at runtime (CA private key,
# audit-signing key, DNS credential files, .secret_key) is created 0600
# owner-only in code, so directory group-write never exposes a key.
RUN mkdir -p /app/certificates /app/data /app/logs /app/backups /app/backups/unified && \
    chown -R certmate:certmate /app && \
    chgrp -R 0 /app/certificates /app/data /app/logs /app/backups && \
    chmod -R g=u /app/certificates /app/data /app/logs /app/backups && \
    chmod -R o-rwx /app/certificates /app/data /app/logs /app/backups && \
    find /app/certificates /app/data /app/logs /app/backups -type d -exec chmod g+s {} +

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app
# Configurable listen port (issue #80). Override with -e PORT=9000 or in .env.
ENV PORT=8000
# Gunicorn worker timeout in seconds. ACME DNS-01 challenges can take up to
# 5 minutes on slow providers (Namecheap, Infomaniak). Default: 300s.
ENV GUNICORN_TIMEOUT=300

# Switch to non-root user
USER certmate

# Expose port (documents the default; actual port is controlled by $PORT)
EXPOSE 8000

# Health check uses $PORT so it works when the port is overridden
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Use tini as init process for proper signal handling and zombie reaping
ENTRYPOINT ["tini", "--"]

# Run the application
# Single worker + threads: avoids duplicate APScheduler jobs and session
# sharing issues. CertMate is I/O-bound, not CPU-bound.
# 8 threads: SSE holds 1 thread per browser tab; 4 was too few.
# $PORT defaults to 8000 and can be overridden via environment variable.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout ${GUNICORN_TIMEOUT} --access-logfile - --error-logfile - --log-level info app:app"]
