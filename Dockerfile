# Multi-stage build for optimized image size and faster builds.
# Base image pinned by sha256 digest (not just the tag): the tag is a
# moving target on Docker Hub, the digest is content-addressed and
# guarantees byte-identical bytes. Bump deliberately when there's a
# CVE fix or feature reason — not implicitly on every rebuild.
# Nothing moves the pin by itself, so `scripts/release.sh prepare` refuses a
# release whose pin is behind the tag and older than two weeks
# (scripts/check_base_image.py; `--update` writes the current digest).
FROM python:3.12-slim-trixie@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS builder

# Set working directory for build stage
WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y -o Acquire::Retries=3 gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy every requirements*.txt so REQUIREMENTS_FILE and EXTRA_REQUIREMENTS
# can point at any of the optional sets (storage backends, cloud DNS,
# extended providers, …) without rebuilding the COPY layer for each one.
# The .lock files are the fully resolved sets for the two main variants, with
# hashes; the .constraints files are their pins without hashes, for the extras
# layer. See the install step below and scripts/regenerate_lockfiles.sh.
COPY requirements*.txt requirements*.lock requirements*.constraints ./

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
# The venv's tools come from requirements-build.lock: pip, setuptools, wheel and
# packaging, each with the hashes of its files.
#
# pip here used to be a bare `pip install -U pip`, so the pin defended the copy
# nobody uses: `ENV PATH` puts /opt/venv/bin first, and on the published v2.25.4
# image /usr/local/bin/pip was the pinned 26.1.2 while /opt/venv/bin/pip, the one
# `pip` resolves to, was 26.2.1. Then it became `pip==X -U setuptools wheel`,
# which pinned pip and left setuptools, wheel and packaging to whatever the
# index served on build day. A comment here said those "never reach the runtime
# stage"; they do, because the runtime stage copies /opt/venv, and the published
# 2.48.1 image carries wheel 0.48.0 and packaging 26.3. They are locked now, at
# exactly those versions, and the runtime stage's PIP_VERSION must equal the pip
# pin in requirements-build.txt (a test holds the two together).
#
# shellcheck disable=SC2086 — intentional word-splitting to iterate the list.
#
# The base install reads the LOCKFILE when the chosen variant has one, because
# `requirements.txt` pins 42 packages and resolves to 118: the other 76 were
# whatever the index served on build day, and two images built from one commit
# a month apart were not the same image. `requirements.lock` and
# `requirements-minimal.lock` record the full resolution, resolved by uv for the
# two published architectures (scripts/regenerate_lockfiles.sh), with the
# sha256 of every file the index publishes for each version. pip installs them
# with --require-hashes: a file that is not one of those is refused, so a
# re-published or substituted wheel at a pinned version stops the build instead
# of shipping. A variant without a lock (the optional-DNS and storage sets)
# installs from its .txt exactly as before, so nothing here narrows what can be
# built.
#
# The extras layer is constrained, and that is load-bearing, not tidiness
# (#686). Each extras install is a separate pip resolution that knows nothing
# about what the first one pinned, so it is free to move those pins. Measured,
# not theorised: with the base stack installed, `pip install "cryptography<46"`
# as a second layer silently downgraded 46.0.7 to 45.0.7, below the floor the
# pinned pyopenssl needed, and the image shipped an interpreter where
# `certbot --version` no longer answered. The extras files carry unbounded `>=`
# requirements (azure-identity, boto3, azure-keyvault-*), so a future release
# of any of them could reach the same edge. With the constraint pip refuses at
# build time and names the conflict.
#
# The constraint is the .constraints file, not the lock: the same pins, without
# hashes. pip turns hash checking on for a whole install when any line in it
# carries a hash, constraints included, so `-c requirements.lock` would refuse
# every unhashed package an extras file brings. Each pip call below is therefore
# fully hashed (the tools, the lock) or not hashed at all (the extras), never
# half (SECURITY.md, "Supply-chain posture"). Every documented combination
# above resolves under the constraint, and CI checks that on every run.
#
# Freezing transitives means a lock can age into a known-vulnerable package. It
# does not go unnoticed: scripts/check_resolved_advisories.py queries OSV for
# the set actually installed in the built image, and it is a required check.
RUN pip install --no-cache-dir --require-hashes -r requirements-build.lock && \
    LOCKFILE="${REQUIREMENTS_FILE%.txt}.lock"; \
    CONSTRAINTS="${REQUIREMENTS_FILE%.txt}.constraints"; \
    if [ -f "${LOCKFILE}" ]; then \
        echo "==> Installing from ${LOCKFILE}, hashes required" && \
        pip install --no-cache-dir --require-hashes -r "${LOCKFILE}"; \
    else \
        echo "==> ${REQUIREMENTS_FILE} has no lock: installing it unlocked" && \
        CONSTRAINTS="${REQUIREMENTS_FILE}" && \
        pip install --no-cache-dir -r "${REQUIREMENTS_FILE}"; \
    fi && \
    if [ -n "${EXTRA_REQUIREMENTS}" ]; then \
        for req in ${EXTRA_REQUIREMENTS}; do \
            echo "==> Installing extras from ${req}"; \
            pip install --no-cache-dir -c "${CONSTRAINTS}" -r "${req}"; \
        done; \
    fi

# Production stage — same digest pin as the builder stage above.
FROM python:3.12-slim-trixie@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# Set working directory
WORKDIR /app

# Install runtime dependencies + tini for proper PID 1 signal handling.
# bash is needed because: (a) the certmate user is created with /bin/bash as
# its login shell on the line below, and (b) operator-provided deploy hooks
# routinely start with `#!/bin/bash` — without bash the kernel cannot resolve
# the shebang and the script returns exit 127 (issue #207).
#
# No `apt-get upgrade` here, deliberately. It upgraded EVERY package in the
# image to whatever the mirror served at that moment, so the whole OS layer
# varied build to build — contradicting, in the same RUN instruction, the
# reproducibility rationale written below for pinning pip and above for
# pinning the base image by digest.
#
# One named exception to that, and it is named on purpose. The base image
# carries perl-base 5.40.1-6, against which three CRITICAL advisories are
# fixable today:
#
#   CVE-2026-13221  incorrect regular expression processing
#   CVE-2026-8376   heap buffer overflow when compiling a regular expression
#   CVE-2026-42496  path traversal in perl-archive-tar
#
# All three are fixed in 5.40.1-6+deb13u1, which trixie/main already serves.
# The normal channel for an OS patch here is a base-image digest bump, and
# that channel is closed: the pinned digest IS the current
# python:3.12-slim-trixie, so there is nothing to bump to until upstream
# rebuilds. Meanwhile the `Fail on a fixable CRITICAL` gate in
# docker-multiplatform.yml is red on every pull request, which is the gate
# doing its job.
#
# `--only-upgrade perl-base` keeps the variance bounded and named, which is
# the same property the paragraph above is protecting: one package, stated
# here, visible in the diff. It becomes a no-op the moment the base image
# carries >= 5.40.1-6+deb13u1, and the line should be removed then rather
# than left to accumulate.
#
# Be precise about what this buys, because it is not full reproducibility:
# `apt-get install` below is still unpinned, so the three packages it names can
# differ between builds. What changes is that the variance goes from unbounded
# (every package in the image) to bounded (three named ones). Pinning those
# versions too would break on every base-image bump, and a genuinely
# reproducible OS layer needs a snapshot mirror — a separate trade, not this
# one.
#
# OS security patches now arrive the way every other dependency does: as a
# base-image digest bump. Dependabot watches the docker ecosystem weekly and
# ignores only python's semver-major/minor, so digest updates are proposed as
# reviewable PRs — auditable and tied to a commit, rather than an invisible
# build-time upgrade. The cost is real: a digest bump has to actually be merged
# when one lands (#659).
#
# The pip upgrade is this stage's, not the builder's. The builder already runs
# `pip install -U pip`, but that only patches the BUILDER's interpreter — the
# runtime stage starts from the same base image with its own bundled pip under
# /usr/local/lib/python3.12/site-packages, which nothing touched. That stale
# copy is what the Trivy scan keeps reporting (CVE-2026-8643, CVE-2026-6357,
# CVE-2026-3219 against pip 25.0.1); the app itself runs from /opt/venv and
# never uses it. See issue #403.
#
# 26.2.1 fixes CVE-2026-13346 in pip itself. It was held at 26.1.2 for a
# while, on the measurement that a scan of the image found more with 26.2.1
# than without, the extra findings being in msgpack 1.1.2 and setuptools
# 70.3.0, "which 26.2.1 vendors". The count was right and the reason was not.
# 26.1.2 vendors the same msgpack 1.1.2 and setuptools 70.3.0
# (pip/_vendor/vendor.txt lists both, and msgpack/fallback.py and
# pkg_resources/__init__.py are byte-identical in the two wheels). What 26.2.1
# adds is pip/_vendor/bom.cdx.json, a CycloneDX list of what it vendors, and
# the scanner reads that. The hold did not avoid those findings: it kept them
# unreported, and kept the CVE.
#
# Measured on 2026-10-05, Trivy 0.70.0 on the image and OSV on each vendored
# version. Known vulnerabilities in pip and what it vendors: 11 in 26.1.2 (its
# own, 5 in urllib3 2.6.3, 1 in idna 3.11, 1 in pygments 2.19.2, 1 in msgpack,
# 2 in setuptools), of which the scan saw one; 6 in 26.2.1 (3 in urllib3
# 2.7.0, msgpack, setuptools), all of which it sees. So the image's count goes
# from 254 to 258 while what is actually there goes down (#403). pip is not
# used at runtime; it runs when the image is built.
#
# Pinned, for the same reason the base image is pinned by digest a few lines
# up: an unpinned `--upgrade pip` would make the runtime stage's contents
# depend on whatever PyPI happens to serve at build time, so two builds of the
# same commit could differ. Bump this deliberately when a pip CVE lands.
ARG PIP_VERSION=26.2.1
RUN apt-get update && \
    apt-get install -y -o Acquire::Retries=3 bash curl tini && \
    apt-get install -y -o Acquire::Retries=3 --only-upgrade perl-base && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir "pip==${PIP_VERSION}" && \
    useradd --create-home --shell /bin/bash certmate

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code.
#
# An allowlist, not `COPY . .` plus a .dockerignore denylist. The denylist
# worked the way denylists do: the published image carried a 188K licensing
# PDF, an 856K demo directory, the Helm chart, the client SDK sources, the MCP
# server, the monitoring dashboards, seven build and test shell scripts, and
# pytest's own configuration — none of which the runtime reads, all of which
# are either build-time (already consumed by the builder stage) or separate
# deliverables published on their own channels. A denylist ships whatever
# nobody remembered to add to it, and the thing nobody remembers is always the
# thing that arrived last.
#
# What is here is what the running process actually touches:
#   app.py, modules/, templates/, static/  the application
#   two files from scripts/                solidserver_hook.py is executed by
#                                          the SolidServer DNS strategy
#                                          (modules/core/dns_strategies.py);
#                                          reset_admin_password.py is the
#                                          documented in-container recovery
#                                          (README, and the login page points
#                                          at it by name)
#   requirements*.txt                      two error paths tell the operator to
#                                          install one of these into a running
#                                          container to add a DNS or storage
#                                          backend
#
# scripts/ is copied BY NAME, not as a directory. It was `COPY scripts/`, which
# put the other twelve files in the image: release.sh with the whole release
# procedure, regenerate_lockfiles.sh, five check_*.py gates, the theme codemod,
# the walkthrough recorder. All build-time, none read by the running process —
# which is the same defect the allowlist above was written to fix, surviving one
# directory further down because the allowlist named a directory.
#
# tests/test_image_ships_only_what_it_runs.py checks this against the built
# image rather than against this comment.
COPY app.py ./
COPY requirements*.txt requirements*.lock requirements*.constraints ./
COPY modules/ ./modules/
COPY templates/ ./templates/
COPY static/ ./static/
COPY scripts/solidserver_hook.py scripts/reset_admin_password.py ./scripts/

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

# Health check uses $PORT so it works when the port is overridden.
#
# start-period is 40s to match docker-compose.yml, which has said 40s since it
# was written while this said 5s. Measured: a container reaches its first
# healthy /health in about 7 seconds on a warm host, so 5s was already shorter
# than a normal boot — and a shorter start-period buys nothing, it only makes
# a failing check start counting against --retries sooner. The margin is for
# the runs that are not warm: a cold image, a settings migration, a slow
# volume.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Use tini as init process for proper signal handling and zombie reaping
ENTRYPOINT ["tini", "--"]

# Run the application
# Single worker + threads: avoids duplicate APScheduler jobs and session
# sharing issues. CertMate is I/O-bound, not CPU-bound.
# 8 threads: SSE holds 1 thread per browser tab; 4 was too few.
# $PORT defaults to 8000 and can be overridden via environment variable.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout ${GUNICORN_TIMEOUT} --access-logfile - --error-logfile - --log-level info app:app"]
