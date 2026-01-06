# Multi-stage build for optimized image size and faster builds
FROM python:3.11-slim AS builder

# Set working directory for build stage
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-minimal.txt ./
RUN ls -la

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install minimal requirements by default (fastest build)
# Override with --build-arg REQUIREMENTS_FILE=requirements.txt for full install
ARG REQUIREMENTS_FILE=requirements.txt
RUN pip install -U pip wheel && \
    pip install --no-cache-dir -r ${REQUIREMENTS_FILE}

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash certmate

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p certificates data logs backups && \
    chown -R certmate:certmate /app

# Ensure proper permissions for volume mounts
RUN chmod 755 /app/certificates /app/data /app/logs

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Switch to non-root user
USER certmate

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "360", "app:app"]
