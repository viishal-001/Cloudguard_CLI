# Multi-stage Dockerfile for CloudGuard
# Per @docker-expert skill: multi-stage build, non-root user, minimal image

# --- Builder stage ---
FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml ./
COPY cloudguard/ ./cloudguard/

RUN pip install --no-cache-dir --prefix=/install .

# --- Runtime stage ---
FROM python:3.11-slim AS runtime

LABEL maintainer="CloudGuard Team"
LABEL description="CloudGuard AWS Security Scanner"
LABEL version="0.1.0"

# Security: non-root user
RUN groupadd -g 1001 cloudguard && \
    useradd -r -u 1001 -g cloudguard cloudguard

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local
COPY --from=builder /build/cloudguard ./cloudguard

# Switch to non-root
USER cloudguard

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD cloudguard --version || exit 1

ENTRYPOINT ["cloudguard"]
CMD ["--help"]
