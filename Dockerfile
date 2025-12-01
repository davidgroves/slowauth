# Stage 1: Builder
FROM python:3.13-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
RUN chmod +x /usr/local/bin/uv && uv --version

# Set working directory
WORKDIR /build

# Copy project files
COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/

# Install dependencies using uv pip install (non-editable for Docker)
RUN uv pip install --system .

# Stage 2: Runtime
FROM python:3.13-slim

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ /app/src/

# Set working directory
WORKDIR /app

# Expose DNS port (UDP and TCP) - default 55533, can be overridden via SLOWAUTH_PORT
EXPOSE 55533/udp 55533/tcp

# Set environment variable (can be overridden)
ENV SLOWAUTH_DOMAIN=""

# Run the DNS server
CMD ["python", "-m", "slowauth.server"]

