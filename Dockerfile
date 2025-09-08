# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.13.2
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy Uv binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies globally as root
RUN uv sync --locked

# Add non-root user
ARG UID=10001
RUN adduser --disabled-password --gecos "" --home "/home/appuser" \
    --shell "/sbin/nologin" --uid "${UID}" appuser

# Create PG service config file
RUN mkdir -p /home/appuser && \
    touch /home/appuser/.pg_service.conf && \
    chown appuser:appuser /home/appuser/.pg_service.conf

# Copy project source code
COPY . .
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose Railway port
EXPOSE 8000

# Use wrapper script as ENTRYPOINT
ENTRYPOINT ["/app/start.sh"]
