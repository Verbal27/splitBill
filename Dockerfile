# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.13.2
FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy Uv binary first so we can use it in RUN commands
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies globally using Uv
RUN uv sync --locked --system

# Add non-root user
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/home/appuser" \
    --shell "/sbin/nologin" \
    --uid "${UID}" \
    appuser

# Create PG service config file
RUN mkdir -p /home/appuser && \
    touch /home/appuser/.pg_service.conf && \
    chown appuser:appuser /home/appuser/.pg_service.conf

# Copy project source code
COPY . .
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Add Uv’s global bin path to PATH
ENV PATH="/home/appuser/.local/bin:/usr/local/bin:/bin:/usr/bin:${PATH}"

# Inject PG config at startup
ENTRYPOINT ["/bin/sh", "-c", "echo \"$PG_SERVICE_CONF\" > /home/appuser/.pg_service.conf && exec \"$@\"", "--"]

# Expose Railway port
EXPOSE 8000

# Start Gunicorn
CMD ["gunicorn", "split_bill.wsgi:application", "--bind", "0.0.0.0:$PORT"]
