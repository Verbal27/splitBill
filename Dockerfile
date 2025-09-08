# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.13.2
FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy project files first (for caching dependencies)
COPY pyproject.toml uv.lock ./

# Install Gunicorn system-wide + Uv dependencies
RUN pip install --no-cache-dir gunicorn && uv sync --locked --system

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

# Inject PG config at startup
ENTRYPOINT ["/bin/sh", "-c", "echo \"$PG_SERVICE_CONF\" > /home/appuser/.pg_service.conf && exec \"$@\"", "--"]

EXPOSE 8000

# Start Gunicorn (now system-wide, so it will always be found)
CMD ["gunicorn", "split_bill.wsgi:application", "--bind", "0.0.0.0:$PORT"]
