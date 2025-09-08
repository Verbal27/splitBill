# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.13.2
FROM python:${PYTHON_VERSION}-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install build dependencies for psycopg / Pillow etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy uv binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files and install via uv
COPY pyproject.toml uv.lock ./
RUN uv sync --locked

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

# Add Uv-installed packages to PATH so gunicorn is found
ENV PATH="/home/appuser/.local/bin:${PATH}"

# At container startup, inject PG config
ENTRYPOINT ["/bin/sh", "-c", "echo \"$PG_SERVICE_CONF\" > /home/appuser/.pg_service.conf && exec \"$@\"", "--"]

# Expose the port Railway provides
EXPOSE 8000

# Start Gunicorn on the Railway port
CMD ["gunicorn", "split_bill.wsgi:application", "--bind", "0.0.0.0:$PORT"]
