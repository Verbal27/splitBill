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

# --- FIX: copy dependency files BEFORE installing ---
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

# Copy PG service config
COPY .pg_service.conf /home/appuser/.pg_service.conf
RUN chown -R appuser:appuser /home/appuser

# Copy project source code
COPY . .
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uv", "run", "manage.py", "runserver", "0.0.0.0:8000"]