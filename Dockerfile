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

# Copy Uv binary so we can use it
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files and install packages globally
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --system

# Add non-root user
ARG UID=10001
RUN adduser --disabled-password --gecos "" --home "/home/appuser" \
    --shell "/sbin/nologin" --uid "${UID}" appuser

# Create PG service config file
RUN mkdir -p /
