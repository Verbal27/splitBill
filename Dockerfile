# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.13.2
FROM python:${PYTHON_VERSION}-slim as base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# ENV PATH="/root/.cargo/bin/:$PATH"

WORKDIR /app

# Optional: Install uv (if you're using it for dependencies)
# COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy and install requirements
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt


# Add non-root user
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

COPY .pg_service.conf /home/appuser/.pg_service.conf
RUN chown appuser:appuser /home/appuser/.pg_service.conf
# Copy source code
COPY . .

# Permissions and switch to non-root user
# RUN chmod -R 775 /usr/local
RUN chown appuser:appuser /home/appuser/.pg_service.conf
USER appuser

EXPOSE 8000
# Run the Django server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
