#!/bin/sh
# Inject PG config for Railway Postgres
echo "$PG_SERVICE_CONF" > /home/appuser/.pg_service.conf

# Ensure Uv binaries are in PATH
export PATH="/home/appuser/.local/bin:$PATH"

# Start Gunicorn on Railway's dynamic port
exec gunicorn split_bill.wsgi:application --bind 0.0.0.0:$PORT
