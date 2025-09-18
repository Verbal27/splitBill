#!/bin/sh
# Inject PG config for Railway Postgres
echo "$PG_SERVICE_CONF" > /home/appuser/.pg_service.conf

python manage.py migrate --noinput

# Start Gunicorn on Railway dynamic port
exec gunicorn split_bill.wsgi:application --bind 0.0.0.0:$PORT
