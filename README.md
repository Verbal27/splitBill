# SplitBill API

A REST API for splitting shared expenses among groups. Create a bill, add members, log expenses with equal, custom, or percentage-based splits, track direct payments, and get automatic balance calculations.

**Production:** `https://splitbill-production.up.railway.app`

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Running with Docker](#running-with-docker)
- [API Overview](#api-overview)
- [Authentication](#authentication)
- [Known Issues](#known-issues)

---

## Features

- **User registration & activation** via email (Mailgun)
- **JWT authentication** with access/refresh token flow
- **Split bills** — group expenses with a flexible member model (registered users, email invitees, or alias-only offline members)
- **Three split strategies** — equal share, custom amounts, percentage-based
- **Automatic balance calculation** — net debts between pairs of members are computed and stored after every change
- **Money given** — record direct payments between members to track debt settlement
- **Comments** — members can annotate a split bill
- **OpenAPI schema** — auto-generated via drf-spectacular, available as Swagger UI and ReDoc

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Django 5.2.4 + Django REST Framework 3.16 |
| Language | Python 3.13 |
| Database | PostgreSQL (psycopg3 + dj-database-url) |
| Authentication | JWT — djangorestframework-simplejwt |
| Email | Mailgun HTTP API |
| API Schema | drf-spectacular (OpenAPI 3.0) |
| Deployment | Railway (Gunicorn via Procfile) |
| Container | Docker (multi-stage, non-root user) |
| Dependency management | uv |

---

## Project Structure

```
splitBill/
├── apps/
│   ├── api/                  # Main app
│   │   ├── models.py         # SplitBill, Expense, Balance, etc.
│   │   ├── views.py          # All API views
│   │   ├── serializers.py    # Request/response serializers
│   │   ├── urls.py           # App URL routing
│   │   ├── utils.py          # Balance engine, permissions, Mailgun helper
│   │   └── tokens.py         # Account activation token generator
│   └── sb_app/               # Minimal entry point app
├── split_bill/
│   ├── settings.py
│   ├── urls.py               # Root URL conf (includes schema endpoints)
│   └── wsgi.py
├── tests/
│   └── test_api.py           # Integration test script
├── Dockerfile
├── Procfile
├── pyproject.toml
├── schema.yml                # Pre-generated OpenAPI schema
└── start.sh                  # Entrypoint: migrate + gunicorn
```

---

## Getting Started

**Requirements:** Python 3.13, PostgreSQL, a Mailgun account

### 1. Clone and install dependencies

```bash
git clone <repo-url>
cd splitBill

# Install uv if you don't have it
pip install uv

# Install all dependencies
uv sync
```

### 2. Configure environment variables

Copy the example below into a `.env` file (see [Environment Variables](#environment-variables)):

```bash
DATABASE_URL=postgresql://user:password@localhost:5432/splitbill
MAILGUN_DOMAIN=mg.yourdomain.com
MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxx
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
SECRET_KEY=your-django-secret-key
```

### 3. Apply migrations

```bash
python manage.py migrate
```

### 4. Create a superuser (optional)

```bash
python manage.py createsuperuser
```

### 5. Run the development server

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/apps/api/`.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `MAILGUN_DOMAIN` | ✅ | Your Mailgun sending domain |
| `MAILGUN_API_KEY` | ✅ | Mailgun private API key |
| `DEFAULT_FROM_EMAIL` | ✅ | From address for outbound emails |
| `SECRET_KEY` | ✅ | Django secret key — **must be set in production** |

> ⚠️ `SECRET_KEY` is currently hardcoded in `settings.py` with an insecure value. Override it via environment variable before any production deployment.

---

## Running with Docker

```bash
# Build
docker build -t splitbill .

# Run
docker run \
  -e DATABASE_URL=postgresql://user:pass@host/db \
  -e MAILGUN_DOMAIN=mg.yourdomain.com \
  -e MAILGUN_API_KEY=key-xxx \
  -e DEFAULT_FROM_EMAIL=noreply@yourdomain.com \
  -p 8000:8000 \
  splitbill
```

The container runs as a non-root user, auto-runs `python manage.py migrate` on startup, then starts Gunicorn on port 8000.

---

## API Overview

All endpoints are prefixed with `/apps/api/`. Full details in [API_REFERENCE.md](./API_REFERENCE.md).

| Group | Endpoints |
|---|---|
| Auth | Register, activate, login (token), refresh, password reset |
| Users | Get profile, update profile |
| Split Bills | Create, list, retrieve, update, delete |
| Members | Add, remove, update alias/email |
| Expenses | Create (equal / custom / percentage), list, detail, update, delete |
| Money Given | Record payment, list, detail, delete |
| Balances | List active balances, settle a balance |
| Comments | Post a comment |

### Interactive docs

- Swagger UI: `/apps/api/schema/swagger-ui/`
- ReDoc: `/apps/api/schema/redoc/`
- Raw OpenAPI schema: `/apps/api/schema/`

---

## Authentication

The API uses JWT. Obtain tokens via `POST /apps/api/token/`:

```bash
curl -X POST https://splitbill-production.up.railway.app/apps/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "mypassword"}'
```

Pass the access token in the `Authorization` header for all protected requests:

```
Authorization: Bearer <access_token>
```

Token lifetimes: **access = 15 min**, **refresh = 1 day**.

---

## Known Issues

| Issue | Impact |
|---|---|
| `SECRET_KEY` hardcoded in `settings.py` | Security risk in production |
| Mailgun errors during registration return HTTP 500, leaving the user with `is_active=False` | User exists but cannot log in |
| Duplicate URL name `expense-detail` for two different routes | `reverse()` for GET/DELETE expense will resolve to the update URL |
| `CORS_ALLOWED_ORIGIN_REGEXES` contains a plain string (not a regex) for the Railway domain | CORS may fail for production frontend requests |
| `SplitBillSerializer.get_balances()` triggers a DB write on every GET | Unexpected side effects on read requests |
