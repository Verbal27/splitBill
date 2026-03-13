# SplitBill API

A REST API for splitting shared expenses among groups. Create a bill, add members, log expenses with equal, custom, or percentage-based splits, track direct payments, and get automatic balance calculations.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Database Configuration](#database-configuration)
- [Running with Docker](#running-with-docker)
- [API Overview](#api-overview)
- [Authentication](#authentication)

---

## Features

- **User registration & email activation** via Mailgun
- **JWT authentication** with access/refresh token flow
- **Split bills** — flexible member model supporting registered users, email invitees, and alias-only offline members
- **Pending invitation flow** — invite by email before the person registers; membership resolves automatically on sign-up
- **Three split strategies** — equal share, custom amounts, percentage-based
- **Automatic balance calculation** — net debts between member pairs computed and stored after every change
- **Money given** — record direct payments between members to track settlement
- **Comments** — members can annotate a split bill
- **OpenAPI schema** — auto-generated via drf-spectacular, available as Swagger UI and ReDoc

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Django 5.2.4 + Django REST Framework 3.16 |
| Language | Python 3.13 |
| Database | PostgreSQL (psycopg3) — `DATABASE_URL` or `pg_service` |
| Authentication | JWT — djangorestframework-simplejwt |
| Email | Mailgun HTTP API |
| API Schema | drf-spectacular (OpenAPI 3.0) |
| Deployment | Railway (Gunicorn via `Procfile`) |
| Container | Docker (non-root user, uv-based) |
| Dependency manager | [uv](https://github.com/astral-sh/uv) |

---

## Project Structure

```
splitBill/
├── apps/
│   ├── api/                        # Main application
│   │   ├── models.py               # SplitBill, Expense, Balance, MoneyGiven, etc.
│   │   ├── views.py                # All API views
│   │   ├── serializers.py          # Request/response serialization and validation
│   │   ├── urls.py                 # App-level URL routing
│   │   ├── utils.py                # Balance engine, permission classes, Mailgun helper
│   │   ├── tokens.py               # Account activation token generator
│   │   └── migrations/             # 4 migrations (initial → balance)
│   └── sb_app/                     # Minimal stub app (index view only)
├── split_bill/
│   ├── settings.py                 # Project settings
│   ├── urls.py                     # Root URL conf — mounts /api/ and schema endpoints
│   └── wsgi.py
├── tests/
│   └── test_api.py                 # Manual integration test script
├── Dockerfile
├── Procfile                        # gunicorn start command for Railway
├── start.sh                        # Entrypoint: pg_service inject → migrate → gunicorn
├── pyproject.toml                  # Dependencies managed with uv
└── schema.yml                      # Pre-generated OpenAPI schema
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

# Install all project dependencies
uv sync
```

### 2. Configure the database

The project supports two methods — use whichever fits your environment:

**Option A — `DATABASE_URL` (recommended for cloud/CI):**

Set the `DATABASE_URL` environment variable (see [Environment Variables](#environment-variables)). When present, this takes priority automatically.

**Option B — `pg_service` (local dev):**

Create `~/.pg_service.conf`:

```ini
[my_db]
host=localhost
port=5432
dbname=splitbill
user=youruser
password=yourpassword
```

### 3. Set environment variables

Create a `.env` file in the project root:

```bash
SECRET_KEY=your-django-secret-key
MAILGUN_DOMAIN=mg.yourdomain.com
MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxx
DEFAULT_FROM_EMAIL=noreply@yourdomain.com

# Optional — cloud/CI deployments
DATABASE_URL=postgresql://user:password@host:5432/splitbill
ALLOWED_HOST=yourdomain.com
```

### 4. Apply migrations

```bash
python manage.py migrate
```

### 5. (Optional) Create a superuser

```bash
python manage.py createsuperuser
```

### 6. Run the development server

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/api/`.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | Django secret key — no default, server won't start without it |
| `MAILGUN_DOMAIN` | ✅ | Your Mailgun sending domain (e.g. `mg.yourdomain.com`) |
| `MAILGUN_API_KEY` | ✅ | Mailgun private API key |
| `DEFAULT_FROM_EMAIL` | ✅ | Sender address for all outbound emails |
| `DATABASE_URL` | ⬜ | PostgreSQL connection string — takes priority over `pg_service` when set |
| `ALLOWED_HOST` | ⬜ | Production hostname appended to `ALLOWED_HOSTS` at startup |

---

## Database Configuration

Settings automatically selects the database backend based on what's available:

```python
if DATABASE_URL:
    DATABASES = {"default": dj_database_url.config(default=DATABASE_URL)}
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "OPTIONS": {"service": "my_db", "passfile": ".pgpass"},
        }
    }
```

On Railway, `DATABASE_URL` is injected automatically by the Postgres plugin. The `start.sh` entrypoint also writes `PG_SERVICE_CONF` to `/home/appuser/.pg_service.conf` as a fallback for pg_service-based configs.

---

## Running with Docker

```bash
# Build
docker build -t splitbill .

# Run
docker run \
  -e SECRET_KEY=your-secret-key \
  -e DATABASE_URL=postgresql://user:pass@host:5432/splitbill \
  -e MAILGUN_DOMAIN=mg.yourdomain.com \
  -e MAILGUN_API_KEY=key-xxx \
  -e DEFAULT_FROM_EMAIL=noreply@yourdomain.com \
  -e ALLOWED_HOST=yourdomain.com \
  -p 8000:8000 \
  splitbill
```

The container runs as a non-root user, automatically runs `python manage.py migrate` on startup, then starts Gunicorn on `$PORT` (default 8000).

---

## API Overview

All endpoints are prefixed with `/api/`. Full request/response details in [API_REFERENCE.md](./API_REFERENCE.md).

| Group | Base path | Description |
|---|---|---|
| Auth | `/api/token/` | Obtain and refresh JWT tokens |
| Users | `/api/register/`, `/api/users/` | Register, activate, update profile, reset password |
| Split Bills | `/api/split-bill/` | Create and manage group bills |
| Members | `/api/split-bill/{id}/add-member/` | Add, remove, update members |
| Expenses | `/api/expenses/` | Create (equal / custom / percentage), update, delete |
| Money Given | `/api/money-given/` | Record and track direct payments |
| Balances | `/api/split-bill/{id}/balances/` | View net balances, mark as settled |
| Comments | `/api/comments/` | Post comments on a split bill |

### Interactive docs

| URL | Description |
|---|---|
| `/api/schema/` | Raw OpenAPI schema (YAML) |
| `/api/schema/swagger-ui/` | Swagger UI |
| `/api/schema/redoc/` | ReDoc |

---

## Authentication

The API uses JWT Bearer tokens. Obtain tokens via `POST /api/token/`:

```bash
curl -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "mypassword"}'
```

Pass the access token in the `Authorization` header on all protected requests:

```
Authorization: Bearer <access_token>
```

Token lifetimes: **access = 15 minutes**, **refresh = 1 day**.
