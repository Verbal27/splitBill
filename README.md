# SplitBill - Expense Sharing API

A Django REST Framework application for managing shared expenses among groups. Users can create split bills, add expenses with various splitting methods (equal, percentage, custom), track payments, and view balances.

## Features

- **User Authentication**: JWT-based authentication with registration, login, and password reset
- **Split Bill Management**: Create and manage expense-sharing sessions
- **Flexible Expense Splitting**: 
  - Equal split among participants
  - Percentage-based distribution
  - Custom amount allocation
- **Member Management**: Add registered users or invite via email
- **Balance Tracking**: Automatic calculation of who owes whom
- **Payment Recording**: Track money transfers between members
- **Comments**: Add notes and discussions to split bills

## Tech Stack

- **Backend**: Django 5.2.4, Django REST Framework 3.16.0
- **Database**: PostgreSQL (via psycopg 3.2.9)
- **Authentication**: JWT (djangorestframework-simplejwt)
- **Email**: Mailgun integration for invitations
- **API Documentation**: drf-spectacular (OpenAPI/Swagger)
- **Package Manager**: uv

## Project Structure

```
splitBill/
├── apps/
│   └── api/              # Main API application
│       ├── models.py     # Data models (SplitBill, Expense, Balance, etc.)
│       ├── serializers.py # DRF serializers
│       ├── views.py      # API endpoints
│       ├── urls.py       # URL routing
│       └── utils.py      # Helper functions (email, balance calculation)
├── split_bill/           # Django project settings
│   ├── settings.py       # Configuration
│   └── urls.py           # Root URL configuration
├── manage.py             # Django management script
├── pyproject.toml        # Project dependencies (uv)
└── .env                  # Environment variables
```

## Installation

### Prerequisites

- Python 3.13
- PostgreSQL database
- Mailgun account (for email invitations)

### Setup Steps

1. **Clone the repository**
   ```bash
   cd /Users/ionganea/Documents/Projects/PythonProjects/splitBill
   ```

2. **Create and activate virtual environment**
   ```bash
   python3.13 -m venv .venv
   source .venv/bin/activate  # On macOS/Linux
   # or
   .venv\Scripts\activate     # On Windows
   ```

3. **Install dependencies**
   ```bash
   # Using uv (recommended)
   uv sync
   
   # Or using pip
   pip install -e .
   ```

4. **Configure environment variables**
   
   Create a `.env` file in the project root:
   ```env
   DATABASE_URL=postgresql://user:password@localhost:5432/splitbill
   MAILGUN_DOMAIN=your-mailgun-domain
   MAILGUN_API_KEY=your-mailgun-api-key
   DEFAULT_FROM_EMAIL=noreply@yourdomain.com
   ```

5. **Run database migrations**
   ```bash
   python manage.py migrate
   ```

6. **Create a superuser (optional)**
   ```bash
   python manage.py createsuperuser
   ```

7. **Run the development server**
   ```bash
   python manage.py runserver
   ```

   The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: `http://localhost:8000/api/schema/swagger-ui/`
- **ReDoc**: `http://localhost:8000/api/schema/redoc/`
- **OpenAPI Schema**: `http://localhost:8000/api/schema/`

## Key API Endpoints

### Authentication
- `POST /api/register/` - Register new user
- `POST /api/login/` - Login (returns JWT tokens)
- `POST /api/token/refresh/` - Refresh access token
- `POST /api/reset-password/` - Request password reset
- `POST /api/set-new-password/` - Set new password

### Split Bills
- `GET /api/split-bills/` - List all split bills
- `POST /api/split-bills/` - Create new split bill
- `GET /api/split-bills/{id}/` - Get split bill details
- `PATCH /api/split-bills/{id}/` - Update split bill
- `DELETE /api/split-bills/{id}/` - Delete split bill

### Expenses
- `POST /api/split-bills/{id}/expenses/equal/` - Add equal split expense
- `POST /api/split-bills/{id}/expenses/custom/` - Add custom split expense
- `POST /api/split-bills/{id}/expenses/percentage/` - Add percentage split expense
- `PATCH /api/expenses/{id}/` - Update expense split type
- `DELETE /api/expenses/{id}/` - Delete expense

### Members
- `POST /api/split-bills/{id}/add-member/` - Add member to split bill
- `POST /api/split-bills/{id}/remove-member/` - Remove member
- `PATCH /api/members/{id}/` - Update member details

### Payments
- `POST /api/money-given/` - Record payment between members
- `GET /api/money-given/` - List all payments

## Data Models

### SplitBill
Main container for shared expenses
- `title`: Name of the split bill
- `owner`: User who created it
- `members`: Registered users participating
- `currency`: Currency code (e.g., "USD")
- `active`: Whether the bill is still active

### Expense
Individual expense entry
- `title`: Description of expense
- `amount`: Total amount
- `split_type`: "equal", "percentage", or "custom"
- `paid_by`: User who paid
- `split_bill`: Associated split bill
- `date`: Date of expense

### ExpenseAssignment
Links expenses to members with their share
- `expense`: Related expense
- `split_bill_member`: Member responsible for this share
- `user`: Registered user (if member is registered)
- `share_amount`: Amount this member owes

### Balance
Calculated balances between members
- `from_member`: Member who owes
- `to_member`: Member who is owed
- `amount`: Amount owed
- `active`: Whether balance is still outstanding

## Development

### Running Tests
```bash
python manage.py test
```

### Code Quality
The project uses:
- **Ruff**: For linting and formatting
- **Pre-commit hooks**: Configured in `.pre-commit-config.yaml`

Install pre-commit hooks:
```bash
pre-commit install
```

### Database Management

**Create migrations after model changes:**
```bash
python manage.py makemigrations
```

**Apply migrations:**
```bash
python manage.py migrate
```

**View migration status:**
```bash
python manage.py showmigrations
```

## Deployment

The application is configured for deployment on Railway with:
- Docker support (see `Dockerfile` and `compose.yaml`)
- Gunicorn WSGI server
- PostgreSQL database
- Environment-based configuration

Production URL: `https://django.splitbills.org`

## IDE Configuration

### VS Code
1. Open Command Palette (`Cmd+Shift+P`)
2. Select "Python: Select Interpreter"
3. Choose `.venv/bin/python`

### PyCharm
1. Go to Preferences → Project → Python Interpreter
2. Add Interpreter → Existing
3. Select `/path/to/splitBill/.venv/bin/python`

## Troubleshooting

### Import errors for Django modules
Ensure your IDE is using the correct Python interpreter from `.venv`. Django is installed in the virtual environment, not globally.

### Database connection issues
Verify your `DATABASE_URL` in `.env` is correct and PostgreSQL is running.

### Email not sending
Check your Mailgun credentials in `.env` and ensure the domain is verified.

## License

[Add your license information here]

## Contributors

[Add contributor information here]
