# SplitBill — API Reference

**Base URL:** `http://localhost:8000` (development) — configure for production  
**API prefix:** `/api/`  
**Version:** 0.1.0  
**Authentication:** JWT Bearer token — see [Authentication](#authentication)

---

## Table of Contents

- [Authentication](#authentication)
- [Users](#users)
- [Split Bills](#split-bills)
- [Members](#members)
- [Expenses](#expenses)
- [Money Given](#money-given)
- [Balances](#balances)
- [Comments](#comments)
- [Schema & Docs](#schema--docs)
- [Error Reference](#error-reference)
- [Permissions Reference](#permissions-reference)
- [Typical Flows](#typical-flows)

---

## Authentication

### `POST /api/token/`

Obtain a JWT access + refresh token pair.

**Auth:** Public

**Request body:**
```json
{
  "username": "alice",
  "password": "mypassword"
}
```

**Response `200`:**
```json
{
  "access": "eyJhbGciOiJIUzI1NiIs...",
  "refresh": "eyJhbGciOiJIUzI1NiIs..."
}
```

Token lifetimes: **access = 15 minutes**, **refresh = 1 day**.

Use the access token in the `Authorization` header on all protected requests:
```
Authorization: Bearer <access_token>
```

---

### `POST /api/token/refresh/`

Exchange a refresh token for a new access token.

**Auth:** Public

**Request body:**
```json
{
  "refresh": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response `200`:**
```json
{
  "access": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## Users

### `POST /api/register/`

Create a new user account. The account is created as **inactive** (`is_active=False`). An activation email is sent via Mailgun. The user cannot log in until activation.

If the registered email matches any existing `PendingInvitation` records, those are resolved automatically — the new user is linked to the corresponding `SplitBillMember` entries and added to those split bills.

**Auth:** Public

**Request body:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "secure123"
}
```

**Validation:**
- `password` — minimum 8 characters
- `email` — must be unique across all users

**Response `201`:**
```json
{
  "detail": "Check your email to activate your account."
}
```

**Response `500`** — returned if Mailgun fails (user is created but cannot activate):
```json
{
  "detail": "Internal server error during registration.<error details>"
}
```

---

### `GET /api/activate/{uidb64}/{token}/`

Activate a user account from the link sent by email. Sets `is_active=True`.

> ⚠️ **Known bug:** This view's `get()` method is missing the `request` parameter in its signature (`def get(self, uidb64, token)`). It will raise a `TypeError` at runtime when called.

**Auth:** Public

**Response `200`:**
```json
{
  "detail": "Account activated successfully!"
}
```

**Response `400`:**
```json
{
  "detail": "Invalid or expired activation link."
}
```

---

### `POST /api/reset-password/`

Request a password reset email. Generates a signed token and sends it to the user's email address via Mailgun.

**Auth:** Public

**Request body:**
```json
{
  "email": "alice@example.com"
}
```

**Response `200`:**
```json
{
  "message": "Password reset link sent to your email."
}
```

**Response `400`** — email not found:
```json
{
  "email": "User with this email does not exist."
}
```

---

### `GET /api/reset-password-confirm/{uidb64}/{token}/`

Validate a password reset token before showing a reset form. Use the `uidb64` and `token` values from the emailed link.

> ⚠️ **Known bug:** This view's `get()` method is missing the `request` parameter (`def get(self, uidb64, token)`). It will raise a `TypeError` at runtime.

**Auth:** Public

**Response `200`:**
```json
{
  "message": "Token is valid"
}
```

**Response `400`:**
```json
{
  "error": "Token is invalid or expired"
}
```

---

### `POST /api/reset-password-complete/`

Set a new password using a valid reset token.

**Auth:** Public

**Request body:**
```json
{
  "uidb64": "MQ",
  "token": "bfqbwi-...",
  "password": "newpassword123"
}
```

**Validation:** `password` — minimum 8 characters

**Response `200`:**
```json
{
  "message": "Password has been reset successfully"
}
```

---

### `GET /api/users/`

Get the profile of the currently authenticated user.

**Auth:** JWT

**Response `200`:**
```json
{
  "id": 1,
  "username": "alice",
  "email": "alice@example.com"
}
```

---

### `PATCH /api/users/{id}/`

Update the authenticated user's username, email, or password. All fields are optional.

**Auth:** JWT

**Request body:**
```json
{
  "username": "alice_new",
  "email": "newemail@example.com",
  "password": "newpassword123"
}
```

**Response `200`:** Updated user object.

---

## Split Bills

A `SplitBill` is the top-level container for a shared expense group. The user who creates it becomes the **owner** and is automatically added as the first `SplitBillMember` (with their username as the alias).

---

### `GET /api/split-bill/`

List all split bills the authenticated user is a member of.

**Auth:** JWT

**Response `200`:** Array of split bill objects.

---

### `POST /api/split-bill/`

Create a new split bill. The creator is added as owner and first member automatically.

**Auth:** JWT

**Request body:**
```json
{
  "title": "Italy Trip 2025",
  "currency": "EUR",
  "member_inputs": [
    { "alias": "Bob" },
    { "alias": "Carol", "email": "carol@example.com" }
  ]
}
```

- `currency` — 3-character code (e.g. `"EUR"`, `"USD"`)
- `member_inputs` — optional array of members to add on creation. Each entry may include `alias`, `email`, or both.
  - If `email` matches a registered user → linked immediately
  - If `email` is unknown → a `PendingInvitation` is created and an invite email is sent
  - If only `alias` is provided → offline member, no invitation sent

**Response `201`:** Full split bill object (see structure below).

---

### `GET /api/split-bill/{id}/`

Retrieve full details of a split bill, including nested expenses, money given, comments, and active balances.

**Auth:** JWT + Member

**Response `200`:**
```json
{
  "id": 1,
  "title": "Italy Trip 2025",
  "date_created": "2025-09-20T10:00:00Z",
  "currency": "EUR",
  "active": true,
  "owner": {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com"
  },
  "members": [
    {
      "id": 1,
      "alias": "alice",
      "email": "alice@example.com",
      "user": { "id": 1, "username": "alice" }
    },
    {
      "id": 2,
      "alias": "Bob",
      "email": null,
      "user": null
    }
  ],
  "expenses": [ ],
  "money_given": [ ],
  "comments": [ ],
  "balances": [
    { "from": "Bob", "to": "alice", "amount": "45.00" }
  ]
}
```

---

### `PATCH /api/split-bill/{id}/`

Update a split bill's `title`, `currency`, or `active` flag.

**Auth:** JWT + Member

**Request body** (all fields optional):
```json
{
  "title": "Italy Trip — Final",
  "currency": "USD",
  "active": false
}
```

**Response `200`:** Updated split bill object.

---

### `DELETE /api/split-bill/{id}/`

Delete the split bill and all cascading data (expenses, members, balances, comments).

**Auth:** JWT + Member

**Response `204`:** No content.

---

## Members

### `POST /api/split-bill/{id}/add-member/`

Add a new member to a split bill.

**Auth:** JWT + Owner

**Request body:**
```json
{
  "alias": "Dave",
  "email": "dave@example.com"
}
```

- `alias` is required.
- `email` is optional. Resolution follows the same logic as `member_inputs` on creation.
- If the exact combination of `alias` + `email` already exists on this split bill, the existing member is returned without duplication.

**Response `201`:**
```json
{
  "detail": "Member added successfully",
  "member": {
    "id": 4,
    "alias": "Dave",
    "email": "dave@example.com",
    "user": null
  }
}
```

---

### `POST /api/split-bill/{id}/remove-member/`

Remove a member by alias and/or email. At least one of `alias` or `email` is required. If both are provided, both conditions must match.

**Auth:** JWT + Owner

**Request body:**
```json
{
  "alias": "Dave"
}
```

**Response `200`:**
```json
{
  "detail": "Removed member(s): Dave"
}
```

**Response `404`:**
```json
{
  "detail": "No member found with the provided alias/email."
}
```

---

### `PATCH /api/split-bill/{split_bill_id}/members/{id}/update/`

Update a member's `alias` or `email`.

**Auth:** JWT + Owner

**Request body** (at least one field):
```json
{
  "alias": "David",
  "email": "david@example.com"
}
```

- If the new `email` matches a registered user → the user is linked and added to `split_bill.members`
- If unregistered → a `PendingInvitation` is created or updated, and an invite email is sent

**Response `200`:** Updated `SplitBillMember` object.

---

## Expenses

Expenses belong to a split bill and carry a `split_type` that determines cost distribution. Three creation endpoints exist — one per strategy. After every create or update, balances are automatically recalculated for the parent split bill.

All three creation endpoints share these common fields:

| Field | Type | Notes |
|---|---|---|
| `title` | string | Expense label |
| `amount` | decimal | Total cost |
| `paid_by_member` | integer | `SplitBillMember` ID of who paid — must be a registered user |
| `split_bill` | integer | ID of the parent `SplitBill` |
| `date` | date | Optional — defaults to today |
| `assignments` | varies | Format depends on split type (see below) |

---

### `POST /api/expenses/equal/`

Create an expense split equally among selected members.

Each participant's share = `amount ÷ number_of_participants`, rounded to 2 decimal places.

**Auth:** JWT

**Request body:**
```json
{
  "title": "Dinner",
  "amount": 90.00,
  "paid_by_member": 1,
  "split_bill": 1,
  "assignments": [1, 2, 3]
}
```

`assignments` — list of `SplitBillMember` IDs to include in the split.

**Response `201`:** Created expense object.

---

### `POST /api/expenses/custom/`

Create an expense with explicit per-member amounts.

The sum of all assignment values must equal `amount` (±0.01 tolerance).

**Auth:** JWT

**Request body:**
```json
{
  "title": "Hotel",
  "amount": 200.00,
  "paid_by_member": 1,
  "split_bill": 1,
  "assignments": {
    "1": 100.00,
    "2": 60.00,
    "3": 40.00
  }
}
```

`assignments` — object mapping `SplitBillMember` ID (string key) → amount owed.

**Response `201`:** Created expense object.

---

### `POST /api/expenses/percentage/`

Create an expense split by percentage.

All percentages must sum to 100 (±0.01 tolerance). Each share is computed as `amount × pct ÷ 100`.

**Auth:** JWT

**Request body:**
```json
{
  "title": "Taxi",
  "amount": 50.00,
  "paid_by_member": 1,
  "split_bill": 1,
  "assignments": {
    "1": 50,
    "2": 30,
    "3": 20
  }
}
```

`assignments` — object mapping `SplitBillMember` ID (string key) → percentage.

**Response `201`:** Created expense object.

---

### `GET /api/expenses/`

List all expenses across all split bills the authenticated user belongs to.

**Auth:** JWT

**Response `200`:**
```json
[
  {
    "id": 1,
    "title": "Dinner",
    "amount": "90.00",
    "split_type": "equal",
    "date": "2025-09-20",
    "paid_by": {
      "id": 1,
      "alias": "alice",
      "user": {
        "id": 1,
        "username": "alice",
        "email": "alice@example.com"
      }
    },
    "assignments": [
      {
        "member": {
          "id": 1,
          "alias": "alice",
          "email": "alice@example.com",
          "user": { "id": 1, "username": "alice", "email": "alice@example.com" }
        },
        "share_amount": "30.00"
      }
    ]
  }
]
```

---

### `GET /api/expenses/{id}/`

Retrieve a single expense with full assignment details.

**Auth:** JWT + Member

**Response `200`:** Single expense object (same structure as list).

---

### `DELETE /api/expenses/{id}/`

Delete an expense.

**Auth:** JWT + Member

**Response `204`:** No content.

---

### `PATCH /api/expenses/{id}/update/`

Change the split type and reassign shares for an existing expense. All previous `ExpenseAssignment` records are deleted and recreated. The expense `amount` is not modified.

**Auth:** JWT + Member

**Request body — equal:**
```json
{
  "split_type": "equal",
  "assignments": [1, 2, 3]
}
```

**Request body — custom:**
```json
{
  "split_type": "custom",
  "assignments": { "1": 100.00, "2": 60.00, "3": 40.00 }
}
```

**Request body — percentage:**
```json
{
  "split_type": "percentage",
  "assignments": { "1": 50, "2": 30, "3": 20 }
}
```

**Response `200`:**
```json
{
  "detail": "Expense updated successfully."
}
```

---

## Money Given

`MoneyGiven` records a direct payment from one member to another — typically used to settle a balance. Balances are recalculated automatically after recording.

---

### `GET /api/money-given/`

List all money transfers across the user's split bills.

**Auth:** JWT + Member

**Response `200`:**
```json
[
  {
    "id": 1,
    "title": "Settling hotel",
    "amount": "40.00",
    "given_by": { "id": 2, "alias": "Bob", "username": null },
    "given_to": { "id": 1, "alias": "alice", "username": "alice" },
    "date": "2025-09-21"
  }
]
```

---

### `POST /api/money-given/`

Record a direct payment between two members.

**Auth:** JWT + Member

**Request body:**
```json
{
  "title": "Settling hotel",
  "amount": 40.00,
  "given_by": 2,
  "given_to": 1,
  "split_bill": 1,
  "date": "2025-09-21"
}
```

- `given_by` — optional. If omitted, resolves to the `SplitBillMember` linked to the authenticated user within the given `split_bill`.
- `given_by`, `given_to` — `SplitBillMember` IDs.

**Response `201`:** Created `MoneyGiven` object.

---

### `GET /api/money-given/{id}/`

Retrieve a single money transfer record.

**Auth:** JWT + Member

**Response `200`:** Single `MoneyGiven` object.

---

### `DELETE /api/money-given/{id}/`

Delete a money transfer record.

**Auth:** JWT + Member

**Response `204`:** No content.

---

## Balances

`Balance` records represent the net amount owed between pairs of `SplitBillMember`s. They are automatically computed after every expense or money-given change.

**Algorithm:** mutual debts are netted. If member A owes B `60` and B owes A `20`, one `Balance` is stored: A → B: `40`. This eliminates redundant or circular pairs.

---

### `GET /api/split-bill/{split_bill_id}/balances/`

List all active (unsettled) balances for a split bill.

**Auth:** JWT + Member

**Response `200`:**
```json
[
  {
    "id": 1,
    "from_member": "Bob",
    "to_member": "alice",
    "amount": "40.00",
    "active": true
  }
]
```

---

### `PATCH /api/split-bill/{split_bill_id}/balances/{balance_id}/settle/`

Mark a balance as settled by setting `active` to `false`.

**Auth:** JWT + Member

**Request body:**
```json
{
  "active": false
}
```

**Response `200`:**
```json
{
  "detail": "Balance settled."
}
```

> Note: A settled balance will be reactivated if further expense changes trigger a recalculation and the net debt is still non-zero.

---

## Comments

### `POST /api/comments/`

Post a comment on a split bill. The author is automatically set to the authenticated user.

**Auth:** JWT + Member

**Request body:**
```json
{
  "split_bill": 1,
  "text": "I paid for the hotel last night!"
}
```

**Response `201`:**
```json
{
  "id": 3,
  "author": {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com"
  },
  "text": "I paid for the hotel last night!",
  "date_created": "2025-09-20T18:45:00Z",
  "split_bill": 1
}
```

---

## Schema & Docs

| URL | Description |
|---|---|
| `GET /api/schema/` | Raw OpenAPI 3.0 schema (YAML) |
| `GET /api/schema/swagger-ui/` | Interactive Swagger UI |
| `GET /api/schema/redoc/` | ReDoc documentation viewer |

A pre-generated `schema.yml` is also committed to the repository root.

---

## Error Reference

| Status | Meaning |
|---|---|
| `200 OK` | Successful GET or PATCH |
| `201 Created` | Resource created successfully |
| `204 No Content` | Successful DELETE |
| `400 Bad Request` | Validation failed — field-level errors in response body |
| `401 Unauthorized` | Missing, invalid, or expired JWT |
| `403 Forbidden` | Authenticated but not a member or owner of the resource |
| `404 Not Found` | Resource does not exist or the user has no access |
| `500 Internal Server Error` | Unhandled server-side exception |

**Validation error example:**
```json
{
  "assignments": ["Percentages must add up to 100."]
}
```

**Auth error example:**
```json
{
  "detail": "Given token not valid for any token type",
  "code": "token_not_valid"
}
```

---

## Permissions Reference

| Label | Condition |
|---|---|
| Public | No authentication required |
| JWT | Valid `Authorization: Bearer <token>` header |
| JWT + Member | JWT required; user must be in `split_bill.members` or be the owner |
| JWT + Owner | JWT required; user must be `split_bill.owner` |

---

## Typical Flows

### Create a bill and record an expense

```
1.  POST /api/register/                          → create user (inactive)
2.  GET  /api/activate/{uidb64}/{token}/          → activate account
3.  POST /api/token/                              → get JWT
4.  POST /api/split-bill/                         → create bill (you are added automatically)
5.  POST /api/split-bill/{id}/add-member/         → add other members; note their member IDs
6.  GET  /api/split-bill/{id}/                    → inspect members array to confirm IDs
7.  POST /api/expenses/equal/                     → create expense using SplitBillMember IDs
8.  GET  /api/split-bill/{id}/balances/           → see who owes what
9.  POST /api/money-given/                        → record a direct settlement payment
10. PATCH /api/split-bill/{id}/balances/{bid}/settle/  → mark balance settled
```

### Invite an unregistered user

```
1. POST /api/split-bill/{id}/add-member/   → provide alias + email
   → PendingInvitation is created; invite email is sent to that address

2. Invited user: POST /api/register/       → registers with that email
   → PendingInvitation is resolved automatically:
      user linked to SplitBillMember, added to split_bill.members

3. Invited user can now authenticate and access the split bill immediately
```
