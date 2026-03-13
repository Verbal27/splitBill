# SplitBill — API Reference

**Base URL:** `https://splitbill-production.up.railway.app/apps/api`  
**Version:** 0.1.0  
**Authentication:** JWT Bearer token (see [Authentication](#authentication))

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

---

## Authentication

### `POST /token/`

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

**Token lifetimes:** access = 15 minutes, refresh = 1 day.

---

### `POST /token/refresh/`

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

### `POST /register/`

Create a new user account. The user is created as inactive and an activation email is sent via Mailgun.

If the registered email matches any pending invitations (from existing split bills), those are resolved automatically — the user is linked to the corresponding `SplitBillMember` and added to the split bill.

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
- `email` — must be unique

**Response `201`:**
```json
{
  "detail": "Check your email to activate your account."
}
```

---

### `GET /activate/{uidb64}/{token}/`

Activate a user account using the link sent by email.

**Auth:** Public

**Response `200`:**
```json
{
  "detail": "Account activated successfully!"
}
```

**Response `400`** — token invalid or expired:
```json
{
  "detail": "Invalid or expired activation link."
}
```

---

### `POST /reset-password/`

Request a password reset email.

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

---

### `GET /reset-password-confirm/{uidb64}/{token}/`

Validate a password reset token before displaying the reset form. Use the `uidb64` and `token` values from the link emailed to the user.

**Auth:** Public

**Response `200`:**
```json
{
  "message": "Token is valid"
}
```

---

### `POST /reset-password-complete/`

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

**Response `200`:**
```json
{
  "message": "Password has been reset successfully"
}
```

---

### `GET /users/`

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

### `PATCH /users/{id}/`

Update username, email, or password for the authenticated user.

**Auth:** JWT

**Request body** (all fields optional):
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

A `SplitBill` is the top-level container for a shared expense group. The user who creates it becomes the **owner** and is automatically added as the first `SplitBillMember`.

---

### `GET /split-bill/`

List all split bills the authenticated user is a member of.

**Auth:** JWT

**Response `200`:** Array of split bill objects (see structure below).

---

### `POST /split-bill/`

Create a new split bill.

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

- `member_inputs` is optional. Each entry may have an `alias`, an `email`, or both.
- If `email` matches a registered user → the user is linked immediately.
- If `email` is unknown → a `PendingInvitation` is created and an invite email is sent.
- The authenticated user is always added as a member with their username as alias.

**Response `201`:** Full split bill object (see structure below).

---

### `GET /split-bill/{id}/`

Retrieve full details of a split bill including expenses, money given, comments, and balances.

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
  "expenses": [ /* see Expense object */ ],
  "money_given": [ /* see MoneyGiven object */ ],
  "comments": [ /* see Comment object */ ],
  "balances": [
    { "from": "Bob", "to": "alice", "amount": "45.00" }
  ]
}
```

---

### `PATCH /split-bill/{id}/`

Update a split bill's title, currency, or active status.

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

### `DELETE /split-bill/{id}/`

Delete a split bill and all its related data.

**Auth:** JWT + Member (owner in practice due to cascading)

**Response `204`:** No content.

---

## Members

### `POST /split-bill/{id}/add-member/`

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
- `email` is optional. Same resolution logic as `member_inputs` on creation.
- If the member (same alias + email combination) already exists, the existing record is returned without duplication.

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

### `POST /split-bill/{id}/remove-member/`

Remove a member from a split bill by alias or email.

**Auth:** JWT + Owner

**Request body:**
```json
{
  "alias": "Dave"
}
```

At least one of `alias` or `email` is required. If both are provided, both conditions must match.

**Response `200`:**
```json
{
  "detail": "Removed member(s): Dave"
}
```

---

### `PATCH /split-bill/{split_bill_id}/members/{id}/update/`

Update a member's alias or email.

**Auth:** JWT + Owner

**Request body** (at least one field):
```json
{
  "alias": "David",
  "email": "david@example.com"
}
```

- If the email matches a registered user, they are linked and added to `split_bill.members`.
- If the email is unregistered, a `PendingInvitation` is created and an invite email is sent.

**Response `200`:** Updated `SplitBillMember` object.

---

## Expenses

Expenses belong to a split bill and have a `split_type` that determines how the cost is distributed. Three creation endpoints exist — one per strategy. After every create or update, balances are automatically recalculated.

All expense creation endpoints share these common fields:

| Field | Type | Description |
|---|---|---|
| `title` | string | Expense label |
| `amount` | decimal | Total cost |
| `paid_by_member` | integer | ID of the `SplitBillMember` who paid |
| `split_bill` | integer | ID of the parent `SplitBill` |
| `date` | date (optional) | Defaults to today |
| `assignments` | varies | See per-endpoint definition |

---

### `POST /expenses/equal`

Create an expense split equally among selected members.

**Auth:** JWT

Each participant's share = `amount / number_of_participants`, rounded to 2 decimal places.

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

### `POST /expenses/custom`

Create an expense with explicit per-member amounts.

**Auth:** JWT

The sum of all assignment values must equal `amount` (±0.01 tolerance).

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

`assignments` — object mapping `SplitBillMember` ID (as string key) → amount owed.

**Response `201`:** Created expense object.

---

### `POST /expenses/percentage`

Create an expense split by percentages.

**Auth:** JWT

All percentages must sum to 100 (±0.01 tolerance). Each share is computed as `amount × pct / 100`.

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

`assignments` — object mapping `SplitBillMember` ID (as string key) → percentage.

**Response `201`:** Created expense object.

---

### `GET /expenses/`

List all expenses across all split bills the authenticated user belongs to.

**Auth:** JWT

**Response `200`:** Array of expense objects.

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
      "user": { "id": 1, "username": "alice", "email": "alice@example.com" }
    },
    "assignments": [
      {
        "member": {
          "id": 1, "alias": "alice", "email": "alice@example.com",
          "user": { "id": 1, "username": "alice", "email": "alice@example.com" }
        },
        "share_amount": "30.00"
      }
    ]
  }
]
```

---

### `GET /expenses/{id}/`

Retrieve a single expense with all assignment details.

**Auth:** JWT + Member

**Response `200`:** Single expense object (same structure as list).

---

### `DELETE /expenses/{id}/`

Delete an expense.

**Auth:** JWT + Member

**Response `204`:** No content.

---

### `PATCH /expenses/{id}/update`

Change the split type and reassign shares for an existing expense. All previous `ExpenseAssignment` records are deleted and recreated. The expense `amount` is not changed.

**Auth:** JWT + Member

**Request body (equal):**
```json
{
  "split_type": "equal",
  "assignments": [1, 2, 3]
}
```

**Request body (custom):**
```json
{
  "split_type": "custom",
  "assignments": { "1": 100.00, "2": 60.00, "3": 40.00 }
}
```

**Request body (percentage):**
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

`MoneyGiven` records a direct money transfer between two members — typically used to settle a computed balance outside the app. After recording, balances are recalculated.

---

### `GET /money-given/`

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

### `POST /money-given/`

Record a direct payment from one member to another.

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

- `given_by` is optional. If omitted, it resolves to the `SplitBillMember` linked to the authenticated user within the specified `split_bill`.
- `given_by` and `given_to` are `SplitBillMember` IDs.

**Response `201`:** Created `MoneyGiven` object.

---

### `GET /money-given/{id}/`

Retrieve a single money transfer record.

**Auth:** JWT + Member

**Response `200`:** Single `MoneyGiven` object.

---

### `DELETE /money-given/{id}/`

Delete a money transfer record.

**Auth:** JWT + Member

**Response `204`:** No content.

---

## Balances

Balances represent the net amount owed between pairs of `SplitBillMember`s. They are automatically computed and stored after every expense creation, update, deletion, or money-given change.

**Algorithm:** mutual debts are netted. If member A owes B 60 and B owes A 20, a single `Balance` of 40 (A → B) is stored. This eliminates circular or redundant balance pairs.

---

### `GET /split-bill/{split_bill_id}/balances/`

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

### `PATCH /split-bill/{split_bill_id}/balances/{balance_id}/settle/`

Mark a balance as settled (inactive).

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

> Note: Settled balances may be reactivated if further expense changes trigger a recalculation.

---

## Comments

### `POST /comments/`

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
| `GET /schema/` | Download the raw OpenAPI 3.0 schema (YAML/JSON) |
| `GET /schema/swagger-ui/` | Interactive Swagger UI |
| `GET /schema/redoc/` | ReDoc documentation viewer |

A pre-generated `schema.yml` is also committed to the repository root.

---

## Error Reference

| Status | Meaning |
|---|---|
| `200 OK` | Successful GET, PATCH |
| `201 Created` | Resource created successfully |
| `204 No Content` | Successful DELETE |
| `400 Bad Request` | Validation failed — field-level errors in response body |
| `401 Unauthorized` | Missing, invalid, or expired JWT |
| `403 Forbidden` | Authenticated but not a member/owner of the resource |
| `404 Not Found` | Resource does not exist or user has no access |
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

| Permission | Condition |
|---|---|
| Public | No authentication required |
| JWT | Valid `Authorization: Bearer <token>` header |
| JWT + Member | JWT required; user must be in `split_bill.members` or be the owner |
| JWT + Owner | JWT required; user must be `split_bill.owner` |

---

## Typical Flows

### Create a bill and split an expense

```
1. POST /register/              → create user (inactive)
2. GET  /activate/{uid}/{token}/ → activate account
3. POST /token/                 → obtain JWT
4. POST /split-bill/            → create bill (you are added as member automatically)
5. POST /split-bill/{id}/add-member/ → add other members (get their SplitBillMember IDs)
6. GET  /split-bill/{id}/       → inspect members to collect SplitBillMember IDs
7. POST /expenses/equal         → create an equal expense using member IDs
8. GET  /split-bill/{id}/balances/ → see who owes what
9. POST /money-given/           → record when someone pays back
10. PATCH /split-bill/{id}/balances/{bid}/settle/ → mark balance as settled
```

### Invite an unregistered user

```
1. POST /split-bill/{id}/add-member/  → provide alias + email
   → PendingInvitation created, invite email sent
2. Invited user: POST /register/      → register with that email
   → PendingInvitation resolved automatically
   → User linked to SplitBillMember, added to split_bill.members
3. Invited user can now access the split bill immediately
```
