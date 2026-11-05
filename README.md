# ShopEase Authentication Service

Standalone authentication microservice for the ShopEase platform: user registration, login, JWT issuing and verification, and password change. It is an independent project with its own database and is not combined with the Product Service.

## 1. Tech stack

| Area | Technology |
|---|---|
| API | FastAPI (Swagger UI at `/docs`) |
| Database | MySQL 8 |
| ORM / migrations | SQLAlchemy 2 + Alembic |
| Password hashing | Passlib (bcrypt) |
| Tokens | JWT (PyJWT, HS256) |
| Validation | Pydantic v2 |
| Containers | Docker + Docker Compose (Python 3.11) |

## 2. Project structure

```
shopease-auth-service/
├── app/
│   ├── main.py                  # app, exception handlers, /health
│   ├── routers/auth_routes.py   # the 5 endpoints
│   ├── models/user_model.py     # users table
│   ├── schemas/auth_schema.py   # request/response models, password rules
│   ├── services/auth_service.py # register / login / change password / current user
│   ├── core/config.py           # settings read from environment (.env)
│   ├── core/security.py         # bcrypt hashing, JWT create/decode, auth dependency
│   └── database/connection.py   # engine, session, Base
├── alembic/ , alembic.ini       # migrations (users table)
├── tests/                       # automated tests (pytest)
├── postman/                     # Postman collection
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example                 # template; copy to .env
├── .env                         # local secrets (git-ignored, docker-ignored)
└── .dockerignore
```

## 3. Database

Database `shopease_auth_db`, table `users`:

| Column | Type | Notes |
|---|---|---|
| id | INT | primary key, auto increment |
| full_name | VARCHAR(100) | |
| email | VARCHAR(255) | unique, stored lowercase |
| password_hash | VARCHAR(255) | bcrypt hash, never the password |
| role | VARCHAR(30) | default `customer` |
| is_active | BOOLEAN | default true; inactive users cannot log in |
| created_at | DATETIME | set by the database |
| updated_at | DATETIME | refreshed on every update |

## 4. Environment setup

Nothing secret is hard-coded: database credentials and the JWT secret are read from `.env`. The application refuses to start if `JWT_SECRET_KEY` is missing or shorter than 32 characters.

```bat
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Put the generated value in `JWT_SECRET_KEY` and replace every `change-me` in `.env`.

| Variable | Purpose |
|---|---|
| MYSQL_ROOT_PASSWORD, MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD | MySQL container initialisation and app connection |
| MYSQL_HOST_PORT | port published on your PC for MySQL (default 3307) |
| MYSQL_HOST, MYSQL_PORT | used only when running the API on your PC (`localhost` / `3307`). Compose overrides them with `auth-db` / `3306` inside the network |
| JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES | token signing and expiry |

`.env` is listed in `.gitignore` and `.dockerignore`. Do not commit it; commit `.env.example` only.

## 5. Run with Docker (recommended)

Requires Docker Desktop. From the project folder in Command Prompt or PowerShell:

```bat
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f auth-service
```

- `auth-db` (MySQL 8) has a health check; `auth-service` starts only when it is healthy (`depends_on: condition: service_healthy`).
- The API reaches MySQL through the Compose service name `auth-db`, not `localhost`.
- Data lives in the named volume `auth_db_data` and survives restarts.
- On start the container runs `alembic upgrade head` and then Uvicorn.

Open Swagger UI: http://localhost:8001/docs   Health: http://localhost:8001/health

```bat
docker compose down
docker compose down -v
```

## 6. Run locally without Docker (optional)

Needs a MySQL 8 server (for example `docker compose up -d auth-db`, which publishes port 3307).

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8001
```

## 7. Alembic commands

```bat
alembic upgrade head
alembic current
alembic history
alembic downgrade -1
alembic revision --autogenerate -m "describe change"
alembic check
```

The initial revision `9ffe713e187e_create_users_table` creates `users` with a unique index on `email`. The database URL is built from `.env` by `alembic/env.py`.

## 8. API documentation

Base URL `http://localhost:8001`. All errors share one shape:

```json
{ "status_code": 401, "error": "Unauthorized", "message": "Invalid token" }
```

Validation errors (422) add `"details": [{"field": "...", "message": "..."}]`. Submitted values (passwords) are never echoed back.

| Method | Path | Auth | Success |
|---|---|---|---|
| POST | /api/auth/register | no | 201 |
| POST | /api/auth/login | no | 200 |
| GET | /api/auth/me | Bearer | 200 |
| POST | /api/auth/verify-token | Bearer | 200 |
| POST | /api/auth/change-password | Bearer | 200 |

### POST /api/auth/register

```json
{ "full_name": "Sai Tej", "email": "sai@example.com", "password": "Secret@123", "confirm_password": "Secret@123" }
```
201 response:
```json
{ "message": "User registered successfully", "user_id": 1, "full_name": "Sai Tej", "email": "sai@example.com", "is_active": true }
```
Rules: valid email; password at least 8 characters with upper-case, lower-case, digit and special character (max 72 bytes, a bcrypt limit); `confirm_password` must match; duplicate email gives 409. New users get the role `customer`. The password hash is never returned.

### POST /api/auth/login

```json
{ "email": "sai@example.com", "password": "Secret@123" }
```
200 response:
```json
{ "message": "Login successful", "access_token": "<jwt>", "token_type": "bearer", "expires_in": 1800,
  "user": { "id": 1, "full_name": "Sai Tej", "email": "sai@example.com", "role": "customer", "is_active": true } }
```
Wrong password or unknown email gives the same 401 `Invalid email or password` (no account enumeration). A correct password on an inactive account gives 403.

### GET /api/auth/me
Header `Authorization: Bearer <token>`. Returns id, full_name, email, role, is_active, created_at, updated_at.

### POST /api/auth/verify-token
Header `Authorization: Bearer <token>`. Returns `{ "valid": true, "user_id": 1, "email": "...", "role": "customer", "expires_at": "..." }`.

### POST /api/auth/change-password
Header `Authorization: Bearer <token>`.
```json
{ "current_password": "Secret@123", "new_password": "NewSecret@456", "confirm_new_password": "NewSecret@456" }
```
200 `{"message": "Password changed successfully"}`. Wrong current password gives 400; a weak or mismatched new password gives 422; reusing the current password gives 400.

### Status codes

| Code | Meaning |
|---|---|
| 200 / 201 | success / created |
| 400 | wrong current password, new password equals the old one |
| 401 | bad credentials, missing, invalid or expired token |
| 403 | inactive account |
| 409 | email already registered |
| 422 | validation error |
| 500 | unexpected error (generic message, details only in the server log) |

## 9. JWT

- Claims: `sub` (user id), `role`, `iat`, `exp`.
- Signed with `JWT_SECRET_KEY` using `JWT_ALGORITHM` (HS256); lifetime `ACCESS_TOKEN_EXPIRE_MINUTES` (default 30). All three come from `.env`.
- Decoding accepts only the configured algorithm (so `alg: none` and tampered tokens are rejected), requires `exp` and `sub`, and returns "Token has expired" or "Invalid token".
- On every protected request the user is loaded again, so a deleted user gets 401 and a deactivated user gets 403 even with a still-valid token.

Using the token in Swagger UI: call `/api/auth/login`, copy `access_token`, click **Authorize**, paste the token (without the word Bearer) and click Authorize.

Reusable dependencies for other routes (in `app/core/security.py` and `app/services/auth_service.py`):

```python
from fastapi import Depends
from app.services.auth_service import get_current_user

@router.get("/protected")
def protected(user = Depends(get_current_user)):   # 401 / 403 handled for you
    return {"hello": user.full_name}
```

`get_token_data` (security.py) validates only the token, without a database lookup.

## 10. Testing

### Swagger UI
Open http://localhost:8001/docs and run the five endpoints in order: register, login, Authorize, me, verify-token, change-password.

### Postman
Import `postman/ShopEase_Auth_Service.postman_collection.json`. Variables: `base_url`, `email`, `password`, `new_password`, `jwt_secret` (set it to `JWT_SECRET_KEY` from `.env`; used only to build the expired token in request 12). Each request has test scripts that check the status code and message. Run the folder top to bottom on a fresh database with the Collection Runner.

Request 08 (inactive account) needs the user deactivated first:

```bat
docker exec -it shopease-auth-db mysql -u root -p shopease_auth_db -e "UPDATE users SET is_active = 0 WHERE email = 'sai@example.com';"
docker exec -it shopease-auth-db mysql -u root -p shopease_auth_db -e "UPDATE users SET is_active = 1 WHERE email = 'sai@example.com';"
```
(use the `MYSQL_ROOT_PASSWORD` from `.env` when prompted; run the second command to re-activate before continuing). Run request 08 on its own between these two commands and skip it in a full Collection Runner run.

### Automated tests
```bat
pip install pytest httpx
pytest -v
```
The tests use an in-memory SQLite database, so they need neither MySQL nor Docker.

### Test results

61 automated tests, all passing (pytest, SQLite in-memory). The 14 mandatory scenarios:

| # | Scenario | Expected | Result |
|---|---|---|---|
| 1 | Register valid user | 201 | Pass |
| 2 | Register duplicate email | 409 | Pass |
| 3 | Register invalid email | 422 | Pass |
| 4 | Register mismatched passwords | 422 | Pass |
| 5 | Login valid credentials | 200 + token | Pass |
| 6 | Login wrong password | 401 | Pass |
| 7 | Login inactive account | 403 | Pass |
| 8 | /me with valid token | 200 | Pass |
| 9 | /me without token | 401 | Pass |
| 10 | /me with invalid token | 401 | Pass |
| 11 | /me with expired token | 401 | Pass |
| 12 | Change password, correct current | 200 | Pass |
| 13 | Change password, wrong current | 400 | Pass |
| 14 | Login with the new password (old one rejected) | 200 / 401 | Pass |

Also covered: weak passwords, name validation, case-insensitive email, tampered / foreign-secret / `alg: none` tokens, deleted and deactivated users with valid tokens, no password or hash in any response, bcrypt storage, verify-token, 404/405, a 500 that leaks nothing, configuration rules (no default secrets, minimum secret length), and the Alembic migration (upgrade, `alembic check`, downgrade).

Not executed in the environment where this project was built: the Docker image build, the MySQL container, and the Postman run. Run `docker compose up -d --build` and the Postman collection on your machine to confirm them; the MySQL migration SQL was generated offline and checked, and the Compose file was parsed, but neither was run against a live MySQL.

## 11. Security notes

- Passwords hashed with bcrypt (salted, 72-byte limit enforced); login does a constant amount of hashing work whether or not the email exists.
- No credentials or secrets in code; `.env` excluded from Git and from the Docker image; Compose refuses to start if a required variable is unset.
- The API container runs as a non-root user and receives only the variables it needs (not the MySQL root password).
- Dependencies are pinned (`passlib==1.7.4` needs `bcrypt==4.0.1`).
- For production use HTTPS, a secret manager, and a stronger rate-limiting layer in front of `/login`.
