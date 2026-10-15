# Master API Gateway

**Production-ready FastAPI + MongoDB backend with centralized Master API architecture.**

All endpoints are fully defined in `main.py` with Pydantic validation, bcrypt password hashing, JWT authentication, sliding-window rate limiting, token blacklisting, and image uploads.

---

## Project Structure

```
project.1authe/
├── main.py              # 🚀 Master Gateway (Centralized Entry Point & All Endpoints)
├── config.py            # ⚙️  Centralized Settings (.env loader)
├── database.py          # 🗄️  MongoDB Motor Driver + Collections + Indexes
├── security.py          # 🔐 JWT + bcrypt Password Utilities + Token Blacklisting
├── middleware.py        # 🛡️  CORS + Security Headers
│
├── core/
│   ├── helpers.py       # 🔧 PyObjectId (ObjectId→JSON) + serialize utils
│   └── rate_limiter.py  # ⏱️  Sliding-Window Rate Limiter (5 attempts/min)
│
├── modules/
│   ├── auth/
│   │   └── auth.py      # 🔑 JWT Dependencies (get_current_user, get_admin_user)
│   ├── users/
│   │   ├── schemas.py   # 📋 Pydantic v2 User Schemas
│   │   └── routes.py    # 🛣️  User Router Reference
│   └── agents/
│       ├── schemas.py   # 📋 Pydantic v2 Agent Schemas
│       └── routes.py    # 🛣️  Agent Router Reference
│
└── uploads/
    └── profile_photos/  # 🖼️  User Profile Photo Storage
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure .env
# Edit MONGO_URI, JWT_SECRET_KEY, EMAIL settings

# 3. Run server
uvicorn main:app --reload
```

- **Swagger UI (Interactive Docs):** http://localhost:8000/docs  
- **ReDoc:** http://localhost:8000/redoc  
- **Health Check:** http://localhost:8000/health  

---

## Complete API Endpoints Table

### 1. Authentication Endpoints

| Method | Endpoint | Auth | Request Body / Params | Detailed Description |
|:---:|:---|:---:|:---|:---|
| `POST` | `/register` | ❌ Public | JSON: `username`, `email`, `password`, `mobile_number`, `gender` | Validates format & uniqueness. If email exists and password matches, logs in automatically. Otherwise creates new account with hashed password. |
| `POST` | `/login` | ❌ Public | JSON: `email`, `password` | Authenticates credentials; rate-limited to **5 attempts per minute** per client IP. Resets attempt counter on success and returns JWT access token. |
| `POST` | `/logout` | 🔑 Bearer Token | Headers: `Authorization: Bearer <token>` | Permanently revokes and blacklists active JWT token so it cannot be reused. Clears session in database. |
| `POST` | `/refresh-token` | 🔑 Bearer Token | Headers: `Authorization: Bearer <token>` | Immediately invalidates and blacklists the old token, then issues a fresh new JWT access token. |
| `POST` | `/forgot-password` | ❌ Public | JSON: `email` | Checks if account exists, generates a secure 6-digit OTP valid for 10 minutes, and sends it via SMTP email. |
| `POST` | `/reset-password` | ❌ Public | JSON: `email`, `otp`, `new_password` | Verifies the OTP and expiration window, securely updates password with bcrypt hashing, and clears the OTP. |

---

### 2. User Profile Endpoints

| Method | Endpoint | Auth | Request Body / Params | Detailed Description |
|:---:|:---|:---:|:---|:---|
| `GET` | `/users/me` | 🔑 Bearer Token | Headers: `Authorization: Bearer <token>` | Returns full profile of logged-in user (including username, email, mobile, gender, profile photo URL) without sensitive secrets. |
| `PUT` | `/users/me` | 🔑 Bearer Token | JSON (Optional): `username`, `email`, `mobile_number`, `gender`, `password` | Updates authenticated user's profile with conflict validation. If username changes, the previous token is revoked and a new token is issued. |
| `POST` | `/users/me/profile-photo` | 🔑 Bearer Token | `multipart/form-data`: `file: UploadFile` | Uploads/updates profile picture (JPEG, PNG, WEBP, GIF, max 5MB). Deletes previous photo file from disk and updates URL in database. |
| `DELETE` | `/users/me/profile-photo` | 🔑 Bearer Token | Headers: `Authorization: Bearer <token>` | Removes profile photo file from disk and unsets the `profile_photo` field in the user document. |
| `DELETE` | `/users/me` | 🔑 Bearer Token | Headers: `Authorization: Bearer <token>` | Permanently deletes the authenticated user's own account and associated uploaded files. |

---

### 3. Administrator Endpoints

| Method | Endpoint | Auth | Request Body / Params | Detailed Description |
|:---:|:---|:---:|:---|:---|
| `GET` | `/admin/stats` | 👑 Admin Only | Headers: `Authorization: Bearer <admin_token>` | Returns real-time platform statistics: total registered accounts, standard users count, and admin accounts count. |
| `GET` | `/admin/users` | 👑 Admin Only | Headers: `Authorization: Bearer <admin_token>` | Lists all registered users across the system (excluding passwords, tokens, and OTP secrets). |
| `PUT` | `/admin/users/{username}/role` | 👑 Admin Only | Path: `username`, JSON: `role` ("admin" or "user") | Updates specified user's role. Admins cannot alter their own role to prevent lockout. |
| `DELETE` | `/admin/users/{username}` | 👑 Admin Only | Path: `username` | Permanently deletes any user account. Admins cannot delete their own account through this endpoint. |

---

### 4. Agent Operations Endpoints

| Method | Endpoint | Auth | Request Body / Params | Detailed Description |
|:---:|:---|:---:|:---|:---|
| `POST` | `/agents/` | 🔑 Bearer Token | JSON: `name`, `phone`, `email` (opt), `status` (active/inactive/suspended), `region`, `department`, `notes` | Creates a new operational agent record. Validates that the phone number is unique across all agents. |
| `GET` | `/agents/` | 🔑 Bearer Token | Query: `page` (default 1), `page_size` (default 10), `status` (opt), `search` (opt) | Returns a paginated list of operational agents with status filtering and name/phone search. |
| `GET` | `/agents/{agent_id}` | 🔑 Bearer Token | Path: `agent_id` (MongoDB ObjectId) | Fetches complete record details of a single agent by ID. Returns 404/422 if invalid or not found. |
| `PUT` | `/agents/{agent_id}` | 🔑 Bearer Token | Path: `agent_id`, JSON (Optional fields) | Updates agent record. Validates unique phone number if modified. |
| `DELETE` | `/agents/{agent_id}` | 👑 Admin Only | Path: `agent_id` | Permanently deletes the specified operational agent record. Restricted to admins. |
| `PATCH` | `/agents/bulk/status` | 👑 Admin Only | JSON: `agent_ids: list[str]`, Query: `new_status` | Atomically updates the operational status of multiple agents in a single request. Restricted to admins. |

---

### 5. System & Health Endpoints

| Method | Endpoint | Auth | Description |
|:---:|:---|:---:|:---|
| `GET` | `/` | ❌ Public | API Gateway root health check returning service status, version, and documentation links. |
| `GET` | `/health` | ❌ Public | Detailed system health status with live categorization of all available endpoints. |
| `GET` | `/uploads/profile_photos/{filename}` | ❌ Public | Direct static file serving for uploaded user profile photos. |

---

## Tech Stack

- **FastAPI** 0.115.5 — High performance asynchronous web framework
- **Motor** 3.6.0 — Asynchronous MongoDB driver for asyncio
- **Pydantic v2** — Fast data validation and serialization
- **PyJWT** — Cryptographically secure JSON Web Tokens
- **bcrypt** — Strong password hashing with automatic salt generation
- **python-dotenv** — Environment configuration manager
