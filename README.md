# Master API Gateway

**Production-ready FastAPI + MongoDB backend with modular Master API architecture.**

---

## Project Structure

```
project.1authe/
├── main.py              # 🚀 Master Gateway (Central Entry Point)
├── config.py            # ⚙️  Centralized Settings (.env loader)
├── database.py          # 🗄️  MongoDB Motor Driver + Collections
├── security.py          # 🔐 JWT + bcrypt Password Utilities
├── middleware.py        # 🛡️  CORS + Security Headers
│
├── core/
│   └── helpers.py       # 🔧 PyObjectId (ObjectId→JSON) + serialize utils
│
└── modules/
    ├── auth/
    │   └── auth.py      # 🔑 JWT Dependency Layer (get_current_user, get_admin_user)
    ├── users/
    │   ├── schemas.py   # 📋 Pydantic v2 User Schemas
    │   └── routes.py    # 🛣️  User + Admin Endpoints
    └── agents/
        ├── schemas.py   # 📋 Pydantic v2 Agent Schemas
        └── routes.py    # 🛣️  Agent CRUD Endpoints
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

**API Docs:** http://localhost:8000/docs  
**Health Check:** http://localhost:8000/health

---

## API Modules

### Auth & Users (`/`)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/register` | ❌ | Register new user (username, email, mobile_number, gender, password) |
| POST | `/login` | ❌ | Login → JWT token (Rate limited: 5 attempts/min) |
| POST | `/logout` | ✅ | Logout → blacklists token permanently |
| POST | `/refresh-token` | ✅ | Renew token → revokes and blacklists old token |
| GET | `/users/me` | ✅ | Get my profile (includes `profile_photo`) |
| PUT | `/users/me` | ✅ | Update my profile |
| DELETE | `/users/me` | ✅ | Delete my account |
| POST | `/users/me/profile-photo` | ✅ | Upload/update profile photo (JPEG, PNG, WEBP, GIF, max 5MB) |
| DELETE | `/users/me/profile-photo` | ✅ | Delete my profile photo |
| POST | `/forgot-password` | ❌ | Request OTP |
| POST | `/reset-password` | ❌ | Reset via OTP |
| GET | `/admin/stats` | 👑 Admin | User statistics |
| GET | `/admin/users` | 👑 Admin | All users list |
| PUT | `/admin/users/{username}/role` | 👑 Admin | Change user role |
| DELETE | `/admin/users/{username}` | 👑 Admin | Delete user |

### Agents (`/agents`)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/agents/` | ✅ | Create agent |
| GET | `/agents/` | ✅ | List agents (paginated, filterable) |
| GET | `/agents/{id}` | ✅ | Get single agent |
| PUT | `/agents/{id}` | ✅ | Update agent |
| DELETE | `/agents/{id}` | 👑 Admin | Delete agent |
| PATCH | `/agents/bulk/status` | 👑 Admin | Bulk status update |

---

## Tech Stack

- **FastAPI** 0.115.5 — Web framework
- **Motor** 3.6.0 — Async MongoDB driver  
- **Pydantic v2** — Data validation
- **PyJWT** — JSON Web Tokens
- **bcrypt** — Password hashing
- **python-dotenv** — Environment config
