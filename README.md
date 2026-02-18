# 💡 NovaMint — AI-Powered Financial Advisory App

> A smart, ethical, and explainable AI financial advisor in your pocket.

![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=flat&logo=postgresql&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)

---

## 📌 Table of Contents
- [About](#-about)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Setup & Installation](#-setup--installation)
- [API Endpoints](#-api-endpoints)
- [System Flow](#-system-flow)
- [Environment Variables](#-environment-variables)

---

## 🧠 About

**NovaMint** is a full-stack AI-powered financial advisory app that helps users make smarter financial decisions through real-time event detection, suitability-based product recommendations, ethical guardrails, and fully explainable AI logic — all built with rule-based scoring, no deep ML required.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔐 Auth | Email + password with JWT tokens and bcrypt hashing |
| 📊 Dashboard | Income, balance, savings ratio, health score, live alerts |
| ⚡ Event Detection | 5 rule-based events triggered on every transaction |
| 🤖 AI Recommendations | Suitability scoring across financial products (0–100) |
| 🛡️ Ethical Guardrails | Hard rules that block unsafe investment recommendations |
| 🔍 Explainable AI | Full reason codes, weights, and human-readable explanations |
| 📈 Growth Projection | SIP calculator with 5yr/10yr projections and chart data |
| 🎭 Demo Mode | Simulate salary credit, high expense, low balance, and surplus |

---

## 🛠 Tech Stack

| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Python 3.10+, FastAPI |
| Database | PostgreSQL 15+ |
| Auth | JWT (python-jose), bcrypt (passlib) |
| AI Logic | Rule-based scoring engine (no ML) |

---

## 📁 Project Structure

```
novamint/
├── main.py              # Complete FastAPI backend
├── fintech_app.html     # Complete frontend (all 8 screens)
├── README.md

```

---

## 🚀 Setup & Installation

### 1. Clone & create virtual environment

```bash
git clone https://github.com/yourname/novamint.git
cd novamint
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
fastapi>=0.100.0
uvicorn>=0.23.0
psycopg2-binary>=2.9.6
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-dotenv>=1.0.0
pydantic[email]>=2.0.0
```

### 3. Set up PostgreSQL

```bash
psql -U postgres -c "CREATE DATABASE novamint;"
psql -U postgres -d novamint -f schema.sql
```

### 4. Configure `.env` and run

```bash
cp .env.example .env
# Edit .env with your values
uvicorn main:app --reload --port 8000
```

### 5. Open the frontend

Open `fintech_app.html` directly in your browser — no build step needed.

> API docs available at `http://localhost:8000/docs`

---

## 🌐 API Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/auth/signup` | Register new user | ❌ |
| POST | `/auth/login` | Login, get JWT | ❌ |
| GET | `/dashboard` | Metrics + alerts | ✅ |
| POST | `/transactions` | Add transaction, triggers event detection | ✅ |
| GET | `/recommendations` | AI-scored product recommendations | ✅ |
| POST | `/growth/projection` | SIP calculator (5yr + 10yr) | ✅ |
| POST | `/demo/simulate/{scenario}` | Simulate scenarios for demo | ✅ |
| POST | `/feedback` | Submit recommendation rating | ✅ |
| GET | `/health` | API health check | ❌ |

**Demo scenarios:** `salary_credit` · `high_expense` · `low_balance` · `surplus`

---

## 🔄 System Flow

```
User Login
  → POST /auth/login → JWT token issued

Transaction Added
  → POST /transactions → profile recalculated
  → Event Detection runs automatically
      SALARY_CREDIT / HIGH_EXPENSE / LOW_SAVINGS / SURPLUS / LOW_EMERGENCY_FUND

Dashboard Updated
  → GET /dashboard → health score + alerts returned

AI Recommendation
  → GET /recommendations → suitability scored (0–100)
  → Guardrails checked → blocked if unsafe
  → XAI explanation generated (reason codes + weights)

User Feedback
  → POST /feedback → rating + accept/reject stored
  → Acceptance rates tracked for future tuning
```

---

## 🔧 Environment Variables

`.env.example`:
```env
DATABASE_URL=postgresql://postgres:password@localhost/novamint
SECRET_KEY=replace-with-a-long-random-string
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

> ⚠️ Never commit your `.env` file. Add it to `.gitignore`.

---

