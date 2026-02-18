"""
NovaMint — AI Financial Advisory App
Complete FastAPI Backend
========================================
Tech Stack: Python FastAPI + PostgreSQL + JWT
Author: NovaMint Engineering

SETUP:
  pip install fastapi uvicorn psycopg2-binary python-jose[cryptography] passlib[bcrypt] python-dotenv pydantic

RUN:
  uvicorn main:app --reload --port 8000

ENV (.env file):
  DATABASE_URL=postgresql://user:pass@localhost/novamint
  SECRET_KEY=your-super-secret-key-change-this
  ALGORITHM=HS256
  ACCESS_TOKEN_EXPIRE_MINUTES=60
"""

# ═══════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import psycopg2
import os
from dotenv import load_dotenv
import math

load_dotenv()

# ═══════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════
SECRET_KEY = os.getenv("SECRET_KEY", "novamint-secret-key-replace-in-prod")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:pass@localhost/novamint")

# ═══════════════════════════════════════════
# APP INIT
# ═══════════════════════════════════════════
app = FastAPI(title="NovaMint API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # In prod: restrict to your domain
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()


# ═══════════════════════════════════════════════════════════════════════
#
#  DATABASE SCHEMA (run this once to set up PostgreSQL tables)
#  Execute in psql: psql -U postgres -d novamint -f schema.sql
#
# ═══════════════════════════════════════════════════════════════════════
SCHEMA_SQL = """
-- ─────────────────────────────────────
-- 1. USERS TABLE
-- ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                  SERIAL PRIMARY KEY,
    full_name           VARCHAR(120) NOT NULL,
    email               VARCHAR(180) UNIQUE NOT NULL,
    hashed_password     TEXT NOT NULL,
    risk_profile        VARCHAR(20) DEFAULT 'moderate',  -- conservative | moderate | aggressive
    age                 INTEGER DEFAULT 30,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE
);

-- ─────────────────────────────────────
-- 2. FINANCIAL PROFILE TABLE
--    One row per user, updated on each transaction
-- ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS financial_profile (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,

    -- Income & Spending
    monthly_income          NUMERIC(12,2) DEFAULT 0,
    monthly_spend           NUMERIC(12,2) DEFAULT 0,
    current_balance         NUMERIC(12,2) DEFAULT 0,

    -- Derived fields (calculated by backend)
    savings_ratio           NUMERIC(5,2) DEFAULT 0,    -- (income - spend) / income * 100
    emergency_fund_months   NUMERIC(4,1) DEFAULT 0,    -- balance / (spend/12)
    debt_amount             NUMERIC(12,2) DEFAULT 0,
    debt_ratio              NUMERIC(5,2) DEFAULT 0,    -- debt / income * 100

    -- Health score (0–100)
    health_score            INTEGER DEFAULT 50,

    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────
-- 3. TRANSACTIONS TABLE
-- ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    amount          NUMERIC(12,2) NOT NULL,
    txn_type        VARCHAR(20) NOT NULL,   -- credit | debit
    category        VARCHAR(50),            -- salary | food | rent | emi | investment | other
    description     TEXT,
    txn_date        TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────
-- 4. EVENTS TABLE
--    Records detected financial events
-- ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL,   -- SALARY_CREDIT | LOW_SAVINGS | HIGH_EXPENSE | SURPLUS
    severity        VARCHAR(20) DEFAULT 'info', -- info | warn | danger | success
    description     TEXT,
    triggered_at    TIMESTAMPTZ DEFAULT NOW(),
    is_read         BOOLEAN DEFAULT FALSE
);

-- ─────────────────────────────────────
-- 5. RECOMMENDATIONS TABLE
-- ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS recommendations (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER REFERENCES users(id) ON DELETE CASCADE,
    product_name        VARCHAR(120),
    suitability_pct     INTEGER,
    risk_level          VARCHAR(20),
    confidence_score    INTEGER,
    guardrail_pass      BOOLEAN,
    blocked_reasons     TEXT[],             -- PostgreSQL array of block reason codes
    reason_codes        JSONB,              -- Full XAI explanation JSON
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────
-- 6. USER FEEDBACK TABLE
-- ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_feedback (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    recommendation_id INTEGER REFERENCES recommendations(id),
    rating          INTEGER CHECK (rating BETWEEN 1 AND 5),
    accepted        BOOLEAN,
    feedback_text   TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_txn_user ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_reco_user ON recommendations(user_id);
"""


# ═══════════════════════════════════════════
# DB CONNECTION HELPER
# ═══════════════════════════════════════════
def get_db():
    """Get a raw psycopg2 connection. In production use a connection pool (psycopg2.pool)."""
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()


# ═══════════════════════════════════════════
# PYDANTIC SCHEMAS
# ═══════════════════════════════════════════

class SignupRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    risk_profile: str = "moderate"   # conservative | moderate | aggressive
    age: int = 30

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TransactionRequest(BaseModel):
    amount: float
    txn_type: str           # credit | debit
    category: str           # salary | food | rent | emi | investment | other
    description: str = ""

class FeedbackRequest(BaseModel):
    recommendation_id: int
    rating: int             # 1–5
    accepted: bool
    feedback_text: str = ""

class SIPRequest(BaseModel):
    monthly_amount: float
    cagr: float = 12.0      # expected annual return %


# ═══════════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════════

def hash_password(plain: str) -> str:
    """Bcrypt-hash a password. Never store plain text."""
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain password against its bcrypt hash."""
    return pwd_ctx.verify(plain, hashed)

def create_access_token(user_id: int, email: str) -> str:
    """
    Create a signed JWT token.
    Payload: { sub: email, user_id: int, exp: datetime }
    """
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "user_id": user_id,
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """
    Middleware: decode and validate JWT from Authorization header.
    Usage: add `Depends(decode_token)` to any protected endpoint.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 1: AUTH ENDPOINTS
#
# ═══════════════════════════════════════════════════════════════════════

@app.post("/auth/signup", tags=["Auth"])
def signup(body: SignupRequest, conn=Depends(get_db)):
    """
    SIGNUP FLOW:
    1. Check email not already registered
    2. Hash password with bcrypt
    3. Insert user into users table
    4. Create default financial_profile row
    5. Return JWT token
    """
    cur = conn.cursor()

    # Step 1: Check duplicate
    cur.execute("SELECT id FROM users WHERE email = %s", (body.email,))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Step 2: Hash password
    hashed = hash_password(body.password)

    # Step 3: Insert user
    cur.execute(
        """INSERT INTO users (full_name, email, hashed_password, risk_profile, age)
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (body.full_name, body.email, hashed, body.risk_profile, body.age)
    )
    user_id = cur.fetchone()[0]

    # Step 4: Create empty financial profile
    cur.execute(
        "INSERT INTO financial_profile (user_id) VALUES (%s)",
        (user_id,)
    )
    conn.commit()

    # Step 5: Return token
    token = create_access_token(user_id, body.email)
    return {"access_token": token, "token_type": "bearer", "user_id": user_id}


@app.post("/auth/login", tags=["Auth"])
def login(body: LoginRequest, conn=Depends(get_db)):
    """
    LOGIN FLOW:
    1. Fetch user by email
    2. Verify password hash
    3. Return JWT token
    """
    cur = conn.cursor()
    cur.execute("SELECT id, hashed_password FROM users WHERE email=%s", (body.email,))
    row = cur.fetchone()

    if not row or not verify_password(body.password, row[1]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(row[0], body.email)
    return {"access_token": token, "token_type": "bearer", "user_id": row[0]}


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 2: DASHBOARD ENDPOINT
#
# ═══════════════════════════════════════════════════════════════════════

@app.get("/dashboard", tags=["Dashboard"])
def get_dashboard(payload=Depends(decode_token), conn=Depends(get_db)):
    """
    Dashboard metrics. All calculations explained below.

    METRIC FORMULAS:
    ─────────────────────────────────────────────────────
    savings_ratio       = (income - spend) / income * 100
    emergency_months    = balance / (spend / 12)
    debt_ratio          = debt / income * 100
    health_score        = see calculate_health_score()

    ALERT RULES:
    ─────────────────────────────────────────────────────
    LOW_SAVINGS     → savings_ratio < 20%
    HIGH_SPEND      → spend > 70% of income
    LOW_BALANCE     → emergency_months < 3
    SALARY_CREDITED → transaction with category='salary' in last 30 days
    """
    user_id = payload["user_id"]
    cur = conn.cursor()

    # Fetch profile
    cur.execute(
        """SELECT monthly_income, monthly_spend, current_balance,
                  savings_ratio, emergency_fund_months, debt_amount,
                  debt_ratio, health_score
           FROM financial_profile WHERE user_id = %s""",
        (user_id,)
    )
    profile = cur.fetchone()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    income, spend, balance, s_ratio, emerg, debt_amt, debt_ratio, health = profile

    # Fetch recent events (alerts)
    cur.execute(
        """SELECT event_type, severity, description, triggered_at
           FROM events WHERE user_id = %s AND is_read = FALSE
           ORDER BY triggered_at DESC LIMIT 5""",
        (user_id,)
    )
    alerts = [
        {"type": r[0], "severity": r[1], "message": r[2], "at": str(r[3])}
        for r in cur.fetchall()
    ]

    # Build alert messages if none exist
    if not alerts:
        if float(s_ratio) < 20:
            alerts.append({"type": "LOW_SAVINGS", "severity": "warn", "message": f"Savings ratio is {s_ratio}% — aim for >20%", "at": str(datetime.utcnow())})
        if float(spend) > float(income) * 0.7:
            alerts.append({"type": "HIGH_SPEND", "severity": "danger", "message": "You're spending over 70% of income", "at": str(datetime.utcnow())})
        if float(emerg) < 3:
            alerts.append({"type": "LOW_EMERGENCY_FUND", "severity": "danger", "message": f"Emergency fund covers only {emerg} months", "at": str(datetime.utcnow())})

    return {
        "metrics": {
            "monthly_income": float(income),
            "current_balance": float(balance),
            "monthly_spend": float(spend),
            "savings_ratio": float(s_ratio),           # % of income saved
            "emergency_fund_months": float(emerg),     # months of spend covered
            "debt_ratio": float(debt_ratio),           # debt as % of income
            "health_score": int(health)                # 0–100
        },
        "alerts": alerts,
        "summary": _health_label(int(health))
    }


def _health_label(score: int) -> str:
    if score >= 80: return "Excellent"
    if score >= 60: return "Good"
    if score >= 40: return "Fair"
    return "Critical"


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 3: TRANSACTION + EVENT DETECTION ENGINE
#
# ═══════════════════════════════════════════════════════════════════════

@app.post("/transactions", tags=["Transactions"])
def add_transaction(body: TransactionRequest, payload=Depends(decode_token), conn=Depends(get_db)):
    """
    Add a transaction and run the event detection engine.

    EVENT DETECTION RULES:
    ─────────────────────────────────────────────────────
    SALARY_CREDIT   → txn_type=credit AND category=salary AND amount > 0
    HIGH_EXPENSE    → single debit > 30% of monthly income
    LOW_SAVINGS     → after update: savings_ratio < 20%
    SURPLUS_BALANCE → after update: savings_ratio > 40%
    """
    user_id = payload["user_id"]
    cur = conn.cursor()

    # 1. Save transaction
    cur.execute(
        """INSERT INTO transactions (user_id, amount, txn_type, category, description)
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (user_id, body.amount, body.txn_type, body.category, body.description)
    )
    txn_id = cur.fetchone()[0]

    # 2. Update financial profile
    cur.execute("SELECT monthly_income, monthly_spend, current_balance FROM financial_profile WHERE user_id=%s", (user_id,))
    row = cur.fetchone()
    income, spend, balance = float(row[0]), float(row[1]), float(row[2])

    if body.txn_type == "credit":
        balance += body.amount
        if body.category == "salary":
            income = body.amount          # Update income on salary credit
    else:
        balance -= body.amount
        spend += body.amount              # Accumulate monthly spend (simplified)

    # Recalculate derived fields
    savings_ratio = max(0, (income - spend) / income * 100) if income > 0 else 0
    monthly_expenses = spend / 12 if spend > 0 else 1
    emergency_months = balance / monthly_expenses if monthly_expenses > 0 else 0
    health_score = calculate_health_score(savings_ratio, emergency_months, income, spend)

    cur.execute(
        """UPDATE financial_profile
           SET monthly_income=%s, monthly_spend=%s, current_balance=%s,
               savings_ratio=%s, emergency_fund_months=%s, health_score=%s, updated_at=NOW()
           WHERE user_id=%s""",
        (income, spend, balance, savings_ratio, emergency_months, health_score, user_id)
    )

    # 3. EVENT DETECTION ENGINE
    events_detected = detect_events(
        user_id=user_id,
        txn_type=body.txn_type,
        category=body.category,
        amount=body.amount,
        income=income,
        savings_ratio=savings_ratio,
        emergency_months=emergency_months,
        cur=cur
    )

    conn.commit()
    return {
        "transaction_id": txn_id,
        "events_detected": events_detected,
        "updated_profile": {
            "balance": balance,
            "savings_ratio": round(savings_ratio, 2),
            "health_score": health_score
        }
    }


def detect_events(user_id, txn_type, category, amount, income, savings_ratio, emergency_months, cur) -> list:
    """
    RULE-BASED EVENT DETECTION ENGINE
    Runs on every transaction. Returns list of detected events.

    PSEUDOCODE:
    ─────────────────────────────────────────────────────
    IF txn_type == "credit" AND category == "salary":
        fire SALARY_CREDIT event

    IF txn_type == "debit" AND amount > income * 0.30:
        fire HIGH_EXPENSE event

    IF savings_ratio < 20:
        fire LOW_SAVINGS event

    IF savings_ratio > 40:
        fire SURPLUS_BALANCE event

    IF emergency_months < 3:
        fire LOW_EMERGENCY_FUND event
    """
    events = []

    # Rule 1: Salary credited
    if txn_type == "credit" and category == "salary":
        cur.execute(
            "INSERT INTO events (user_id, event_type, severity, description) VALUES (%s, %s, %s, %s)",
            (user_id, "SALARY_CREDIT", "success", f"Salary credited: ₹{amount:,.0f}")
        )
        events.append({"type": "SALARY_CREDIT", "severity": "success"})

    # Rule 2: High single expense
    if txn_type == "debit" and income > 0 and amount > income * 0.30:
        cur.execute(
            "INSERT INTO events (user_id, event_type, severity, description) VALUES (%s, %s, %s, %s)",
            (user_id, "HIGH_EXPENSE", "danger", f"Large expense detected: ₹{amount:,.0f} ({amount/income*100:.0f}% of income)")
        )
        events.append({"type": "HIGH_EXPENSE", "severity": "danger"})

    # Rule 3: Low savings
    if savings_ratio < 20:
        cur.execute(
            "INSERT INTO events (user_id, event_type, severity, description) VALUES (%s, %s, %s, %s)",
            (user_id, "LOW_SAVINGS", "warn", f"Savings ratio dropped to {savings_ratio:.1f}% — below 20% threshold")
        )
        events.append({"type": "LOW_SAVINGS", "severity": "warn"})

    # Rule 4: Surplus balance
    elif savings_ratio > 40:
        cur.execute(
            "INSERT INTO events (user_id, event_type, severity, description) VALUES (%s, %s, %s, %s)",
            (user_id, "SURPLUS_BALANCE", "success", f"Savings ratio at {savings_ratio:.1f}% — surplus available for investment")
        )
        events.append({"type": "SURPLUS_BALANCE", "severity": "success"})

    # Rule 5: Low emergency fund
    if emergency_months < 3:
        cur.execute(
            "INSERT INTO events (user_id, event_type, severity, description) VALUES (%s, %s, %s, %s)",
            (user_id, "LOW_EMERGENCY_FUND", "danger", f"Emergency fund covers only {emergency_months:.1f} months")
        )
        events.append({"type": "LOW_EMERGENCY_FUND", "severity": "danger"})

    return events


def calculate_health_score(savings_ratio, emergency_months, income, spend) -> int:
    """
    FINANCIAL HEALTH SCORE (0–100)
    ─────────────────────────────────────────────────────
    Component               Max Points  Formula
    ─────────────────────────────────────────────────────
    Savings ratio           30 pts      savings_ratio / 50 × 30 (capped at 30)
    Emergency fund          25 pts      min(emergency_months, 6) / 6 × 25
    Spend control           25 pts      (1 - spend/income) × 25 (if positive)
    Income adequacy         20 pts      min(income/30000, 1) × 20  (relative to 30k baseline)
    ─────────────────────────────────────────────────────
    Total: sum of all components, clamped to 0–100
    """
    savings_score = min(30, savings_ratio / 50 * 30)
    emergency_score = min(25, min(emergency_months, 6) / 6 * 25)
    spend_ratio = spend / income if income > 0 else 1
    spend_score = max(0, (1 - spend_ratio) * 25)
    income_score = min(20, income / 30000 * 20)
    total = savings_score + emergency_score + spend_score + income_score
    return max(0, min(100, round(total)))


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 4: RECOMMENDATION ENGINE (SUITABILITY SCORING)
#
# ═══════════════════════════════════════════════════════════════════════

PRODUCTS = [
    {
        "name": "Nifty 50 Index Fund SIP",
        "risk_level": "moderate",
        "min_savings_ratio": 20,
        "max_debt_ratio": 40,
        "min_emergency_months": 3,
        "requires_profile": ["moderate", "aggressive"],
        "cagr_est": "12–14%",
        "description": "Low-cost, diversified equity fund tracking India's top 50 companies."
    },
    {
        "name": "Liquid Fund",
        "risk_level": "low",
        "min_savings_ratio": 5,
        "max_debt_ratio": 80,
        "min_emergency_months": 0,
        "requires_profile": ["conservative", "moderate", "aggressive"],
        "cagr_est": "6–7%",
        "description": "Safe, high-liquidity investment. Ideal for building emergency funds."
    },
    {
        "name": "Small Cap Equity Fund",
        "risk_level": "aggressive",
        "min_savings_ratio": 30,
        "max_debt_ratio": 20,
        "min_emergency_months": 6,
        "requires_profile": ["aggressive"],
        "cagr_est": "15–20%",
        "description": "High-risk, high-reward fund targeting emerging small companies."
    },
    {
        "name": "Fixed Deposit (5 Year)",
        "risk_level": "low",
        "min_savings_ratio": 10,
        "max_debt_ratio": 70,
        "min_emergency_months": 1,
        "requires_profile": ["conservative", "moderate"],
        "cagr_est": "6.5–7.5%",
        "description": "Guaranteed returns, capital protection, no market exposure."
    }
]

RISK_WEIGHTS = {"conservative": 0, "moderate": 1, "aggressive": 2}


@app.get("/recommendations", tags=["Recommendations"])
def get_recommendations(payload=Depends(decode_token), conn=Depends(get_db)):
    """
    RECOMMENDATION PIPELINE:
    1. Fetch user financial profile
    2. Score each product using suitability formula
    3. Run ethical guardrails (may block certain products)
    4. Generate XAI explanation for each
    5. Return sorted recommendations

    SUITABILITY SCORE FORMULA (0–100):
    ─────────────────────────────────────────────────────
    savings_score    = min(30, savings_ratio / 50 × 30)     [weight: 30%]
    emergency_score  = min(25, emergency_months / 6 × 25)   [weight: 25%]
    risk_match_score = 20 if profile matches, 10 if partial  [weight: 20%]
    income_score     = min(15, income / 50000 × 15)         [weight: 15%]
    debt_score       = max(0, (1 - debt_ratio/100) × 10)    [weight: 10%]
    ─────────────────────────────────────────────────────
    total = sum, clamped to 0–100
    confidence = total × 0.95 (slight discount for model uncertainty)
    """
    user_id = payload["user_id"]
    cur = conn.cursor()

    cur.execute(
        """SELECT u.risk_profile, u.age,
                  fp.monthly_income, fp.savings_ratio, fp.emergency_fund_months,
                  fp.debt_ratio, fp.monthly_spend
           FROM users u JOIN financial_profile fp ON u.id = fp.user_id
           WHERE u.id = %s""",
        (user_id,)
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    risk_profile, age, income, s_ratio, emerg, debt_ratio, spend = row
    income, s_ratio, emerg, debt_ratio = float(income), float(s_ratio), float(emerg), float(debt_ratio)

    results = []
    for product in PRODUCTS:
        score, reasons, blocked, block_reasons = score_product(
            product, income, s_ratio, emerg, debt_ratio, risk_profile, age
        )

        # Build XAI explanation
        explanation = build_explanation(product, reasons, blocked, block_reasons)

        # Save recommendation to DB
        cur.execute(
            """INSERT INTO recommendations
               (user_id, product_name, suitability_pct, risk_level, confidence_score,
                guardrail_pass, blocked_reasons, reason_codes)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (user_id, product["name"], score,
             product["risk_level"],
             round(score * 0.95),
             not blocked,
             block_reasons,
             str(reasons))
        )

        results.append({
            "product": product["name"],
            "description": product["description"],
            "suitability_pct": score,
            "confidence_score": round(score * 0.95),
            "risk_level": product["risk_level"],
            "cagr_estimate": product["cagr_est"],
            "guardrail_pass": not blocked,
            "block_reasons": block_reasons,
            "explanation": explanation,
            "reason_codes": reasons
        })

    conn.commit()
    results.sort(key=lambda x: (x["guardrail_pass"], x["suitability_pct"]), reverse=True)
    return {"recommendations": results, "total": len(results)}


def score_product(product, income, s_ratio, emerg, debt_ratio, risk_profile, age) -> tuple:
    """
    SCORING FUNCTION — runs per product.
    Returns: (score, reason_codes, is_blocked, block_reasons)
    """
    reasons = []
    block_reasons = []

    # ─── SCORE COMPONENTS ───────────────────────────────
    # 1. Savings score (30 pts)
    savings_score = min(30, s_ratio / 50 * 30)
    reasons.append({
        "code": "SAVINGS_RATIO",
        "label": f"Savings ratio {s_ratio:.1f}%",
        "score": round(savings_score),
        "weight": 0.30,
        "signal": f"savings_ratio = {s_ratio:.1f}%"
    })

    # 2. Emergency fund score (25 pts)
    emergency_score = min(25, emerg / 6 * 25)
    reasons.append({
        "code": "EMERGENCY_FUND",
        "label": f"Emergency fund {emerg:.1f} months",
        "score": round(emergency_score),
        "weight": 0.25,
        "signal": f"emergency_months = {emerg:.1f}"
    })

    # 3. Risk profile match (20 pts)
    risk_score = 0
    user_risk_val = RISK_WEIGHTS.get(risk_profile, 1)
    prod_risk_val = RISK_WEIGHTS.get(product["risk_level"], 1)
    if risk_profile in product["requires_profile"]:
        risk_score = 20
    elif abs(user_risk_val - prod_risk_val) == 1:
        risk_score = 10       # Partial match (one level off)
    reasons.append({
        "code": "RISK_MATCH",
        "label": f"Risk profile {risk_profile} vs product {product['risk_level']}",
        "score": risk_score,
        "weight": 0.20,
        "signal": f"user={risk_profile}, product={product['risk_level']}"
    })

    # 4. Income score (15 pts)
    income_score = min(15, income / 50000 * 15)
    reasons.append({
        "code": "INCOME_LEVEL",
        "label": f"Monthly income ₹{income:,.0f}",
        "score": round(income_score),
        "weight": 0.15,
        "signal": f"income = {income}"
    })

    # 5. Debt score (10 pts)
    debt_score = max(0, (1 - debt_ratio / 100) * 10)
    reasons.append({
        "code": "DEBT_STATUS",
        "label": f"Debt ratio {debt_ratio:.1f}%",
        "score": round(debt_score),
        "weight": 0.10,
        "signal": f"debt_ratio = {debt_ratio:.1f}%"
    })

    total = savings_score + emergency_score + risk_score + income_score + debt_score
    score = max(0, min(100, round(total)))

    # ─── ETHICAL GUARDRAILS ─────────────────────────────
    # Rule 1: No equity if emergency fund < 3 months
    if product["risk_level"] in ["moderate", "aggressive"] and emerg < product["min_emergency_months"]:
        block_reasons.append("INSUFFICIENT_EMERGENCY_FUND")

    # Rule 2: No investment if debt ratio too high
    if debt_ratio > product["max_debt_ratio"]:
        block_reasons.append("HIGH_DEBT_RATIO")

    # Rule 3: Risk profile mismatch (strict)
    if risk_profile not in product["requires_profile"] and prod_risk_val > user_risk_val + 1:
        block_reasons.append("RISK_MISMATCH")

    # Rule 4: Savings too low for this product
    if s_ratio < product["min_savings_ratio"]:
        block_reasons.append("INSUFFICIENT_SAVINGS")

    is_blocked = len(block_reasons) > 0
    return score, reasons, is_blocked, block_reasons


def build_explanation(product, reasons, blocked, block_reasons) -> dict:
    """
    EXPLAINABLE AI (XAI) LAYER
    Generates human-readable explanation for each recommendation.
    No black box — every signal is visible.
    """
    top_reasons = sorted(reasons, key=lambda r: r["score"], reverse=True)[:3]

    if blocked:
        text = (
            f"This product is blocked because: "
            + ", ".join([r.replace("_", " ").title() for r in block_reasons])
            + ". Please resolve these issues before investing."
        )
    else:
        top = top_reasons[0]["label"] if top_reasons else "your profile"
        text = (
            f"Recommended because {top}. "
            f"Your financial signals align well with {product['name']}. "
            f"All ethical guardrails have passed."
        )

    return {
        "summary": text,
        "top_signals": top_reasons,
        "blocked": blocked,
        "block_reasons": block_reasons,
        "transparency_note": "This recommendation uses rule-based scoring. No black-box AI."
    }


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 5: INVESTMENT GROWTH PROJECTION (SIP CALCULATOR)
#
# ═══════════════════════════════════════════════════════════════════════

@app.post("/growth/projection", tags=["Growth"])
def sip_projection(body: SIPRequest, payload=Depends(decode_token)):
    """
    SIP GROWTH CALCULATOR

    FORMULA (Compound Interest for SIP):
    ─────────────────────────────────────────────────────
    r = CAGR / 12 / 100                  (monthly rate)
    n = years × 12                        (total months)
    FV = P × [((1 + r)^n - 1) / r] × (1 + r)

    This is the standard Future Value of Annuity Due formula.
    ─────────────────────────────────────────────────────
    Example: ₹10,000/month, 12% CAGR
      r = 0.01
      5yr: FV ≈ ₹8,16,697
      10yr: FV ≈ ₹23,23,391
    """
    P = body.monthly_amount
    r = body.cagr / 12 / 100

    def fv(months):
        if r == 0:
            return P * months
        return P * (((1 + r) ** months - 1) / r) * (1 + r)

    yearly_data = []
    for year in range(1, 11):
        months = year * 12
        invested = P * months
        total = fv(months)
        yearly_data.append({
            "year": year,
            "invested": round(invested, 2),
            "total_value": round(total, 2),
            "gain": round(total - invested, 2),
            "growth_pct": round((total - invested) / invested * 100, 1) if invested > 0 else 0
        })

    fv_5y = fv(60)
    fv_10y = fv(120)
    inv_5y = P * 60
    inv_10y = P * 120

    return {
        "inputs": {
            "monthly_sip": P,
            "annual_cagr_pct": body.cagr,
            "monthly_rate": round(r, 6)
        },
        "projections": {
            "5_year": {
                "total_value": round(fv_5y, 2),
                "total_invested": round(inv_5y, 2),
                "total_gain": round(fv_5y - inv_5y, 2),
                "gain_pct": round((fv_5y - inv_5y) / inv_5y * 100, 1)
            },
            "10_year": {
                "total_value": round(fv_10y, 2),
                "total_invested": round(inv_10y, 2),
                "total_gain": round(fv_10y - inv_10y, 2),
                "gain_pct": round((fv_10y - inv_10y) / inv_10y * 100, 1)
            }
        },
        "chart_data": yearly_data,          # Ready to plug into Chart.js or Recharts
        "formula_note": "FV = P × [((1+r)^n - 1) / r] × (1+r) — standard SIP annuity formula"
    }


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 6: DEMO SIMULATION MODE
#
# ═══════════════════════════════════════════════════════════════════════

@app.post("/demo/simulate/{scenario}", tags=["Demo"])
def simulate_scenario(scenario: str, payload=Depends(decode_token), conn=Depends(get_db)):
    """
    DEMO MODE — Simulate financial scenarios for hackathon/demo.

    Scenarios:
    ─────────────────────────────────────────────────────
    salary_credit   → Injects ₹85,000 credit, category=salary
    high_expense    → Injects ₹35,000 debit (>30% of income → HIGH_EXPENSE event)
    low_balance     → Sets balance to ₹3,000 (< 3 months emergency fund)
    surplus         → Sets savings to 45%, balance to ₹2L

    Usage in frontend:
    POST /demo/simulate/salary_credit
    POST /demo/simulate/high_expense
    """
    user_id = payload["user_id"]
    cur = conn.cursor()

    scenarios = {
        "salary_credit": {
            "amount": 85000, "txn_type": "credit", "category": "salary",
            "description": "Monthly salary — demo simulation"
        },
        "high_expense": {
            "amount": 35000, "txn_type": "debit", "category": "lifestyle",
            "description": "High discretionary spend — demo simulation"
        },
        "low_balance": {
            "override": {"current_balance": 3000, "emergency_fund_months": 0.8, "health_score": 25},
            "description": "Low balance scenario — demo simulation"
        },
        "surplus": {
            "override": {"current_balance": 200000, "savings_ratio": 45, "emergency_fund_months": 7.5, "health_score": 88},
            "description": "Surplus scenario — demo simulation"
        }
    }

    if scenario not in scenarios:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose: {list(scenarios.keys())}")

    s = scenarios[scenario]

    if "override" in s:
        # Direct override for quick simulation
        sets = ", ".join([f"{k}=%s" for k in s["override"].keys()])
        cur.execute(
            f"UPDATE financial_profile SET {sets}, updated_at=NOW() WHERE user_id=%s",
            (*s["override"].values(), user_id)
        )
        # Record an event
        cur.execute(
            "INSERT INTO events (user_id, event_type, severity, description) VALUES (%s, %s, %s, %s)",
            (user_id, scenario.upper(), "info", s["description"])
        )
        conn.commit()
        return {"simulated": scenario, "message": s["description"], "overrides": s["override"]}
    else:
        # Use the real transaction flow
        conn.commit()
        from fastapi.testclient import TestClient
        # In production, call the transaction logic directly:
        txn = TransactionRequest(
            amount=s["amount"], txn_type=s["txn_type"],
            category=s["category"], description=s["description"]
        )
        result = add_transaction(txn, payload, conn)
        return {"simulated": scenario, "result": result}


# ═══════════════════════════════════════════════════════════════════════
#
#  MODULE 7: USER FEEDBACK (LEARNING LOOP)
#
# ═══════════════════════════════════════════════════════════════════════

@app.post("/feedback", tags=["Feedback"])
def submit_feedback(body: FeedbackRequest, payload=Depends(decode_token), conn=Depends(get_db)):
    """
    LEARNING LOOP:
    User accepts/rejects recommendations → stored in feedback table.
    This data can later be used to:
    1. Tune scoring weights per user segment
    2. Flag products with consistently low acceptance
    3. Detect user preference drift

    For now (rule-based system): we store and report acceptance rate.
    In a future ML version, this becomes training data.
    """
    user_id = payload["user_id"]
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO user_feedback (user_id, recommendation_id, rating, accepted, feedback_text)
           VALUES (%s, %s, %s, %s, %s)""",
        (user_id, body.recommendation_id, body.rating, body.accepted, body.feedback_text)
    )
    conn.commit()

    # Calculate acceptance rate for this product
    cur.execute(
        """SELECT AVG(CASE WHEN accepted THEN 1 ELSE 0 END) as acceptance_rate,
                  COUNT(*) as total_feedback
           FROM user_feedback uf
           JOIN recommendations r ON uf.recommendation_id = r.id
           WHERE r.product_name = (SELECT product_name FROM recommendations WHERE id=%s)""",
        (body.recommendation_id,)
    )
    stats = cur.fetchone()
    return {
        "status": "feedback_recorded",
        "acceptance_rate": round(float(stats[0] or 0) * 100, 1),
        "total_feedback_count": stats[1],
        "learning_note": "Feedback stored. Will influence future scoring adjustments."
    }


# ═══════════════════════════════════════════════════════════════════════
#
#  HEALTH CHECK
#
# ═══════════════════════════════════════════════════════════════════════

@app.get("/health", tags=["System"])
def health():
    return {"status": "ok", "app": "NovaMint API", "version": "1.0.0"}


# ═══════════════════════════════════════════════════════════════════════
#
#  END-TO-END SYSTEM FLOW (for reference)
#
# ═══════════════════════════════════════════════════════════════════════
"""
COMPLETE SYSTEM FLOW:
═══════════════════════════════════════════════════════════════════════

1. USER LOGIN  →  POST /auth/login
   - Verify email + bcrypt password
   - Return JWT token
   - Frontend stores token in localStorage

2. TRANSACTION UPDATE  →  POST /transactions
   - Frontend sends: {amount, type, category}
   - Backend updates financial_profile (balance, spend, savings_ratio)

3. EVENT DETECTION  →  (runs inside /transactions)
   - detect_events() checks all rules
   - Fires events: SALARY_CREDIT / HIGH_EXPENSE / LOW_SAVINGS / SURPLUS
   - Stores events in events table

4. DASHBOARD  →  GET /dashboard
   - Returns metrics + alerts
   - Frontend shows health score, charts, alerts

5. RECOMMENDATION  →  GET /recommendations
   - score_product() scores each product 0–100
   - Guardrails run (ethical checks)
   - XAI explanation generated

6. GUARDRAIL CHECK  →  (inside score_product)
   - BLOCK if emergency < 3 months AND product is equity
   - BLOCK if debt > threshold
   - BLOCK if risk mismatch is severe

7. EXPLAINABLE AI  →  (inside build_explanation)
   - Returns reason_codes with weights
   - Human-readable summary text
   - No black box — every decision traceable

8. USER FEEDBACK  →  POST /feedback
   - User rates recommendation 1–5
   - Records accepted/rejected
   - Future: adjusts scoring weights per user segment

═══════════════════════════════════════════════════════════════════════
"""
