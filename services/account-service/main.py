# ZTLab - account-service

import os
import asyncpg
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP

SERVICE = "account-service"
CLOUD = os.getenv("CLOUD_PROVIDER", "aws")

DB_HOST = os.getenv("ACCOUNTS_DB_HOST", "localhost")
DB_PORT = int(os.getenv("ACCOUNTS_DB_PORT", "5432"))
DB_NAME = os.getenv("ACCOUNTS_DB_NAME", "accounts_db")
DB_USER = os.getenv("ACCOUNTS_DB_USER", "accounts_user")
DB_PASS = os.getenv("ACCOUNTS_DB_PASS", "accounts_pass")

pool: asyncpg.Pool | None = None

logger = ZTLabLogger(SERVICE, CLOUD)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(
        host=DB_HOST, port=DB_PORT, database=DB_NAME,
        user=DB_USER, password=DB_PASS, min_size=2, max_size=10,
    )
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            owner      TEXT    NOT NULL,
            balance    NUMERIC NOT NULL DEFAULT 0,
            currency   TEXT    NOT NULL DEFAULT 'VND'
        )
    """)
    await pool.execute("""
        INSERT INTO accounts (account_id, owner, balance, currency) VALUES
            ('ACC-1001', 'testuser01',  48500000.0, 'VND'),
            ('ACC-2001', 'testuser02',  31200000.0, 'VND'),
            ('ACC-3001', 'demoadmin',  100000000.0, 'VND'),
            ('ACC-4001', 'merchant01',  26750000.0, 'VND'),
            ('ACC-5001', 'analyst01',   10000000.0, 'VND')
        ON CONFLICT DO NOTHING
    """)
    SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)
    yield
    await pool.close()


app = FastAPI(title="ZTLab Account Service", lifespan=lifespan)
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())


class AccountCreate(BaseModel):
    account_id: str
    owner: str
    balance: float = Field(default=0, ge=0)
    currency: str = "VND"


class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"


@app.get("/accounts")
async def list_accounts(owner: str | None = None, limit: int = 50):
    if owner:
        rows = await pool.fetch("SELECT * FROM accounts WHERE owner = $1", owner)
    else:
        rows = await pool.fetch("SELECT * FROM accounts ORDER BY account_id LIMIT $1", limit)
    return [dict(r) for r in rows]


@app.post("/accounts", status_code=201)
async def create_account(body: AccountCreate):
    try:
        row = await pool.fetchrow(
            "INSERT INTO accounts (account_id, owner, balance, currency) VALUES ($1,$2,$3,$4) RETURNING *",
            body.account_id, body.owner, body.balance, body.currency,
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="account already exists")
    logger.audit("account_created", account_id=body.account_id, owner=body.owner)
    return dict(row)


@app.get("/accounts/{account_id}")
async def get_account(account_id: str):
    row = await pool.fetchrow("SELECT * FROM accounts WHERE account_id = $1", account_id)
    if not row:
        raise HTTPException(status_code=404, detail="account not found")
    return dict(row)


@app.post("/accounts/transfer")
async def transfer(body: TransferRequest):
    async with pool.acquire() as conn:
        async with conn.transaction():
            source = await conn.fetchrow(
                "SELECT * FROM accounts WHERE account_id = $1 FOR UPDATE", body.from_account
            )
            target = await conn.fetchrow(
                "SELECT * FROM accounts WHERE account_id = $1 FOR UPDATE", body.to_account
            )
            if not source or not target:
                raise HTTPException(status_code=404, detail="source or target account not found")
            if source["currency"] != body.currency or target["currency"] != body.currency:
                raise HTTPException(status_code=400, detail="currency mismatch")
            if source["balance"] < body.amount:
                raise HTTPException(status_code=409, detail="insufficient balance")
            new_src = float(source["balance"]) - body.amount
            new_tgt = float(target["balance"]) + body.amount
            await conn.execute(
                "UPDATE accounts SET balance = $1 WHERE account_id = $2", new_src, body.from_account
            )
            await conn.execute(
                "UPDATE accounts SET balance = $1 WHERE account_id = $2", new_tgt, body.to_account
            )
    logger.audit(
        "account_transfer_applied",
        from_account=body.from_account, to_account=body.to_account, amount=body.amount,
    )
    return {"status": "applied", "from_balance": new_src, "to_balance": new_tgt}


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
