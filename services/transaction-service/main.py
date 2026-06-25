# ZTLab - transaction-service

import os
import uuid
import asyncpg
from contextlib import asynccontextmanager
from collections import defaultdict
from fastapi import FastAPI
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP, TXN_TOTAL

SERVICE = "transaction-service"
CLOUD = os.getenv("CLOUD_PROVIDER", "aws")

DB_HOST = os.getenv("TXN_DB_HOST", "localhost")
DB_PORT = int(os.getenv("TXN_DB_PORT", "5432"))
DB_NAME = os.getenv("TXN_DB_NAME", "transactions_db")
DB_USER = os.getenv("TXN_DB_USER", "txn_user")
DB_PASS = os.getenv("TXN_DB_PASS", "txn_pass")

pool: asyncpg.Pool | None = None

logger = ZTLabLogger(SERVICE, CLOUD)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    import asyncio
    for attempt in range(10):
        try:
            pool = await asyncpg.create_pool(
                host=DB_HOST, port=DB_PORT, database=DB_NAME,
                user=DB_USER, password=DB_PASS, min_size=2, max_size=10,
            )
            break
        except Exception:
            if attempt == 9:
                raise
            await asyncio.sleep(3)
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            transaction_id TEXT    PRIMARY KEY,
            from_account   TEXT    NOT NULL,
            to_account     TEXT    NOT NULL,
            amount         NUMERIC NOT NULL,
            currency       TEXT    NOT NULL DEFAULT 'VND',
            status         TEXT    NOT NULL DEFAULT 'completed',
            trace_id       TEXT    NOT NULL DEFAULT '',
            created_at     DOUBLE PRECISION NOT NULL
        )
    """)
    SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)
    yield
    await pool.close()


app = FastAPI(title="ZTLab Transaction Service", lifespan=lifespan)
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())


class LedgerRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    status: str = "completed"
    trace_id: str = ""


@app.post("/transactions")
async def create_transaction(body: LedgerRequest):
    import time
    record = {
        "transaction_id": str(uuid.uuid4()),
        "created_at": time.time(),
        **body.model_dump(),
    }
    await pool.execute(
        """INSERT INTO ledger
           (transaction_id, from_account, to_account, amount, currency, status, trace_id, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
        record["transaction_id"], record["from_account"], record["to_account"],
        record["amount"], record["currency"], record["status"],
        record["trace_id"], record["created_at"],
    )
    TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="ledger", status=body.status).inc()
    logger.audit("ledger_record_created", **record)
    return record


@app.get("/transactions")
async def list_transactions(account_id: str | None = None, limit: int = 100):
    limit = max(1, min(limit, 500))
    if account_id:
        rows = await pool.fetch(
            "SELECT * FROM ledger WHERE from_account=$1 OR to_account=$1 ORDER BY created_at DESC LIMIT $2",
            account_id, limit,
        )
    else:
        rows = await pool.fetch(
            "SELECT * FROM ledger ORDER BY created_at DESC LIMIT $1", limit
        )
    return [dict(r) for r in rows]


@app.get("/stats/velocity/{account_id}")
async def account_velocity(account_id: str, window_seconds: int = 90 * 24 * 3600):
    import time
    cutoff = time.time() - window_seconds
    rows = await pool.fetch(
        """SELECT status, amount FROM ledger
           WHERE (from_account=$1 OR to_account=$1) AND created_at >= $2""",
        account_id, cutoff,
    )
    totals: dict[str, float] = defaultdict(float)
    for row in rows:
        totals[row["status"]] += float(row["amount"])
    return {"account_id": account_id, "count": len(rows), "amount_by_status": dict(totals)}


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
