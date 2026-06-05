# ZTLab - transaction-service

import time
import uuid
from collections import defaultdict
from fastapi import FastAPI
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP, TXN_TOTAL

SERVICE = "transaction-service"
CLOUD = "openstack"

app = FastAPI(title="ZTLab Transaction Service")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)

_ledger: list[dict] = []


class LedgerRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    status: str = "completed"
    trace_id: str = ""


@app.post("/transactions")
async def create_transaction(body: LedgerRequest):
    record = {
        "transaction_id": str(uuid.uuid4()),
        "created_at": time.time(),
        **body.model_dump(),
    }
    _ledger.append(record)
    TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="ledger", status=body.status).inc()
    logger.audit("ledger_record_created", **record)
    return record


@app.get("/transactions")
async def list_transactions(account_id: str | None = None, limit: int = 100):
    rows = _ledger
    if account_id:
        rows = [row for row in rows if row["from_account"] == account_id or row["to_account"] == account_id]
    return rows[-max(1, min(limit, 500)):]


@app.get("/stats/velocity/{account_id}")
async def account_velocity(account_id: str, window_seconds: int = 90 * 24 * 3600):
    now = time.time()
    rows = [
        row for row in _ledger
        if now - row["created_at"] <= window_seconds and (row["from_account"] == account_id or row["to_account"] == account_id)
    ]
    totals = defaultdict(float)
    for row in rows:
        totals[row["status"]] += row["amount"]
    return {"account_id": account_id, "count": len(rows), "amount_by_status": dict(totals)}


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
