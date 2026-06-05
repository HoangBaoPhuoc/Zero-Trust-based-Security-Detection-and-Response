# ZTLab - core-banking

import os
import uuid
from fastapi import FastAPI, Request, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP, TXN_TOTAL

SERVICE = "core-banking"
CLOUD = "openstack"
MAX_FRAUD_SCORE = int(os.getenv("MAX_ALLOWED_FRAUD_SCORE", os.getenv("MAX_FRAUD_SCORE", "74")))

app = FastAPI(title="ZTLab Core Banking API")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)


class ExecuteTransactionRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    trace_id: str = ""


@app.post("/transactions/execute")
async def execute_transaction(req: Request, body: ExecuteTransactionRequest):
    trace_id = body.trace_id or req.headers.get("X-Trace-ID", "")
    fraud_gate = req.headers.get("X-Fraud-Gate", "")
    try:
        fraud_score = int(req.headers.get("X-Fraud-Score", "999"))
    except ValueError:
        fraud_score = 999

    if fraud_gate != "passed" or fraud_score > MAX_FRAUD_SCORE:
        TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="core_execute", status="fraud_gate_denied").inc()
        logger.audit(
            "fraud_gate_bypass",
            trace_id=trace_id,
            fraud_gate=fraud_gate,
            fraud_score=fraud_score,
            max_fraud_score=MAX_FRAUD_SCORE,
            from_account=body.from_account,
            to_account=body.to_account,
        )
        raise HTTPException(status_code=403, detail="fraud gate validation failed")

    transaction_id = str(uuid.uuid4())
    TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="core_execute", status="completed").inc()
    logger.audit(
        "core_transaction_completed",
        trace_id=trace_id,
        transaction_id=transaction_id,
        amount=body.amount,
        currency=body.currency,
        fraud_score=fraud_score,
    )
    return {"transaction_id": transaction_id, "status": "completed", "trace_id": trace_id}


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
