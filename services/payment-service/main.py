# ZTLab - payment-service
# Source: IMPLEMENTATION.md §6.4
# See MAP.md §10 for context and edit guidance

import os
import time
import uuid
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="ZTLab Payment Service")
FRAUD_URL = os.getenv("FRAUD_SERVICE_URL", "http://fraud-detection:8080")
CORE_BANKING_URL = os.getenv("CORE_BANKING_URL", "http://core-banking:8080")
MAX_SINGLE_TXN = int(os.getenv("MAX_SINGLE_TXN_VND", str(500_000_000)))

class PaymentRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = Field(default="VND")
    channel: str = Field(default="api")

@app.post("/payments")
async def process_payment(req: Request, body: PaymentRequest):
    if body.amount > MAX_SINGLE_TXN:
        raise HTTPException(status_code=400, detail="amount exceeds MAX_SINGLE_TXN_VND")

    trace_id = req.headers.get("X-Trace-ID", str(uuid.uuid4()))
    return {
        "transaction_id": str(uuid.uuid4()),
        "status": "queued",
        "trace_id": trace_id,
        "fraud_service": FRAUD_URL,
        "core_banking": CORE_BANKING_URL,
        "note": "TODO: implement fraud gate orchestration from IMPLEMENTATION.md §6.4"
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "payment-service", "cloud": "aws", "ts": time.time()}
