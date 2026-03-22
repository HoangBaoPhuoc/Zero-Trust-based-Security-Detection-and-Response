# ZTLab - core-banking
# Source: IMPLEMENTATION.md §6.6
# See MAP.md §10 for context and edit guidance

import os
import uuid
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ZTLab Core Banking API")
MAX_FRAUD_SCORE = int(os.getenv("MAX_ALLOWED_FRAUD_SCORE", "74"))

class ExecuteTransactionRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float
    currency: str = "VND"
    trace_id: str = ""

@app.post("/transactions/execute")
async def execute_transaction(req: Request, body: ExecuteTransactionRequest):
    fraud_gate = req.headers.get("X-Fraud-Gate", "")
    fraud_score = int(req.headers.get("X-Fraud-Score", "999"))

    if fraud_gate != "passed" or fraud_score > MAX_FRAUD_SCORE:
        raise HTTPException(status_code=403, detail="fraud gate validation failed")

    return {
        "transaction_id": str(uuid.uuid4()),
        "status": "completed",
        "trace_id": body.trace_id or req.headers.get("X-Trace-ID", "")
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "core-banking", "cloud": "openstack"}
