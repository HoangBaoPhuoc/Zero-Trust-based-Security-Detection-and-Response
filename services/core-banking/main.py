# ZTLab - core-banking

import os
import uuid
import httpx
from fastapi import FastAPI, Request, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP, TXN_TOTAL

SERVICE = "core-banking"
CLOUD = os.getenv("CLOUD_PROVIDER", "aws")
MAX_FRAUD_SCORE = int(os.getenv("MAX_ALLOWED_FRAUD_SCORE", os.getenv("MAX_FRAUD_SCORE", "74")))
ACCOUNT_SERVICE_URL = os.getenv("ACCOUNT_SERVICE_URL", "http://account-service:8080").rstrip("/")
TRANSACTION_SERVICE_URL = os.getenv("TRANSACTION_SERVICE_URL", "http://transaction-service:8080").rstrip("/")

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

    downstream_headers = {"X-Trace-ID": trace_id}

    # Debit/credit via account-service (atomic DB transfer)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            acct_resp = await client.post(
                f"{ACCOUNT_SERVICE_URL}/accounts/transfer",
                json={
                    "from_account": body.from_account,
                    "to_account": body.to_account,
                    "amount": body.amount,
                    "currency": body.currency,
                },
                headers=downstream_headers,
            )
            acct_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            detail = exc.response.text
            TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="core_execute", status=f"account_error_{status_code}").inc()
            logger.warn("account_service_error", trace_id=trace_id, status_code=status_code, detail=detail)
            raise HTTPException(status_code=status_code, detail=detail) from exc
        except Exception as exc:
            TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="core_execute", status="account_unavailable").inc()
            logger.error("account_service_unavailable", trace_id=trace_id, error=str(exc))
            raise HTTPException(status_code=503, detail="account service unavailable") from exc

        acct_data = acct_resp.json()
        transaction_id = str(uuid.uuid4())

        # Record in ledger (best-effort)
        try:
            await client.post(
                f"{TRANSACTION_SERVICE_URL}/transactions",
                json={
                    "from_account": body.from_account,
                    "to_account": body.to_account,
                    "amount": body.amount,
                    "currency": body.currency,
                    "status": "completed",
                    "trace_id": trace_id,
                },
                headers=downstream_headers,
            )
        except Exception as exc:
            logger.warn("transaction_ledger_failed", trace_id=trace_id, transaction_id=transaction_id, error=str(exc))

    TXN_TOTAL.labels(service=SERVICE, cloud=CLOUD, type="core_execute", status="completed").inc()
    logger.audit(
        "core_transaction_completed",
        trace_id=trace_id,
        transaction_id=transaction_id,
        amount=body.amount,
        currency=body.currency,
        fraud_score=fraud_score,
        from_balance=acct_data.get("from_balance"),
        to_balance=acct_data.get("to_balance"),
    )
    return {
        "transaction_id": transaction_id,
        "status": "completed",
        "trace_id": trace_id,
        "from_balance": acct_data.get("from_balance"),
        "to_balance": acct_data.get("to_balance"),
    }


@app.post("/accounts")
async def create_account(request: Request):
    body = await request.json()
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.post(f"{ACCOUNT_SERVICE_URL}/accounts", json=body)
            if resp.status_code == 409:
                raise HTTPException(status_code=409, detail="account_id already exists")
            resp.raise_for_status()
            return resp.json()
        except HTTPException:
            raise
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/accounts")
async def list_accounts(owner: str = ""):
    params = {"owner": owner} if owner else {}
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{ACCOUNT_SERVICE_URL}/accounts", params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/accounts/{account_id}")
async def get_account(account_id: str):
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{ACCOUNT_SERVICE_URL}/accounts/{account_id}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/transactions")
async def list_transactions(account_id: str = "", limit: int = 20):
    params: dict = {"limit": min(limit, 100)}
    if account_id:
        params["account_id"] = account_id
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{TRANSACTION_SERVICE_URL}/transactions", params=params)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="transaction service unavailable") from exc


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
