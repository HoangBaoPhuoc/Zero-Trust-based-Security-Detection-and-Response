# ZTLab - account-service

from fastapi import FastAPI, HTTPException
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP

SERVICE = "account-service"
CLOUD = "openstack"

app = FastAPI(title="ZTLab Account Service")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)

_accounts: dict[str, dict] = {
    "ACC-1001": {"account_id": "ACC-1001", "owner": "testuser01", "balance": 1000000000.0, "currency": "VND"},
    "ACC-2001": {"account_id": "ACC-2001", "owner": "merchant01", "balance": 250000000.0, "currency": "VND"},
}


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


@app.post("/accounts")
async def create_account(body: AccountCreate):
    if body.account_id in _accounts:
        raise HTTPException(status_code=409, detail="account already exists")
    _accounts[body.account_id] = body.model_dump()
    logger.audit("account_created", account_id=body.account_id, owner=body.owner)
    return _accounts[body.account_id]


@app.get("/accounts/{account_id}")
async def get_account(account_id: str):
    account = _accounts.get(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="account not found")
    return account


@app.post("/accounts/transfer")
async def transfer(body: TransferRequest):
    source = _accounts.get(body.from_account)
    target = _accounts.get(body.to_account)
    if not source or not target:
        raise HTTPException(status_code=404, detail="source or target account not found")
    if source["currency"] != body.currency or target["currency"] != body.currency:
        raise HTTPException(status_code=400, detail="currency mismatch")
    if source["balance"] < body.amount:
        raise HTTPException(status_code=409, detail="insufficient balance")
    source["balance"] -= body.amount
    target["balance"] += body.amount
    logger.audit("account_transfer_applied", from_account=body.from_account, to_account=body.to_account, amount=body.amount)
    return {"status": "applied", "from_balance": source["balance"], "to_balance": target["balance"]}


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
