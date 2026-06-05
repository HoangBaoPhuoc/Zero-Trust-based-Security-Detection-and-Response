# ZTLab - fraud-detection

import os
import time
from collections import defaultdict, deque
from pydantic import BaseModel, Field
from fastapi import FastAPI
from prometheus_client import make_asgi_app

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import FRAUD_SCORE, SERVICE_UP

SERVICE = "fraud-detection"
CLOUD = "aws"
VELOCITY_WINDOW_SECONDS = int(os.getenv("FRAUD_VELOCITY_WINDOW_SECONDS", "60"))
VELOCITY_SOFT_LIMIT = int(os.getenv("FRAUD_VELOCITY_SOFT_LIMIT", "10"))
HIGH_AMOUNT_VND = float(os.getenv("FRAUD_HIGH_AMOUNT_VND", "100000000"))
CRITICAL_AMOUNT_VND = float(os.getenv("FRAUD_CRITICAL_AMOUNT_VND", "500000000"))

app = FastAPI(title="ZTLab Fraud Detection")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)

_recent_by_account: dict[str, deque[float]] = defaultdict(deque)


class FraudRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    channel: str = "api"
    country: str | None = None


class FraudResponse(BaseModel):
    score: int
    verdict: str
    reason: list[str]
    gate: str


def _velocity_score(account: str) -> tuple[int, int]:
    now = time.time()
    bucket = _recent_by_account[account]
    while bucket and now - bucket[0] > VELOCITY_WINDOW_SECONDS:
        bucket.popleft()
    bucket.append(now)
    count = len(bucket)
    if count > VELOCITY_SOFT_LIMIT * 3:
        return 40, count
    if count > VELOCITY_SOFT_LIMIT:
        return 25, count
    if count > max(3, VELOCITY_SOFT_LIMIT // 2):
        return 10, count
    return 0, count


def _score(body: FraudRequest) -> FraudResponse:
    reasons: list[str] = []
    score = 5

    velocity, velocity_count = _velocity_score(body.from_account)
    if velocity:
        score += velocity
        reasons.append(f"velocity={velocity_count}/{VELOCITY_WINDOW_SECONDS}s")

    if body.amount >= CRITICAL_AMOUNT_VND:
        score += 55
        reasons.append("critical_amount")
    elif body.amount >= HIGH_AMOUNT_VND:
        score += 30
        reasons.append("high_amount")

    if body.channel.lower() in {"tor", "unknown", "script"}:
        score += 15
        reasons.append("risky_channel")

    if body.country and body.country.upper() not in {"VN", "SG", "TH"}:
        score += 10
        reasons.append("unusual_country")

    score = min(score, 100)
    if score >= 75:
        verdict = "block"
    elif score >= 40:
        verdict = "review"
    else:
        verdict = "allow"
    gate = "blocked" if verdict == "block" else "passed"
    if not reasons:
        reasons.append("baseline")
    return FraudResponse(score=score, verdict=verdict, reason=reasons, gate=gate)


@app.post("/score", response_model=FraudResponse)
async def score(body: FraudRequest) -> FraudResponse:
    result = _score(body)
    FRAUD_SCORE.labels(service=SERVICE, cloud=CLOUD, verdict=result.verdict).observe(result.score)
    logger.audit(
        "fraud_score_computed",
        from_account=body.from_account,
        to_account=body.to_account,
        amount=body.amount,
        fraud_score=result.score,
        verdict=result.verdict,
        reason=result.reason,
    )
    return result


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
