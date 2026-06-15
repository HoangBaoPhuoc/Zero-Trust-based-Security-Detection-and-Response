# ZTLab - fraud-detection

import os
import time
import uuid
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from fastapi import FastAPI
from prometheus_client import make_asgi_app
import redis.asyncio as aioredis

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import FRAUD_SCORE, SERVICE_UP

SERVICE = "fraud-detection"
CLOUD = "aws"
VELOCITY_WINDOW_SECONDS = int(os.getenv("FRAUD_VELOCITY_WINDOW_SECONDS", "60"))
VELOCITY_SOFT_LIMIT = int(os.getenv("FRAUD_VELOCITY_SOFT_LIMIT", "10"))
HIGH_AMOUNT_VND = float(os.getenv("FRAUD_HIGH_AMOUNT_VND", "100000000"))
CRITICAL_AMOUNT_VND = float(os.getenv("FRAUD_CRITICAL_AMOUNT_VND", "500000000"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

redis_client: aioredis.Redis | None = None

logger = ZTLabLogger(SERVICE, CLOUD)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    await redis_client.ping()
    SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)
    yield
    await redis_client.aclose()


app = FastAPI(title="ZTLab Fraud Detection", lifespan=lifespan)
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())


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


async def _velocity_score(account: str) -> tuple[int, int]:
    now = time.time()
    key = f"fraud:velocity:{account}"
    pipe = redis_client.pipeline()
    pipe.zremrangebyscore(key, 0, now - VELOCITY_WINDOW_SECONDS)
    pipe.zadd(key, {str(uuid.uuid4()): now})
    pipe.zcard(key)
    pipe.expire(key, VELOCITY_WINDOW_SECONDS * 2)
    results = await pipe.execute()
    count = int(results[2])
    if count > VELOCITY_SOFT_LIMIT * 3:
        return 40, count
    if count > VELOCITY_SOFT_LIMIT:
        return 25, count
    if count > max(3, VELOCITY_SOFT_LIMIT // 2):
        return 10, count
    return 0, count


async def _score(body: FraudRequest) -> FraudResponse:
    reasons: list[str] = []
    score = 5

    velocity, velocity_count = await _velocity_score(body.from_account)
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
    result = await _score(body)
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


@app.get("/debug/velocity")
async def debug_velocity():
    now = time.time()
    keys = await redis_client.keys("fraud:velocity:*")
    result = []
    for key in sorted(keys):
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, now - VELOCITY_WINDOW_SECONDS)
        pipe.zcard(key)
        pipe.ttl(key)
        r = await pipe.execute()
        count = int(r[1])
        ttl = int(r[2])
        account = key.replace("fraud:velocity:", "")
        if count > VELOCITY_SOFT_LIMIT * 3:
            risk = "high"
        elif count > VELOCITY_SOFT_LIMIT:
            risk = "elevated"
        elif count > max(3, VELOCITY_SOFT_LIMIT // 2):
            risk = "low"
        else:
            risk = "normal"
        result.append({
            "account": account,
            "tx_in_window": count,
            "ttl_seconds": ttl,
            "risk": risk,
        })
    return {
        "velocity": result,
        "window_seconds": VELOCITY_WINDOW_SECONDS,
        "soft_limit": VELOCITY_SOFT_LIMIT,
        "timestamp": now,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
