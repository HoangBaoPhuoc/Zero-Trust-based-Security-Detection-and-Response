# ZTLab - api-gateway

import os
import time
import uuid
from collections import defaultdict, deque

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from jose import JWTError, jwk, jwt
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import AUTH_FAILURES, SERVICE_UP

SERVICE = "api-gateway"
CLOUD = "aws"
PAYMENT_SERVICE_URL = os.getenv("PAYMENT_SERVICE_URL", "http://payment-service:8080").rstrip("/")
JWT_SECRET = os.getenv("JWT_DEV_SECRET", "ztlab-dev-secret")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")
JWT_ISSUER = os.getenv("JWT_ISSUER", "http://keycloak.ztlab.local/realms/ztlab")
JWKS_URL = os.getenv("JWKS_URL", "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

app = FastAPI(title="ZTLab API Gateway")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)

_recent_by_source: dict[str, deque[float]] = defaultdict(deque)
_jwks_keys: list = []


def _load_jwks() -> None:
    global _jwks_keys
    if not JWKS_URL:
        return
    try:
        resp = httpx.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        _jwks_keys = [jwk.construct(k) for k in resp.json().get("keys", []) if k.get("use") == "sig"]
        logger.info("jwks_loaded", key_count=len(_jwks_keys), jwks_url=JWKS_URL)
    except Exception as exc:
        logger.warn("jwks_load_failed", error=str(exc), jwks_url=JWKS_URL)


class PaymentRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    channel: str = "api"
    country: str | None = None


def _source_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(source_ip: str) -> None:
    now = time.time()
    bucket = _recent_by_source[source_ip]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    bucket.append(now)
    if len(bucket) > RATE_LIMIT_PER_MINUTE:
        logger.warn("rate_limit_exceeded", source_ip=source_ip, count=len(bucket))
        raise HTTPException(status_code=429, detail="rate limit exceeded")


def _require_role(claims: dict, role: str, source_ip: str) -> None:
    roles = claims.get("realm_access", {}).get("roles", [])
    if role not in roles:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="insufficient_role").inc()
        logger.warn("authz_denied", required_role=role, user=claims.get("preferred_username","?"), source_ip=source_ip)
        raise HTTPException(status_code=403, detail=f"role '{role}' required")


def _verify_token(authorization: str | None, source_ip: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="missing_bearer").inc()
        logger.warn("jwt_verification_failed", reason="missing_bearer", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()

    # Try RS256 via Keycloak JWKS first
    if _jwks_keys:
        for key in _jwks_keys:
            try:
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    issuer=JWT_ISSUER,
                    options={"verify_aud": False},
                )
                return claims
            except JWTError:
                continue

    # Fallback: HS256 dev token
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            options={"verify_aud": False},
        )
    except JWTError as exc:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="invalid_jwt").inc()
        logger.warn("jwt_verification_failed", reason="invalid_jwt", source_ip=source_ip, error=str(exc))
        raise HTTPException(status_code=401, detail="invalid token") from exc


@app.on_event("startup")
async def startup() -> None:
    _load_jwks()


@app.post("/payments")
async def create_payment(request: Request, body: PaymentRequest, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-write", source_ip)
    trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            response = await client.post(
                f"{PAYMENT_SERVICE_URL}/payments",
                json=body.model_dump(),
                headers={"X-Trace-ID": trace_id, "X-User-ID": str(claims.get("sub", "unknown")), "Authorization": authorization},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except Exception as exc:
            logger.error("payment_route_failed", trace_id=trace_id, error=str(exc))
            raise HTTPException(status_code=503, detail="payment service unavailable") from exc
    return response.json()


@app.get("/accounts/{account_id}")
async def get_account(account_id: str, request: Request, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-read", source_ip)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{PAYMENT_SERVICE_URL}/accounts/{account_id}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="account service unavailable") from exc


@app.get("/transactions")
async def get_transactions(request: Request, account_id: str = "", limit: int = 20,
                           authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-read", source_ip)
    params: dict = {"limit": min(limit, 100)}
    if account_id:
        params["account_id"] = account_id
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{PAYMENT_SERVICE_URL}/transactions", params=params)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="transaction service unavailable") from exc


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD, "jwks_keys_loaded": len(_jwks_keys)}
