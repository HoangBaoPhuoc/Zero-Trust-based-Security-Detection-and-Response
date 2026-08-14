# ZTLab - api-gateway

import asyncio
import os
import time
import uuid
from collections import defaultdict, deque

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Header, HTTPException, Request
from jose import JWTError, jwk, jwt
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import AUTH_FAILURES, SERVICE_UP

SERVICE = "api-gateway"
CLOUD = "aws"
PAYMENT_SERVICE_URL = os.getenv("PAYMENT_SERVICE_URL", "http://payment-service:8080").rstrip("/")
JWT_SECRET = os.getenv("JWT_DEV_SECRET", "")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")

# Issuer và JWKS URL trước đây là 2 hằng số hardcode độc lập, phải tự tay giữ
# khớp với cấu hình THẬT của Keycloak (KC_HOSTNAME/KC_HOSTNAME_PORT). Lệch 1
# ký tự giữa chúng (đã xảy ra ngày 2026-08-13, thiếu KC_HOSTNAME_PORT khiến
# issuer thật lệch port) làm toàn bộ JWT bị từ chối, mất nhiều giờ để lần ra.
# Giờ lấy cả 2 giá trị từ chính OIDC discovery document Keycloak tự công bố —
# nguồn sự thật duy nhất, không cần đồng bộ tay.
JWT_ISSUER_OVERRIDE = os.getenv("JWT_ISSUER", "")  # để trống = luôn theo discovery; đặt tay chỉ dùng khi cần ghim khẩn cấp
JWKS_URL_OVERRIDE = os.getenv("JWKS_URL", "")
_KEYCLOAK_REALM_BASE = os.getenv(
    "KEYCLOAK_REALM_BASE", "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab"
).rstrip("/")
OIDC_DISCOVERY_URL = f"{_KEYCLOAK_REALM_BASE}/.well-known/openid-configuration"

# Giá trị dự phòng nếu discovery chưa chạy được lần nào (VD Keycloak chưa kịp
# lên khi api-gateway khởi động) — không để service crash hoàn toàn, chỉ
# fail-closed như bình thường cho tới khi discovery thành công.
_jwt_issuer = JWT_ISSUER_OVERRIDE or "http://keycloak.ztlab.local:8180/realms/ztlab"
_jwks_uri = JWKS_URL_OVERRIDE or f"{_KEYCLOAK_REALM_BASE}/protocol/openid-connect/certs"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
ALLOW_DEV_TOKENS = os.getenv("ALLOW_DEV_TOKENS", "false").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://redis.financial.svc.cluster.local:6379/0")
IP_BLOCK_ENABLED = os.getenv("IP_BLOCK_ENABLED", "true").lower() == "true"

app = FastAPI(title="ZTLab API Gateway")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)

_recent_by_source: dict[str, deque[float]] = defaultdict(deque)
_jwks_keys: list = []
_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _redis


async def _is_ip_blocked(ip: str) -> bool:
    if not IP_BLOCK_ENABLED:
        return False
    try:
        r = await _get_redis()
        return bool(await r.exists(f"ztlab:blocked_ip:{ip}"))
    except Exception:
        return False


def _load_oidc_config() -> None:
    """Nạp issuer + JWKS URI từ OIDC discovery document của Keycloak, thay vì
    2 hằng số hardcode độc lập. Nếu discovery lỗi, fallback dùng override/URL
    JWKS mặc định (đã tính sẵn) để không phá vỡ hoàn toàn service."""
    global _jwks_keys, _jwt_issuer, _jwks_uri
    issuer = _jwt_issuer
    jwks_uri = _jwks_uri
    try:
        disc = httpx.get(OIDC_DISCOVERY_URL, timeout=5)
        disc.raise_for_status()
        disc_data = disc.json()
        disc_issuer = disc_data.get("issuer")
        disc_jwks_uri = disc_data.get("jwks_uri")
        if not disc_issuer or not disc_jwks_uri:
            raise ValueError("discovery document missing issuer/jwks_uri")
        if not JWT_ISSUER_OVERRIDE:
            issuer = disc_issuer
        if not JWKS_URL_OVERRIDE:
            jwks_uri = disc_jwks_uri
    except Exception as exc:
        logger.warn("oidc_discovery_failed", error=str(exc), discovery_url=OIDC_DISCOVERY_URL,
                    fallback_issuer=issuer, fallback_jwks_uri=jwks_uri)

    try:
        resp = httpx.get(jwks_uri, timeout=5)
        resp.raise_for_status()
        _jwks_keys = [jwk.construct(k) for k in resp.json().get("keys", []) if k.get("use") == "sig"]
        _jwt_issuer = issuer
        _jwks_uri = jwks_uri
        logger.info("oidc_config_loaded", key_count=len(_jwks_keys), issuer=_jwt_issuer, jwks_uri=_jwks_uri)
    except Exception as exc:
        logger.warn("jwks_load_failed", error=str(exc), jwks_uri=jwks_uri)


class PaymentRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float = Field(gt=0)
    currency: str = "VND"
    channel: str = "api"
    country: str | None = None
    device_trust: str = "unknown"


def _source_ip(request: Request) -> str:
    # Use TCP-level peer address — not X-Forwarded-For, which is user-controllable
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


def _decode_jwt(token: str, key, algorithms: list[str]) -> dict:
    kwargs = {
        "algorithms": algorithms,
        "issuer": _jwt_issuer,
    }
    if JWT_AUDIENCE:
        kwargs["audience"] = JWT_AUDIENCE
    else:
        kwargs["options"] = {"verify_aud": False}
    return jwt.decode(token, key, **kwargs)


def _verify_token(authorization: str | None, source_ip: str) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="missing_bearer").inc()
        logger.warn("jwt_verification_failed", reason="missing_bearer", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()

    # RS256 via Keycloak JWKS (primary path)
    if _jwks_keys:
        for key in _jwks_keys:
            try:
                claims = _decode_jwt(token, key, ["RS256"])
                return claims
            except JWTError:
                continue
        # JWKS keys are loaded — token is invalid, do NOT fall back to HS256
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="invalid_jwt").inc()
        logger.warn("jwt_verification_failed", reason="invalid_rs256", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="invalid token")

    if not ALLOW_DEV_TOKENS:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="jwks_unavailable").inc()
        logger.warn("jwt_verification_failed", reason="jwks_unavailable_fail_closed", source_ip=source_ip)
        raise HTTPException(status_code=503, detail="token verifier unavailable")

    if not JWT_SECRET:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="dev_secret_missing").inc()
        logger.warn("jwt_verification_failed", reason="dev_secret_missing", source_ip=source_ip)
        raise HTTPException(status_code=503, detail="dev token verifier unavailable")

    # HS256 dev token is opt-in only. Do not enable this in production.
    try:
        return _decode_jwt(token, JWT_SECRET, ["HS256"])
    except JWTError as exc:
        AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="invalid_jwt").inc()
        logger.warn("jwt_verification_failed", reason="invalid_jwt", source_ip=source_ip, error=str(exc))
        raise HTTPException(status_code=401, detail="invalid token") from exc


async def _jwks_refresh_loop() -> None:
    while True:
        if not _jwks_keys:
            _load_oidc_config()
        await asyncio.sleep(300)


@app.on_event("startup")
async def startup() -> None:
    _load_oidc_config()
    asyncio.create_task(_jwks_refresh_loop())


@app.post("/payments")
async def create_payment(request: Request, body: PaymentRequest, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    if await _is_ip_blocked(source_ip):
        logger.warn("ip_blocked_request", source_ip=source_ip, path="/payments")
        raise HTTPException(status_code=403, detail={"reason": "ip_blocked", "source_ip": source_ip, "message": "IP bị chặn bởi hệ thống bảo mật"})
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
        except Exception as exc:
            logger.error("payment_route_failed", trace_id=trace_id, error=str(exc))
            raise HTTPException(status_code=503, detail="payment service unavailable") from exc
    if response.status_code >= 400:
        try:
            body = response.json()
            detail = body.get("detail", body) if isinstance(body, dict) else body
        except Exception:
            detail = "upstream payment service error"
        raise HTTPException(status_code=response.status_code, detail=detail)
    return response.json()


@app.post("/accounts")
async def create_account(request: Request, authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-write", source_ip)
    body = await request.json()
    # Enforce: new account must belong to the authenticated user
    if body.get("owner") and body["owner"] != claims.get("preferred_username"):
        raise HTTPException(status_code=403, detail="cannot create account for another user")
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(f"{PAYMENT_SERVICE_URL}/accounts", json=body)
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
async def list_accounts(request: Request, owner: str = "", authorization: str | None = Header(default=None)):
    source_ip = _source_ip(request)
    _check_rate_limit(source_ip)
    claims = _verify_token(authorization, source_ip)
    _require_role(claims, "financial-read", source_ip)
    roles = claims.get("realm_access", {}).get("roles", [])
    if "security-admin" in roles:
        params = {"owner": owner} if owner else {}
    else:
        params = {"owner": claims.get("preferred_username", "")}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{PAYMENT_SERVICE_URL}/accounts", params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail="account service error") from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="account service unavailable") from exc


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
            data = resp.json()
            # IDOR check: account must belong to the authenticated user
            if data.get("owner") != claims.get("preferred_username"):
                AUTH_FAILURES.labels(service=SERVICE, cloud=CLOUD, reason="idor_attempt").inc()
                logger.warn("idor_attempt", account_id=account_id,
                            user=claims.get("preferred_username"), source_ip=source_ip)
                raise HTTPException(status_code=403, detail="access denied")
            return data
        except HTTPException:
            raise
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=exc.response.status_code, detail="account not found") from exc
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
    return {
        "status": "ok", "service": SERVICE, "cloud": CLOUD,
        "jwks_keys_loaded": len(_jwks_keys),
        "active_issuer": _jwt_issuer,
        "active_jwks_uri": _jwks_uri,
    }
