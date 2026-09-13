"""
ZTLab BFF — edge Policy Enforcement Point trước OWASP crAPI.

Vai trò (KE-HOACH-CRAPI.md C2b):
  1. Điểm vào DUY NHẤT. User đăng nhập Keycloak OIDC/PKCE tại đây.
  2. Token-exchange: sau khi có phiên Keycloak, MINT một token crAPI-native
     (RS256, ký bằng khoá RSA của chính crAPI — cùng key `default_jwks.json`
     nhúng trong ảnh crapi-identity) với `sub` = email user. Token này đi ở
     header `Authorization` cho hop Đông–Tây (crAPI cần). Token Keycloak đi
     ở `X-Access-Token` cho OPA kiểm (realm role + step-up `acr`).
  3. Device-trust + device-posture (Phần 1.3, remediation 2026-09): Istio
     IngressGateway ở biên yêu cầu client certificate (Device CA,
     k8s/crapi/edge-gateway.yaml, tls.mode: MUTUAL) rồi gắn header
     `x-device-cert-info` (Lua filter, k8s/istio/edge-gateway-cert-header.yaml)
     — bff đọc cert đã verify để suy ra device_id (SAN URI) + posture (Subject
     OU). Header chỉ đáng tin vì waf's inbound (k8s/crapi/waf-strip-forged-
     cert-header.yaml) xoá nó trừ khi mТLS peer đúng là edge-gateway — không
     còn bí mật chia sẻ (X-Edge-Marker cũ đã xoá hoàn toàn) → header
     `X-Device-Trust` / `X-Device-Posture` cho hop đi tiếp.
  4. Reverse-proxy: /identity /community /workshop → backend crAPI (có
     inject header). / , /static , /images ... → crapi-web (React tĩnh).
  5. Step-up: hành động nhạy cảm + `acr != high` → 401 step_up_required
     (OPA cũng chặn độc lập ở Phase 3 — defense in depth).
  6. Audit log → Loki.

crAPI GIỮ ẢNH GỐC, KHÔNG sửa source.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
from typing import Any

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from jose import jwt as jose_jwt

try:
    from shared.posture import DEVICE_POSTURE, DEVICE_POSTURE_REASONS
except Exception:  # pragma: no cover
    DEVICE_POSTURE, DEVICE_POSTURE_REASONS = "compliant", []

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("bff")

SERVICE = "bff"
CLOUD = os.getenv("CLOUD_PROVIDER", "aws")

# ── Keycloak ────────────────────────────────────────────────────────────────
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.identity.svc.cluster.local:8080").rstrip("/")
KEYCLOAK_PUBLIC_URL = os.getenv("KEYCLOAK_PUBLIC_URL", "http://keycloak.ztlab.local:8180").rstrip("/")
KC_EXTERNAL_HOST = os.getenv("KC_EXTERNAL_HOST", "keycloak.ztlab.local")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "ztlab")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "crapi-bff")
KEYCLOAK_STEPUP_CLIENT_ID = os.getenv("KEYCLOAK_STEPUP_CLIENT_ID", "crapi-bff-stepup")

# ── crAPI backends ──────────────────────────────────────────────────────────
CRAPI_IDENTITY_URL = os.getenv(
    "CRAPI_IDENTITY_URL", "http://crapi-identity-openstack.crapi.svc.cluster.local:30090").rstrip("/")
CRAPI_COMMUNITY_URL = os.getenv("CRAPI_COMMUNITY_URL", "http://crapi-community.crapi.svc.cluster.local:8087").rstrip("/")
CRAPI_WORKSHOP_URL = os.getenv("CRAPI_WORKSHOP_URL", "http://crapi-workshop.crapi.svc.cluster.local:8000").rstrip("/")
CRAPI_WEB_URL = os.getenv("CRAPI_WEB_URL", "http://crapi-web.crapi.svc.cluster.local:80").rstrip("/")

_BACKENDS = {
    "identity": CRAPI_IDENTITY_URL,
    "community": CRAPI_COMMUNITY_URL,
    "workshop": CRAPI_WORKSHOP_URL,
}

# ── crAPI JWT signing key (mint token cho từng user) ────────────────────────
CRAPI_JWT_KEY_PATH = os.getenv("CRAPI_JWT_KEY_PATH", "/app/crapi-keys/jwks.json")
CRAPI_JWT_TTL = int(os.getenv("CRAPI_JWT_TTL", "3600"))


def _load_crapi_key() -> dict:
    with open(CRAPI_JWT_KEY_PATH) as f:
        doc = json.load(f)
    key = doc["keys"][0] if isinstance(doc, dict) and "keys" in doc else doc
    if "d" not in key:
        raise RuntimeError("crAPI JWK không có private key ('d') — không mint được token")
    return key


_CRAPI_KEY = _load_crapi_key()
_CRAPI_KID = _CRAPI_KEY.get("kid")

# Keycloak realm role → crAPI `role` claim. crapi-identity đặt role = tên Role
# entity; giá trị thực xác nhận Phase 1 khi thấy token thật (mặc định "user").
ROLE_MAP = {
    "crapi-admin": os.getenv("CRAPI_ROLE_ADMIN", "admin"),
    "crapi-mechanic": os.getenv("CRAPI_ROLE_MECHANIC", "mechanic"),
    "crapi-user": os.getenv("CRAPI_ROLE_USER", "user"),
    "soc-analyst": os.getenv("CRAPI_ROLE_USER", "user"),
}
DEFAULT_CRAPI_ROLE = os.getenv("CRAPI_ROLE_USER", "user")

# ── Sensitive actions cần step-up (KET-QUA-CRAPI.md GATE 0 #4) ───────────────
SENSITIVE_ACTIONS = [
    tuple(x.split(" ", 1)) for x in json.loads(os.getenv("SENSITIVE_ACTIONS", json.dumps([
        "POST /workshop/api/shop/orders",
        "POST /workshop/api/shop/orders/return_order",
        "POST /identity/api/v2/user/reset-password",
        "POST /identity/api/v2/user/change-email",
    ])))
]

# ── Session ────────────────────────────────────────────────────────────────
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_urlsafe(32)
SESSION_COOKIE = "ztlab_bff_session"
PKCE_COOKIE = "ztlab_bff_pkce"
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", "3600"))
HTTPS_ENABLED = os.getenv("HTTPS_ENABLED", "").lower() == "true"

# ── Phần 1.3 (remediation 2026-09): device cert đã verify ở biên mesh thật
# (Istio IngressGateway, k8s/crapi/edge-gateway.yaml, tls.mode: MUTUAL bằng
# Device CA) ─────────────────────────────────────────────────────────────
# Header dưới đây KHÔNG cần một bí mật chia sẻ (kiểu X-Edge-Marker cũ, đã xoá
# khỏi toàn bộ codebase — xem KIEM-KE-HOP.md nhóm (c)-1) để tin: nó chỉ có
# thể mang giá trị thật vì (1) k8s/istio/edge-gateway-cert-header.yaml (Lua,
# chạy ở Gateway) chỉ gắn nó SAU KHI tự verify client cert bằng Device CA ở
# tầng TLS — không cert hợp lệ thì không có request nào tới được đây để gắn;
# (2) k8s/crapi/waf-strip-forged-cert-header.yaml (Lua, chạy ở waf's inbound)
# xoá sạch header này trừ khi mТLS peer đúng là
# spiffe://ztlab.local/aws/edge-gateway — không pod/bypass port nào khác giả
# được. Đây chính là "OPA/BFF đổi từ kiểm marker sang kiểm source_principal
# đúng là biên" mà kế hoạch remediation yêu cầu.
_DEVICE_URI_PREFIX = "spiffe://ztlab.local/device/"
_DEVICE_CERT_HEADER_V2 = "x-device-cert-info"

REDIS_URL = os.getenv("REDIS_URL", "redis://redis.crapi.svc.cluster.local:6379/0")
LOKI_URL = os.getenv("LOKI_URL", "http://loki.plg-stack.svc.cluster.local:3100").rstrip("/")

_signer = URLSafeTimedSerializer(SESSION_SECRET)
# Session store: Redis (bff có thể scale + phiên sống qua restart). Fallback
# in-process nếu Redis lỗi. Cookie chỉ mang {sid} đã ký.
_sessions: dict[str, dict[str, Any]] = {}
_SESSION_PREFIX = "bff:session:"
redis_client: aioredis.Redis | None = None
_http: httpx.AsyncClient | None = None


async def _session_store_set(sid: str, data: dict) -> None:
    try:
        await redis_client.setex(_SESSION_PREFIX + sid, SESSION_MAX_AGE,
                                 json.dumps({"data": data, "created_at": time.time()}))
        return
    except Exception:
        pass
    _sessions[sid] = {"data": data, "created_at": time.time()}


async def _session_store_get(sid: str) -> dict | None:
    try:
        raw = await redis_client.get(_SESSION_PREFIX + sid)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return _sessions.get(sid)


async def _session_store_del(sid: str) -> None:
    try:
        await redis_client.delete(_SESSION_PREFIX + sid)
    except Exception:
        pass
    _sessions.pop(sid, None)

_KC_PROXY_ALLOWED = ("/realms/", "/resources/", "/js/")
_HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
               "proxy-authorization", "proxy-authenticate", "host", "content-length"}

app = FastAPI(title="ZTLab BFF (crAPI edge PEP)")


@app.on_event("startup")
async def _startup() -> None:
    global redis_client, _http
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    _http = httpx.AsyncClient(timeout=20, follow_redirects=False)
    logger.info(json.dumps({"event": "bff_start", "crapi_kid": _CRAPI_KID,
                            "device_posture": DEVICE_POSTURE, "posture_reasons": DEVICE_POSTURE_REASONS}))


@app.on_event("shutdown")
async def _shutdown() -> None:
    if _http:
        await _http.aclose()


# ── helpers ────────────────────────────────────────────────────────────────
def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _sign(data: dict) -> str:
    return _signer.dumps(data)


def _load(token: str | None, max_age: int) -> dict | None:
    if not token:
        return None
    try:
        v = _signer.loads(token, max_age=max_age)
        return v if isinstance(v, dict) else None
    except (BadSignature, SignatureExpired):
        return None


async def _get_session(request: Request) -> dict | None:
    env = _load(request.cookies.get(SESSION_COOKIE), SESSION_MAX_AGE)
    sid = env.get("sid") if env else None
    if not sid:
        return None
    rec = await _session_store_get(sid)
    if not rec:
        return None
    if time.time() - rec.get("created_at", 0) > SESSION_MAX_AGE:
        await _session_store_del(sid)
        return None
    return rec["data"]


async def _set_session(response: Response, data: dict) -> str:
    sid = secrets.token_urlsafe(32)
    await _session_store_set(sid, data)
    response.set_cookie(SESSION_COOKIE, _sign({"sid": sid}), max_age=SESSION_MAX_AGE,
                        httponly=True, samesite="lax", secure=HTTPS_ENABLED)
    return sid


async def _clear_session(response: Response, request: Request) -> None:
    env = _load(request.cookies.get(SESSION_COOKIE), SESSION_MAX_AGE)
    if env and env.get("sid"):
        await _session_store_del(env["sid"])
    response.delete_cookie(SESSION_COOKIE)


def _decode_jwt_payload(token: str) -> dict:
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _external_base(request: Request) -> str:
    """request.base_url chỉ phản ánh Host/scheme của hop bff thấy — KHÔNG phải
    URL bên ngoài client thật sự dùng. WAF (nginx) đứng giữa Gateway và bff
    ghi đè X-Forwarded-Proto về scheme của chính nó (luôn http, vì TLS đã kết
    thúc ở Istio IngressGateway) nên header chuẩn này không tin được ở đây.
    X-Edge-Scheme là header riêng do Lua filter ở Gateway gắn
    (k8s/istio/edge-gateway-cert-header.yaml) — nginx không biết tên này nên
    đi qua nguyên vẹn, giống x-device-cert-info. Thiếu scheme đúng thì OIDC
    redirect_uri sai (http thay vì https), Keycloak/trình duyệt không quay
    lại được BFF."""
    scheme = request.headers.get("x-edge-scheme") or request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.base_url.hostname
    return f"{scheme}://{host}"


def _parse_cert_info(raw: str) -> dict[str, str]:
    """Traefik X-Forwarded-Tls-Client-Cert-Info, URL-encoded (percent-encoded
    `=`/`;`/`"` — must decode before parsing, otherwise every field silently
    fails, no literal `=`/`;` survives). Format is `Field="value";Field2="v2"`
    for the leaf cert, followed by `,Field="value"` (comma, no semicolon) for
    each cert further up the chain — regex-matching `key="value"` pairs and
    keeping only the first occurrence of each key naturally picks the leaf
    cert's fields over the issuer's, regardless of the mixed `;`/`,` separators."""
    raw = urllib.parse.unquote(raw)
    fields: dict[str, str] = {}
    for k, v in re.findall(r'(\w+)="([^"]*)"', raw):
        fields.setdefault(k, v)
    return fields


def _cert_fields_to_device(fields: dict[str, str]) -> dict:
    subject = fields.get("Subject", "")
    san = fields.get("SAN") or fields.get("URI", "")

    m = re.search(r"OU=posture:([A-Za-z0-9_-]+)", subject)
    posture = m.group(1) if m else "unknown"
    device_id = san[len(_DEVICE_URI_PREFIX):] if san.startswith(_DEVICE_URI_PREFIX) else None
    if not device_id:
        return {"device_id": None, "posture": "unknown", "device_trust": "suspicious"}

    device_trust = "trusted" if posture == "compliant" else "suspicious"
    return {"device_id": device_id, "posture": posture, "device_trust": device_trust}


def _evaluate_device_cert(request: Request) -> dict:
    """Device posture từ client cert đã verify bằng Device CA ở tầng TLS của
    Istio IngressGateway (k8s/crapi/edge-gateway.yaml). Không cần kiểm gì
    thêm ở đây: giá trị header CHỈ có thể là thật, vì
    k8s/crapi/waf-strip-forged-cert-header.yaml đã xoá nó ở waf's inbound trừ
    khi mТLS peer đúng spiffe://ztlab.local/aws/edge-gateway — không cert
    hợp lệ ở Gateway thì không có request nào tới được BFF để mang header
    giả cả (TLS handshake fail ngay ở Gateway)."""
    cert_info = request.headers.get(_DEVICE_CERT_HEADER_V2, "")
    if not cert_info:
        return {"device_id": None, "posture": "unknown", "device_trust": "suspicious"}
    return _cert_fields_to_device(_parse_cert_info(cert_info))


async def _audit(event: str, **kw: Any) -> None:
    rec = {"event": event, "service": SERVICE, "cloud": CLOUD, "ts": time.time(), **kw}
    logger.info(json.dumps(rec))
    if not LOKI_URL:
        return
    try:
        ns = str(int(time.time() * 1e9))
        payload = {"streams": [{"stream": {"job": "bff-audit", "namespace": "crapi", "app": "bff", "cloud": CLOUD},
                                "values": [[ns, json.dumps(rec)]]}]}
        await _http.post(f"{LOKI_URL}/loki/api/v1/push", json=payload, timeout=3)
    except Exception:
        pass


def _mint_crapi_token(email: str, realm_roles: list[str]) -> str:
    crapi_role = DEFAULT_CRAPI_ROLE
    for rr in realm_roles:
        if rr in ROLE_MAP:
            crapi_role = ROLE_MAP[rr]
            if rr == "crapi-admin":
                break
    now = int(time.time())
    claims = {"sub": email, "role": crapi_role, "iat": now, "exp": now + CRAPI_JWT_TTL}
    headers = {"kid": _CRAPI_KID} if _CRAPI_KID else None
    return jose_jwt.encode(claims, _CRAPI_KEY, algorithm="RS256", headers=headers)


def _kc_token_url(realm: str = "") -> str:
    return f"{KEYCLOAK_URL}/realms/{realm or KEYCLOAK_REALM}/protocol/openid-connect/token"


def _is_sensitive(method: str, path: str) -> bool:
    return any(method == m and path.startswith(p) for m, p in SENSITIVE_ACTIONS)


_ADMIN_PREFIXES = ("/identity/api/v2/admin", "/workshop/api/management")
_MECHANIC_PREFIXES = ("/workshop/api/mechanic/service_requests",
                      "/workshop/api/mechanic/mechanic_report")
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _rbac_ok(roles: list[str], method: str, path: str) -> bool:
    """RBAC lớp bff — GƯƠNG của opa/crapi-policies/zta_crapi.rego role_permits_action.
    Cần vì hop bff→crapi-identity (cross-cloud) đi qua OPA OpenStack
    (crosscloud_crapi.rego) chỉ kiểm service_acl, KHÔNG kiểm token người dùng.
    Hop bff→community/workshop (cùng cluster AWS) OPA vẫn kiểm — đây là
    defense-in-depth (giống api-gateway app + OPA của finance app)."""
    rs = set(roles)
    if not rs & {"crapi-user", "crapi-mechanic", "crapi-admin", "soc-analyst"}:
        return False
    if method in ("GET", "HEAD", "OPTIONS"):
        return True
    if method not in _WRITE_METHODS:
        return False
    if any(path.startswith(p) for p in _ADMIN_PREFIXES):
        return "crapi-admin" in rs
    if any(path.startswith(p) for p in _MECHANIC_PREFIXES):
        return bool(rs & {"crapi-mechanic", "crapi-admin"})
    # write thường: crapi-user/mechanic/admin (KHÔNG soc-analyst)
    return bool(rs & {"crapi-user", "crapi-mechanic", "crapi-admin"})


# ── health ─────────────────────────────────────────────────────────────────
@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": SERVICE, "device_posture": DEVICE_POSTURE}


# ── OIDC login ─────────────────────────────────────────────────────────────
def _auth_redirect(request: Request, client_id: str, extra: dict | None = None) -> RedirectResponse:
    state = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    base = _external_base(request)
    redirect_uri = base + "/auth/callback"
    tok = _sign({"state": state, "code_verifier": verifier, "redirect_uri": redirect_uri, "client_id": client_id})
    params = {
        "client_id": client_id, "response_type": "code", "scope": "openid profile email",
        "redirect_uri": redirect_uri, "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if extra:
        params.update(extra)
    url = f"{base}/kc/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?{urllib.parse.urlencode(params)}"
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(PKCE_COOKIE, tok, max_age=300, httponly=True, samesite="lax", secure=HTTPS_ENABLED)
    return resp


@app.get("/login")
async def login(request: Request):
    return _auth_redirect(request, KEYCLOAK_CLIENT_ID)


@app.get("/auth/start")
async def auth_start(request: Request):
    return _auth_redirect(request, KEYCLOAK_CLIENT_ID)


@app.get("/auth/start-stepup")
async def auth_start_stepup(request: Request):
    # client stepup + acr_values=high → Keycloak Conditional-OTP flow
    return _auth_redirect(request, KEYCLOAK_STEPUP_CLIENT_ID, {"acr_values": "high"})


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error or not code or not state:
        return RedirectResponse(f"/?login_error={urllib.parse.quote(error or 'missing_params')}", status_code=302)
    pkce = _load(request.cookies.get(PKCE_COOKIE), 300)
    if not pkce or pkce.get("state") != state:
        await _audit("oidc_state_mismatch", ip=_client_ip(request))
        return RedirectResponse("/?login_error=state_mismatch", status_code=302)

    client_id = pkce.get("client_id", KEYCLOAK_CLIENT_ID)
    try:
        r = await _http.post(_kc_token_url(), data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "redirect_uri": pkce["redirect_uri"], "code_verifier": pkce["code_verifier"],
        })
        if r.status_code != 200:
            await _audit("oidc_token_exchange_failed", status=r.status_code, body=r.text[:200])
            return RedirectResponse("/?login_error=token_exchange", status_code=302)
        td = r.json()
    except Exception as exc:
        await _audit("oidc_token_exchange_error", error=str(exc))
        return RedirectResponse("/?login_error=keycloak_unreachable", status_code=302)

    access_token = td.get("access_token", "")
    claims = _decode_jwt_payload(access_token)
    email = claims.get("email") or claims.get("preferred_username", "")
    username = claims.get("preferred_username", email)
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    acr = claims.get("acr", "")

    device = _evaluate_device_cert(request)
    crapi_token = _mint_crapi_token(email, realm_roles)

    data = {
        "email": email, "username": username, "roles": realm_roles, "acr": acr,
        "access_token": access_token, "refresh_token": td.get("refresh_token", ""),
        "crapi_token": crapi_token, "crapi_token_exp": int(time.time()) + CRAPI_JWT_TTL,
        "device_id": device["device_id"], "device_trust": device["device_trust"],
        "device_posture": device["posture"],
        "logged_in_at": time.time(),
    }
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(PKCE_COOKIE)
    await _set_session(resp, data)
    await _audit("user_login", username=username, email=email, roles=realm_roles, acr=acr,
                 device_id=device["device_id"], device_trust=device["device_trust"],
                 device_posture=device["posture"], stepup=(client_id == KEYCLOAK_STEPUP_CLIENT_ID))
    return resp


@app.get("/auth/logout")
async def logout(request: Request):
    session = await _get_session(request)
    if session and session.get("refresh_token"):
        try:
            await _http.post(f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout",
                             data={"client_id": KEYCLOAK_CLIENT_ID, "refresh_token": session["refresh_token"]})
        except Exception:
            pass
    resp = RedirectResponse("/", status_code=302)
    await _clear_session(resp, request)
    return resp


@app.api_route("/kc/{path:path}", methods=["GET", "POST"])
async def kc_proxy(path: str, request: Request):
    full = "/" + path
    if not any(full.startswith(p) for p in _KC_PROXY_ALLOWED):
        raise HTTPException(status_code=404)
    target = f"{KEYCLOAK_URL}/{path}"
    if request.url.query:
        target += "?" + request.url.query
    body = await request.body()
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    fwd["accept-encoding"] = "identity"
    try:
        kc = await _http.request(request.method, target, headers=fwd, content=body, cookies=dict(request.cookies))
    except Exception as exc:
        await _audit("kc_proxy_error", path=path, error=str(exc))
        raise HTTPException(status_code=502, detail="Keycloak unavailable")

    base = _external_base(request)
    kc_hosts = {h for h in (KC_EXTERNAL_HOST, urllib.parse.urlsplit(KEYCLOAK_PUBLIC_URL).hostname,
                            urllib.parse.urlsplit(KEYCLOAK_URL).hostname) if h}
    kc_re = re.compile(r"https?://(?:" + "|".join(re.escape(h) for h in kc_hosts) + r")(?::\d+)?")
    rewrite = lambda t: kc_re.sub(base + "/kc", t)

    content = kc.content
    ct = kc.headers.get("content-type", "")
    if "html" in ct or "javascript" in ct:
        content = rewrite(content.decode("utf-8", "replace")).encode()
    skip = {"content-encoding", "transfer-encoding", "content-length", "connection"}
    resp = Response(content=content, status_code=kc.status_code, media_type=ct or None)
    for name, val in kc.headers.multi_items():
        n = name.lower()
        if n in skip:
            continue
        if n == "location":
            val = rewrite(val)
        elif n == "set-cookie":
            val = re.sub(r"(?i)(;\s*path=)/realms/", r"\1/kc/realms/", val)
        resp.headers.append(name, val)
    return resp


# ── reverse proxy → crAPI ──────────────────────────────────────────────────
async def _proxy(request: Request, base: str, upstream_path: str,
                 inject: dict[str, str] | None = None) -> Response:
    target = f"{base}{upstream_path}"
    if request.url.query:
        target += "?" + request.url.query
    body = await request.body()
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP}
    # client KHÔNG được tự đặt các header tin cậy (x-device-cert-info là tín
    # hiệu nội bộ bff↔Gateway — không được lộ ra hop sau)
    for h in ("authorization", "x-access-token", "x-device-trust", "x-device-posture",
              _DEVICE_CERT_HEADER_V2):
        fwd.pop(h, None)
        fwd.pop(h.title(), None)
    if inject:
        fwd.update(inject)
    try:
        up = await _http.request(request.method, target, headers=fwd, content=body)
    except Exception as exc:
        await _audit("proxy_error", target=target, error=str(exc))
        raise HTTPException(status_code=502, detail="upstream unavailable")
    skip = {"content-encoding", "transfer-encoding", "content-length", "connection"}
    resp = Response(content=up.content, status_code=up.status_code,
                    media_type=up.headers.get("content-type"))
    for name, val in up.headers.multi_items():
        if name.lower() not in skip:
            resp.headers.append(name, val)
    return resp


@app.api_route("/{svc}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def api_proxy(svc: str, path: str, request: Request):
    if svc not in _BACKENDS:
        return await _proxy(request, CRAPI_WEB_URL, request.url.path)  # rơi về static
    full_path = f"/{svc}/{path}"
    session = await _get_session(request)
    if not session:
        return JSONResponse({"error": "unauthenticated", "login_url": "/auth/start"}, status_code=401)

    # device trust: suspicious → chặn ghi (gương device_trust_compliant của OPA;
    # OPA OpenStack không kiểm cái này cho hop identity)
    if session.get("device_trust") == "suspicious" and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        await _audit("device_trust_denied", username=session.get("username"), path=full_path)
        return JSONResponse({"error": "forbidden", "reason": "suspicious_device"}, status_code=403)

    # RBAC (gương của OPA — cần cho hop cross-cloud bff→identity)
    if not _rbac_ok(session.get("roles", []), request.method, full_path):
        await _audit("rbac_denied", username=session.get("username"),
                     path=full_path, method=request.method, roles=session.get("roles"))
        return JSONResponse({"error": "forbidden", "reason": "insufficient_role"}, status_code=403)

    # step-up: hành động nhạy cảm cần acr=high (OPA cũng chặn ở Phase 3)
    if _is_sensitive(request.method, full_path) and session.get("acr") != "high":
        await _audit("step_up_required", username=session.get("username"), path=full_path,
                     method=request.method, acr=session.get("acr", ""))
        return JSONResponse({"error": "step_up_required",
                             "stepup_url": "/auth/start-stepup"}, status_code=401)

    inject = {
        "authorization": f"Bearer {session['crapi_token']}",
        "x-access-token": session["access_token"],
        "x-device-trust": session.get("device_trust", "suspicious"),
        "x-device-posture": session.get("device_posture", "unknown"),
        "x-forwarded-for": _client_ip(request),
    }
    resp = await _proxy(request, _BACKENDS[svc], full_path, inject)
    if _is_sensitive(request.method, full_path) and resp.status_code < 400:
        await _audit("sensitive_action_ok", username=session.get("username"),
                     path=full_path, method=request.method, status=resp.status_code)
    return resp


# fallthrough: mọi path còn lại → crapi-web (index.html / static / images)
@app.api_route("/{path:path}", methods=["GET", "HEAD"])
async def static_proxy(path: str, request: Request):
    return await _proxy(request, CRAPI_WEB_URL, request.url.path)


@app.get("/")
async def root(request: Request):
    return await _proxy(request, CRAPI_WEB_URL, "/")
