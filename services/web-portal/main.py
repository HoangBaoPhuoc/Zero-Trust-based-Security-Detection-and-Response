"""
ZTLab Web Portal — Banking UI
Chức năng: đăng ký, đăng nhập (OIDC/PKCE), xem tài khoản, chuyển tiền.
Security events → Grafana. Anomaly scoring → security-scorer (Redis 15 phút).
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import secrets
import string
import time
import urllib.parse
from collections import defaultdict, deque
from typing import Any

import httpx
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware

SERVICE = "web-portal"
CLOUD = os.getenv("CLOUD_PROVIDER", "aws")

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.identity.svc.cluster.local:8080").rstrip("/")
KEYCLOAK_PUBLIC_URL = os.getenv("KEYCLOAK_PUBLIC_URL", "http://127.0.0.1:8180").rstrip("/")
KC_EXTERNAL_HOST = os.getenv("KC_EXTERNAL_HOST", "keycloak.ztlab.local")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "ztlab")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "web-portal")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS", "")

PKCE_STATE_COOKIE = "ztlab_pkce"
_KC_PROXY_ALLOWED = ("/realms/", "/resources/", "/js/")

API_GATEWAY_URL = os.getenv("API_GATEWAY_URL", "http://api-gateway.financial.svc.cluster.local:8080").rstrip("/")
FRAUD_DETECTION_URL = os.getenv("FRAUD_DETECTION_URL", "http://fraud-detection.financial.svc.cluster.local:8080").rstrip("/")
SECURITY_SCORER_URL = os.getenv("SECURITY_SCORER_URL", "http://security-scorer.plg-stack.svc.cluster.local:8080").rstrip("/")
SOAR_ENGINE_URL = os.getenv("SOAR_ENGINE_URL", "http://soar-engine.plg-stack.svc.cluster.local:8080").rstrip("/")
SOAR_API_TOKEN = os.getenv("SOAR_API_TOKEN", "")

SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_urlsafe(32)
SESSION_COOKIE = "ztlab_session"
SESSION_MAX_AGE = 3600

INITIAL_BALANCE = float(os.getenv("INITIAL_BALANCE", "10000000"))
HTTPS_ENABLED = os.getenv("HTTPS_ENABLED", "").lower() == "true"
REGISTER_LIMIT_PER_HOUR = int(os.getenv("REGISTER_LIMIT_PER_HOUR", "5"))
ENABLE_SCENARIOS = os.getenv("ENABLE_SCENARIOS", "true").lower() == "true"

_register_attempts: dict[str, deque] = defaultdict(deque)
_sessions: dict[str, dict[str, Any]] = {}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(SERVICE)

app = FastAPI(title="ZTLab Banking Portal")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if HTTPS_ENABLED:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


_signer = URLSafeTimedSerializer(SESSION_SECRET)


def _sign_session(data: dict) -> str:
    return _signer.dumps(data)


def _load_session(token: str) -> dict | None:
    try:
        return _signer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def _get_session(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    envelope = _load_session(token)
    sid = envelope.get("sid") if isinstance(envelope, dict) else None
    if not sid:
        return None
    record = _sessions.get(sid)
    if not record:
        return None
    if time.time() - record.get("created_at", 0) > SESSION_MAX_AGE:
        _sessions.pop(sid, None)
        return None
    return record.get("data")


def _set_session(response: Response, data: dict) -> None:
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {"data": data, "created_at": time.time()}
    token = _sign_session({"sid": sid})
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=HTTPS_ENABLED,
    )


def _clear_session(response: Response, request: Request | None = None) -> None:
    if request:
        token = request.cookies.get(SESSION_COOKIE)
        envelope = _load_session(token) if token else None
        sid = envelope.get("sid") if isinstance(envelope, dict) else None
        if sid:
            _sessions.pop(sid, None)
    response.delete_cookie(SESSION_COOKIE)


def _token_url() -> str:
    return f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"


def _admin_token_url() -> str:
    return f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _fmt_vnd(amount) -> str:
    try:
        return f"{float(amount):,.0f} ₫"
    except (TypeError, ValueError):
        return str(amount)


templates.env.filters["fmt_vnd"] = _fmt_vnd


def _gen_account_id() -> str:
    suffix = "".join(random.choices(string.digits, k=4))
    return f"ACC-{suffix}"


def _decode_jwt_payload(access_token: str) -> dict:
    try:
        parts = access_token.split(".")
        padding = 4 - len(parts[1]) % 4
        payload_json = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        return json.loads(payload_json)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Keycloak Admin helpers
# ---------------------------------------------------------------------------

async def _get_admin_token() -> str | None:
    if not KEYCLOAK_ADMIN_PASS:
        logger.error(json.dumps({"event": "admin_token_error", "error": "KEYCLOAK_ADMIN_PASS not set"}))
        return None
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                _admin_token_url(),
                data={"grant_type": "password", "client_id": "admin-cli",
                      "username": KEYCLOAK_ADMIN_USER, "password": KEYCLOAK_ADMIN_PASS},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception as exc:
            logger.error(json.dumps({"event": "admin_token_error", "error": str(exc)}))
    return None


async def _keycloak_create_user(
    admin_token: str, username: str, email: str, full_name: str, password: str,
) -> tuple[bool, str]:
    parts = full_name.strip().split(" ", 1)
    first_name = parts[0]
    last_name = parts[1] if len(parts) > 1 else ""
    admin_base = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}"
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{admin_base}/users",
            headers=headers,
            json={
                "username": username, "email": email,
                "firstName": first_name, "lastName": last_name,
                "enabled": True, "emailVerified": True,
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        if resp.status_code == 409:
            return False, "Đăng ký không thành công. Thông tin đã được sử dụng hoặc không hợp lệ."
        if resp.status_code not in (201, 200):
            logger.warning(json.dumps({"event": "keycloak_create_user_failed", "status": resp.status_code}))
            return False, "Không thể tạo tài khoản. Vui lòng thử lại sau."

        search = await client.get(
            f"{admin_base}/users", headers=headers,
            params={"username": username, "exact": "true"},
        )
        users = search.json()
        if not users:
            return False, "Tạo user thành công nhưng không tìm được ID"
        user_id = users[0]["id"]

        roles_to_assign = []
        for role_name in ("financial-read", "financial-write"):
            r = await client.get(f"{admin_base}/roles/{role_name}", headers=headers)
            if r.status_code == 200:
                roles_to_assign.append(r.json())
        if roles_to_assign:
            await client.post(
                f"{admin_base}/users/{user_id}/role-mappings/realm",
                headers=headers, json=roles_to_assign,
            )

    logger.info(json.dumps({"event": "keycloak_user_created", "username": username}))
    return True, ""


async def _get_user_token(username: str, password: str) -> str | None:
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                _token_url(),
                data={"grant_type": "password", "client_id": KEYCLOAK_CLIENT_ID,
                      "username": username, "password": password},
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception as exc:
            logger.error(json.dumps({"event": "user_token_error", "error": str(exc)}))
    return None


async def _create_bank_account_with_token(access_token: str, username: str) -> tuple[str, str]:
    """Create bank account using the user's OIDC access_token (no password grant needed)."""
    headers = {"Authorization": f"Bearer {access_token}"}
    for _ in range(5):
        account_id = _gen_account_id()
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.post(
                    f"{API_GATEWAY_URL}/accounts",
                    json={"account_id": account_id, "owner": username,
                          "balance": INITIAL_BALANCE, "currency": "VND"},
                    headers=headers,
                )
                if resp.status_code in (200, 201):
                    logger.info(json.dumps({"event": "bank_account_created", "username": username, "account_id": account_id}))
                    return account_id, ""
                if resp.status_code == 409:
                    continue
                return "", f"api-gateway error {resp.status_code}: {resp.text[:100]}"
            except Exception as exc:
                return "", f"api-gateway unavailable: {exc}"
    return "", "Không thể tạo tài khoản ngân hàng (xung đột ID)"


async def _lookup_account(username: str, access_token: str = "") -> str:
    if not access_token:
        return ""
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            resp = await client.get(
                f"{API_GATEWAY_URL}/accounts",
                params={"owner": username},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code == 200:
                accounts = resp.json()
                if isinstance(accounts, list) and accounts:
                    return accounts[0]["account_id"]
        except Exception:
            pass
    return ""


async def _push_security_event(event_type: str, message: str, service: str = SERVICE, source_ip: str | None = None) -> None:
    """Push security event to scorer service (best-effort, non-blocking)."""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            await client.post(
                f"{SECURITY_SCORER_URL}/events",
                json={"event_type": event_type, "message": message,
                      "service": service, "cloud": CLOUD, "source_ip": source_ip},
            )
    except Exception:
        pass


async def _cleanup_sessions() -> None:
    while True:
        await asyncio.sleep(300)
        now = time.time()
        expired = [sid for sid, rec in list(_sessions.items())
                   if now - rec.get("created_at", 0) > SESSION_MAX_AGE]
        for sid in expired:
            _sessions.pop(sid, None)
        if expired:
            logger.info(json.dumps({"event": "session_cleanup", "expired_count": len(expired)}))


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(_cleanup_sessions())


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    session = _get_session(request)
    if session:
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "", success: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error, "success": success})


@app.get("/auth/start")
async def auth_start(request: Request):
    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = _pkce_pair()
    portal_base = str(request.base_url).rstrip("/")
    redirect_uri = portal_base + "/auth/callback"

    pkce_payload = {"state": state, "code_verifier": code_verifier, "redirect_uri": redirect_uri}
    token = _sign_session(pkce_payload)

    params = urllib.parse.urlencode({
        "client_id": KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })
    auth_url = f"{portal_base}/kc/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth?{params}"

    response = RedirectResponse(auth_url, status_code=302)
    response.set_cookie(
        PKCE_STATE_COOKIE, token, max_age=300, httponly=True, samesite="lax", secure=HTTPS_ENABLED,
    )
    return response


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return RedirectResponse(f"/login?error={urllib.parse.quote(error)}", status_code=302)
    if not code or not state:
        return RedirectResponse("/login?error=Thiếu+tham+số+callback", status_code=302)

    pkce_token = request.cookies.get(PKCE_STATE_COOKIE)
    if not pkce_token:
        return RedirectResponse("/login?error=Session+PKCE+hết+hạn,+vui+lòng+thử+lại", status_code=302)
    try:
        pkce_data = _signer.loads(pkce_token, max_age=300)
    except Exception:
        return RedirectResponse("/login?error=Session+PKCE+không+hợp+lệ", status_code=302)

    if not isinstance(pkce_data, dict) or pkce_data.get("state") != state:
        ip = request.client.host if request.client else "?"
        logger.warning(json.dumps({"event": "oidc_state_mismatch", "ip": ip}))
        asyncio.create_task(_push_security_event("access_denied", "OIDC state mismatch / CSRF attempt", source_ip=ip))
        return RedirectResponse("/login?error=CSRF+state+không+khớp", status_code=302)

    code_verifier = pkce_data.get("code_verifier", "")
    redirect_uri = pkce_data.get("redirect_uri", "")

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                _token_url(),
                data={"grant_type": "authorization_code", "client_id": KEYCLOAK_CLIENT_ID,
                      "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier},
            )
            if resp.status_code != 200:
                logger.warning(json.dumps({"event": "oidc_token_exchange_failed", "status": resp.status_code}))
                return RedirectResponse("/login?error=Xác+thực+Keycloak+thất+bại", status_code=302)
            token_data = resp.json()
        except Exception as exc:
            logger.error(json.dumps({"event": "oidc_token_exchange_error", "error": str(exc)}))
            return RedirectResponse("/login?error=Không+thể+kết+nối+Keycloak", status_code=302)

    access_token = token_data.get("access_token", "")
    claims = _decode_jwt_payload(access_token)
    preferred_username = claims.get("preferred_username", "")
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    full_name = " ".join(filter(None, [claims.get("given_name", ""), claims.get("family_name", "")])) or preferred_username

    account_id = await _lookup_account(preferred_username, access_token)
    if not account_id:
        # First login — create bank account using the user's own OIDC token
        account_id, acc_err = await _create_bank_account_with_token(access_token, preferred_username)
        if acc_err:
            logger.warning(json.dumps({"event": "first_login_account_create_failed",
                                       "username": preferred_username, "error": acc_err}))

    stale = [sid for sid, rec in list(_sessions.items())
             if rec.get("data", {}).get("username") == preferred_username]
    for sid in stale:
        _sessions.pop(sid, None)

    session_data = {
        "username": preferred_username,
        "full_name": full_name,
        "email": claims.get("email", ""),
        "access_token": access_token,
        "refresh_token": token_data.get("refresh_token", ""),
        "roles": realm_roles,
        "account_id": account_id,
        "logged_in_at": time.time(),
    }
    response = RedirectResponse("/dashboard", status_code=302)
    response.delete_cookie(PKCE_STATE_COOKIE)
    _set_session(response, session_data)
    logger.info(json.dumps({"event": "user_login_oidc", "username": preferred_username, "account_id": account_id}))
    return response


@app.api_route("/kc/{path:path}", methods=["GET", "POST"])
async def kc_proxy(path: str, request: Request):
    full_path = "/" + path
    if not any(full_path.startswith(pfx) for pfx in _KC_PROXY_ALLOWED):
        raise HTTPException(status_code=404)

    target_url = f"{KEYCLOAK_URL}/{path}"
    if request.url.query:
        target_url += "?" + request.url.query

    body = await request.body()
    hop_by_hop = {"connection", "keep-alive", "transfer-encoding", "te", "trailer",
                  "upgrade", "proxy-authorization", "proxy-authenticate", "host"}
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop}
    fwd_headers["accept-encoding"] = "identity"

    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        try:
            kc_resp = await client.request(
                method=request.method, url=target_url,
                headers=fwd_headers, content=body, cookies=dict(request.cookies),
            )
        except Exception as exc:
            logger.error(json.dumps({"event": "kc_proxy_error", "path": path, "error": str(exc)}))
            raise HTTPException(status_code=502, detail="Keycloak không khả dụng")

    portal_base = str(request.base_url).rstrip("/")
    kc_ext_base_http = f"http://{KC_EXTERNAL_HOST}"
    kc_ext_base_https = f"https://{KC_EXTERNAL_HOST}"
    # Must replace the full public URL (with port) first to avoid partial replace
    # e.g. "http://keycloak.ztlab.local:8180" → "http://localhost:18081/kc"
    # If we replace hostname-only first, ":8180" would be left dangling in the path
    kc_replacements = [
        KEYCLOAK_PUBLIC_URL,       # http://keycloak.ztlab.local:8180 (with port, most specific)
        kc_ext_base_https,         # https://keycloak.ztlab.local
        kc_ext_base_http,          # http://keycloak.ztlab.local
        KEYCLOAK_URL,              # http://keycloak.identity.svc.cluster.local:8080 (internal)
    ]

    def _rewrite(text: str) -> str:
        for src in kc_replacements:
            if src:
                text = text.replace(src, portal_base + "/kc")
        return text

    content = kc_resp.content
    ct = kc_resp.headers.get("content-type", "")
    if "html" in ct or "javascript" in ct:
        text = content.decode("utf-8", errors="replace")
        text = _rewrite(text)
        content = text.encode("utf-8")

    skip_hdrs = {"content-encoding", "transfer-encoding", "content-length", "connection"}
    response = Response(content=content, status_code=kc_resp.status_code, media_type=ct or None)
    for hdr_name, hdr_val in kc_resp.headers.multi_items():
        hn = hdr_name.lower()
        if hn in skip_hdrs:
            continue
        if hn == "location":
            hdr_val = _rewrite(hdr_val)
        elif hn == "set-cookie":
            hdr_val = re.sub(r'(?i)(;\s*[Pp]ath=)/realms/', r'\1/kc/realms/', hdr_val)
        response.headers.append(hdr_name, hdr_val)
    return response


@app.get("/auth/logout")
async def logout(request: Request):
    session = _get_session(request)
    if session:
        refresh_token = session.get("refresh_token", "")
        if refresh_token:
            async with httpx.AsyncClient(timeout=5) as client:
                try:
                    await client.post(
                        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout",
                        data={"client_id": KEYCLOAK_CLIENT_ID, "refresh_token": refresh_token},
                    )
                except Exception:
                    pass
    response = RedirectResponse("/login", status_code=302)
    _clear_session(response, request)
    return response


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = "", success: str = ""):
    return templates.TemplateResponse("register.html", {"request": request, "error": error, "success": success})


def _check_register_rate(ip: str) -> bool:
    now = time.time()
    bucket = _register_attempts[ip]
    while bucket and now - bucket[0] > 3600:
        bucket.popleft()
    if len(bucket) >= REGISTER_LIMIT_PER_HOUR:
        return False
    bucket.append(now)
    return True


@app.post("/auth/register", response_class=HTMLResponse)
async def do_register(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_register_rate(client_ip):
        asyncio.create_task(_push_security_event(
            "brute_force", f"Register rate limit exceeded source_ip={client_ip}", source_ip=client_ip,
        ))
        return RedirectResponse("/register?error=Quá+nhiều+yêu+cầu+đăng+ký.+Thử+lại+sau+1+giờ.", status_code=302)

    username = username.strip().lower()
    if len(username) < 3 or not re.match(r'^[a-z0-9_\-\.]+$', username):
        return RedirectResponse("/register?error=Tên+đăng+nhập+phải+có+ít+nhất+3+ký+tự+và+chỉ+gồm+chữ+thường,+số,+dấu+gạch+dưới", status_code=302)
    if len(password) < 12:
        return RedirectResponse("/register?error=Mật+khẩu+phải+có+ít+nhất+12+ký+tự", status_code=302)
    if not re.search(r'[A-Z]', password):
        return RedirectResponse("/register?error=Mật+khẩu+phải+có+ít+nhất+1+chữ+hoa", status_code=302)
    if not re.search(r'[0-9]', password):
        return RedirectResponse("/register?error=Mật+khẩu+phải+có+ít+nhất+1+chữ+số", status_code=302)
    if not re.search(r'[^A-Za-z0-9]', password):
        return RedirectResponse("/register?error=Mật+khẩu+phải+có+ít+nhất+1+ký+tự+đặc+biệt", status_code=302)
    if password != confirm_password:
        return RedirectResponse("/register?error=Mật+khẩu+xác+nhận+không+khớp", status_code=302)
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return RedirectResponse("/register?error=Email+không+hợp+lệ", status_code=302)

    admin_token = await _get_admin_token()
    if not admin_token:
        return RedirectResponse("/register?error=Hệ+thống+tạm+thời+không+khả+dụng", status_code=302)

    ok, err = await _keycloak_create_user(admin_token, username, email, full_name, password)
    if not ok:
        from urllib.parse import quote
        return RedirectResponse(f"/register?error={quote(err)}", status_code=302)

    logger.info(json.dumps({"event": "user_registered", "username": username}))
    return RedirectResponse(
        "/login?success=Đăng+ký+thành+công!+Hãy+đăng+nhập+để+kích+hoạt+tài+khoản+ngân+hàng.",
        status_code=302,
    )


# ---------------------------------------------------------------------------
# Protected pages
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "roles": session.get("roles", []),
        "account_id": session.get("account_id", ""),
        "page": "dashboard",
    })


@app.get("/transfer", response_class=HTMLResponse)
async def transfer_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("transfer.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "account_id": session.get("account_id", ""),
        "page": "transfer",
    })


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "email": session.get("email", ""),
        "roles": session.get("roles", []),
        "account_id": session.get("account_id", ""),
        "logged_in_at": session.get("logged_in_at", 0),
        "page": "profile",
    })


# ---------------------------------------------------------------------------
# REST API (called via fetch() from frontend)
# ---------------------------------------------------------------------------

@app.get("/api/balance/{account_id}")
async def get_balance(account_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if account_id != session.get("account_id", ""):
        logger.warning(json.dumps({
            "event": "idor_attempt", "endpoint": "/api/balance",
            "requested": account_id, "user": session.get("username"),
        }))
        asyncio.create_task(_push_security_event(
            "access_denied",
            f"IDOR attempt on /api/balance requested={account_id} user={session.get('username')}",
        ))
        return JSONResponse({"error": "access denied"}, status_code=403)
    access_token = session.get("access_token", "")
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{API_GATEWAY_URL}/accounts/{account_id}",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/transactions")
async def get_transactions(request: Request, account_id: str = "", limit: int = 20):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    access_token = session.get("access_token", "")
    params: dict[str, Any] = {"limit": min(limit, 100)}
    if account_id:
        params["account_id"] = account_id
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{API_GATEWAY_URL}/transactions",
                params=params,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.post("/api/transfer")
async def do_transfer(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    access_token = session.get("access_token", "")
    client_ip = request.client.host if request.client else "unknown"

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                f"{API_GATEWAY_URL}/payments",
                json=body,
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            )
            result = resp.json()
            # Push security event if fraud was detected
            fraud = result.get("fraud", {})
            if fraud.get("gate") == "blocked" or fraud.get("verdict") == "block":
                asyncio.create_task(_push_security_event(
                    "fraud_gate_bypass",
                    f"fraud_block score={fraud.get('score')} from={body.get('from_account')} amount={body.get('amount')} source_ip={client_ip}",
                    source_ip=client_ip,
                ))
            return JSONResponse(result, status_code=resp.status_code)
        except Exception:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/account/me")
async def get_my_account(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    username = session.get("username", "")
    access_token = session.get("access_token", "")
    roles = session.get("roles", [])
    is_admin = "security-admin" in roles
    params = {} if is_admin else {"owner": username}
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            resp = await client.get(
                f"{API_GATEWAY_URL}/accounts",
                params=params,
                headers={"Authorization": f"Bearer {access_token}"} if access_token else {},
            )
            if resp.status_code == 200:
                accounts = resp.json()
                return JSONResponse({"accounts": accounts, "username": username, "is_admin": is_admin})
            return JSONResponse({"accounts": [], "username": username, "is_admin": is_admin})
        except Exception:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/velocity")
async def get_velocity(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            r = await client.get(f"{FRAUD_DETECTION_URL}/debug/velocity")
            return JSONResponse(r.json())
        except Exception:
            return JSONResponse({"velocity": [], "window_seconds": 60, "soft_limit": 10, "error": "unavailable"})


@app.get("/api/security/score")
async def get_security_score(request: Request):
    """Trả về anomaly score hiện tại từ Redis scorer (15 phút window)."""
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    # Chỉ security roles mới xem được
    roles = session.get("roles", [])
    if not any(r in roles for r in ("security-admin", "security-analyst", "financial-read")):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            r = await client.get(f"{SECURITY_SCORER_URL}/score")
            return JSONResponse(r.json())
        except Exception:
            return JSONResponse({"score": 0, "error": "scorer unavailable"})


# ---------------------------------------------------------------------------
# Admin panel (security-admin role only)
# ---------------------------------------------------------------------------

def _require_admin(session: dict | None) -> bool:
    if not session:
        return False
    return "security-admin" in session.get("roles", [])


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    if not _require_admin(session):
        raise HTTPException(status_code=403, detail="Chỉ security-admin mới được truy cập")
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "roles": session.get("roles", []),
        "page": "admin",
    })


async def _admin_fetch_users_map(admin_token: str, client: httpx.AsyncClient) -> dict:
    """Return {username: {full_name, email, roles, enabled, created}} from Keycloak."""
    ALLOWED = {"financial-read", "financial-write", "security-analyst", "security-admin"}
    try:
        resp = await client.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            params={"max": 100},
        )
        resp.raise_for_status()
    except Exception:
        return {}
    user_map: dict = {}
    for u in resp.json():
        uname = u.get("username", "")
        first = u.get("firstName", "")
        last  = u.get("lastName", "")
        full  = f"{first} {last}".strip() or uname
        role_resp = await client.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users/{u['id']}/role-mappings/realm",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        roles = [r["name"] for r in (role_resp.json() if role_resp.status_code == 200 else [])
                 if r["name"] in ALLOWED]
        user_map[uname] = {
            "id": u["id"],
            "username": uname,
            "full_name": full,
            "first_name": first,
            "last_name": last,
            "email": u.get("email", ""),
            "enabled": u.get("enabled", True),
            "created_at": u.get("createdTimestamp", 0) // 1000,
            "roles": roles,
        }
    return user_map


@app.get("/api/admin/accounts")
async def admin_all_accounts(request: Request):
    session = _get_session(request)
    if not session or not _require_admin(session):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    access_token = session.get("access_token", "")
    admin_token = await _get_admin_token()
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            acct_resp = await client.get(
                f"{API_GATEWAY_URL}/accounts",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            acct_resp.raise_for_status()
            accounts = acct_resp.json()
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)
        user_map = await _admin_fetch_users_map(admin_token, client) if admin_token else {}
    enriched = []
    for a in accounts:
        owner = a.get("owner", "")
        u = user_map.get(owner, {})
        enriched.append({
            **a,
            "full_name": u.get("full_name", owner),
            "email": u.get("email", ""),
            "roles": u.get("roles", []),
            "user_enabled": u.get("enabled", True),
        })
    enriched.sort(key=lambda x: x.get("account_id", ""))
    return JSONResponse({"accounts": enriched})


@app.get("/api/admin/transactions")
async def admin_all_transactions(request: Request, limit: int = 100):
    session = _get_session(request)
    if not session or not _require_admin(session):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    access_token = session.get("access_token", "")
    import asyncio as _asyncio
    async with httpx.AsyncClient(timeout=15) as client:
        txn_resp, acct_resp = await _asyncio.gather(
            client.get(f"{API_GATEWAY_URL}/transactions",
                       params={"limit": min(limit, 500)},
                       headers={"Authorization": f"Bearer {access_token}"}),
            client.get(f"{API_GATEWAY_URL}/accounts",
                       headers={"Authorization": f"Bearer {access_token}"}),
            return_exceptions=True,
        )
    txns   = txn_resp.json()  if not isinstance(txn_resp,  Exception) and txn_resp.status_code  == 200 else []
    accts  = acct_resp.json() if not isinstance(acct_resp, Exception) and acct_resp.status_code == 200 else []
    if not isinstance(txns,  list): txns  = []
    if not isinstance(accts, list): accts = []
    acct_map = {a["account_id"]: a for a in accts}
    admin_token = await _get_admin_token()
    user_map: dict = {}
    if admin_token:
        async with httpx.AsyncClient(timeout=10) as client2:
            user_map = await _admin_fetch_users_map(admin_token, client2)
    enriched = []
    for t in txns:
        fa = acct_map.get(t.get("from_account", ""), {})
        ta = acct_map.get(t.get("to_account",   ""), {})
        fu = user_map.get(fa.get("owner", ""), {})
        tu = user_map.get(ta.get("owner", ""), {})
        enriched.append({
            **t,
            "from_owner":    fa.get("owner", ""),
            "from_name":     fu.get("full_name", fa.get("owner", t.get("from_account", ""))),
            "from_email":    fu.get("email", ""),
            "to_owner":      ta.get("owner", ""),
            "to_name":       tu.get("full_name", ta.get("owner", t.get("to_account", ""))),
            "to_email":      tu.get("email", ""),
        })
    return JSONResponse({"transactions": enriched, "total": len(enriched)})


@app.get("/api/admin/users")
async def admin_users(request: Request):
    session = _get_session(request)
    if not session or not _require_admin(session):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    access_token = session.get("access_token", "")
    admin_token = await _get_admin_token()
    if not admin_token:
        return JSONResponse({"error": "keycloak admin unavailable"}, status_code=503)
    async with httpx.AsyncClient(timeout=15) as client:
        user_map = await _admin_fetch_users_map(admin_token, client)
        try:
            acct_resp = await client.get(
                f"{API_GATEWAY_URL}/accounts",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            accounts = acct_resp.json() if acct_resp.status_code == 200 else []
        except Exception:
            accounts = []
    # Build owner → accounts map
    owner_accts: dict[str, list] = {}
    for a in (accounts if isinstance(accounts, list) else []):
        owner_accts.setdefault(a.get("owner", ""), []).append(a)
    users_out = []
    for uname, u in user_map.items():
        accts = owner_accts.get(uname, [])
        users_out.append({
            **u,
            "accounts": accts,
            "total_balance": sum(float(a.get("balance", 0)) for a in accts),
        })
    users_out.sort(key=lambda x: x.get("username", ""))
    return JSONResponse({"users": users_out})


@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    session = _get_session(request)
    if not session or not _require_admin(session):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    access_token = session.get("access_token", "")
    import asyncio as _asyncio, time as _time
    async with httpx.AsyncClient(timeout=10) as client:
        accounts_resp, txns_resp = await _asyncio.gather(
            client.get(f"{API_GATEWAY_URL}/accounts",
                       headers={"Authorization": f"Bearer {access_token}"}),
            client.get(f"{API_GATEWAY_URL}/transactions", params={"limit": 500},
                       headers={"Authorization": f"Bearer {access_token}"}),
            return_exceptions=True,
        )
    accounts = accounts_resp.json() if not isinstance(accounts_resp, Exception) and accounts_resp.status_code == 200 else []
    txns = txns_resp.json() if not isinstance(txns_resp, Exception) and txns_resp.status_code == 200 else []
    if not isinstance(accounts, list): accounts = []
    if not isinstance(txns, list): txns = []
    total_balance = sum(float(a.get("balance", 0)) for a in accounts if isinstance(a, dict))
    cutoff_24h = _time.time() - 86400
    txns_24h = [t for t in txns if isinstance(t, dict) and float(t.get("created_at", 0)) >= cutoff_24h]
    completed = [t for t in txns if isinstance(t, dict) and t.get("status") == "completed"]
    return JSONResponse({
        "total_accounts": len(accounts),
        "total_balance": total_balance,
        "total_transactions": len(txns),
        "completed_transactions": len(completed),
        "transactions_24h": len(txns_24h),
        "volume_24h": sum(float(t.get("amount", 0)) for t in txns_24h),
        "total_volume": sum(float(t.get("amount", 0)) for t in completed),
    })


# ---------------------------------------------------------------------------
# Demo scenarios (hidden from nav, accessible for demo/testing)
# ---------------------------------------------------------------------------

_FAKE_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJoYWNrZXIiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9"
    ".INVALIDSIGNATURE_NOT_KEYCLOAK"
)


async def _call_gateway(
    method: str, path: str, token: str | None = None,
    json_body: dict | None = None, extra_headers: dict | None = None, timeout: int = 10,
) -> tuple[int, Any]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if method == "POST":
            resp = await client.post(f"{API_GATEWAY_URL}{path}", json=json_body, headers=headers)
        else:
            resp = await client.get(f"{API_GATEWAY_URL}{path}", headers=headers)
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:300]}
        return resp.status_code, body


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _push_scenario_event(scenario_id: str, logs: list[dict]) -> None:
    """Push scenario events to security scorer instead of AI analyzer."""
    for log in logs:
        await _push_security_event(
            event_type=scenario_id,
            message=log.get("message", ""),
            service=log.get("labels", {}).get("app", "demo"),
        )


@app.get("/scenarios", response_class=HTMLResponse)
async def scenarios_page(request: Request):
    if not ENABLE_SCENARIOS:
        raise HTTPException(status_code=404)
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("scenarios.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "page": "scenarios",
    })


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str, request: Request) -> JSONResponse:
    if not ENABLE_SCENARIOS:
        raise HTTPException(status_code=404)
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)

    token = session.get("access_token", "")
    account_id = session.get("account_id", "ACC-1001")

    if scenario_id == "no_jwt":
        sc, body = await _call_gateway("POST", "/payments",
            json_body={"from_account": account_id, "to_account": "ACC-2001", "amount": 1000})
        await _push_security_event("access_denied", "no_jwt payment attempt blocked")
        return JSONResponse({"status_code": sc, "result": body, "expected": "403 – OPA deny: missing JWT"})

    if scenario_id == "jwt_forgery":
        sc, body = await _call_gateway("POST", "/payments", token=_FAKE_JWT,
            json_body={"from_account": account_id, "to_account": "ACC-2001", "amount": 1000})
        await _push_security_event("access_denied", "jwt_forgery attempt invalid signature")
        return JSONResponse({"status_code": sc, "result": body, "expected": "401 – invalid JWT signature"})

    if scenario_id == "lateral_movement":
        sc, body = await _call_gateway("POST", "/payments/internal/execute",
            extra_headers={"X-Forwarded-Client-Cert": "URI=spiffe://evil.corp/attacker"},
            json_body={"from_account": account_id, "to_account": "ACC-9999", "amount": 999_999_999})
        await _push_security_event("lateral_movement", "lateral_movement invalid svid spiffe://evil.corp/attacker")
        return JSONResponse({"status_code": sc, "result": body, "expected": "403 – SVID not in trust domain"})

    if scenario_id == "fraud_gate":
        sc, body = await _call_gateway("POST", "/payments", token=token,
            json_body={"from_account": account_id, "to_account": "ACC-2001",
                       "amount": 500_000_000, "currency": "VND", "channel": "tor"})
        await _push_security_event("fraud_gate_bypass", f"fraud_block critical_amount channel=tor from={account_id}")
        return JSONResponse({"status_code": sc, "result": body, "expected": "403 – fraud_block (score=75)"})

    if scenario_id == "high_velocity":
        results = []
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(10):
                resp = await client.post(
                    f"{API_GATEWAY_URL}/payments", timeout=8,
                    json={"from_account": account_id, "to_account": "ACC-2001", "amount": 1_000},
                    headers={"Authorization": f"Bearer {token}"},
                )
                try:
                    d = resp.json()
                except Exception:
                    d = {}
                fraud = d.get("fraud", {})
                results.append({
                    "attempt": i + 1, "status_code": resp.status_code,
                    "fraud_score": fraud.get("score", "?"),
                    "gate": fraud.get("gate", "?" if resp.status_code < 400 else "blocked"),
                })
        await _push_scenario_event("high_velocity", [
            {"message": f"velocity={len(results)} transactions window=30s from_account={account_id}",
             "labels": {"app": "fraud-detection"}}
        ])
        return JSONResponse({"results": results, "expected": "fraud score tăng dần theo velocity"})

    if scenario_id == "rate_limit":
        results = []
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(65):
                resp = await client.get(f"{API_GATEWAY_URL}/health", timeout=5)
                results.append({"req": i + 1, "status_code": resp.status_code})
        blocked = sum(1 for r in results if r["status_code"] == 429)
        return JSONResponse({"results": results, "blocked_count": blocked,
                             "expected": "req 61+ → 429 Too Many Requests"})

    if scenario_id == "inject_brute_force":
        _logs = [{"message": f"jwt_verification_failed reason=invalid_jwt attempt={i} username=testuser01 source_ip=10.9.8.55",
                  "labels": {"app": "api-gateway"}} for i in range(1, 21)]
        _logs.append({"message": "brute_force_detected account_locked source_ip=10.9.8.55 attempts=20",
                      "labels": {"app": "api-gateway"}})
        await _push_scenario_event("inject_brute_force", _logs)
        return JSONResponse({"result": "injected", "events": len(_logs),
                             "expected": "anomaly score tăng, pattern=brute_force"})

    if scenario_id == "inject_port_scan":
        await _push_security_event("port_scan", "nmap syn scan detected source_ip=10.9.8.99 ports_tried=1024 target=api-gateway")
        return JSONResponse({"result": "injected", "expected": "anomaly score tăng, pattern=port_scan"})

    if scenario_id == "inject_exfiltration":
        await _push_security_event("data_exfil", "bytes_sent=8388608 method=GET path=/accounts/history source_ip=10.9.8.77")
        return JSONResponse({"result": "injected", "expected": "anomaly score tăng, pattern=data_exfil"})

    if scenario_id == "inject_cryptomining":
        await _push_security_event("cryptomining", "xmrig stratum+tcp://pool.minexmr.com:4444 connected cpu_usage=98pct")
        return JSONResponse({"result": "injected", "expected": "anomaly score tăng, pattern=cryptomining"})

    if scenario_id == "sqli_probe":
        sc_live, body_live = await _call_gateway("POST", "/payments", token=token,
            json_body={"from_account": "1' OR '1'='1", "to_account": "ACC-2001", "amount": 100})
        await _push_security_event("exploit_probe", "sqlmap union select sql_injection from_account payload_anomaly=sql_injection")
        return JSONResponse({"status_code": sc_live, "result": body_live,
                             "expected": "HTTP 422 validation error + scorer: exploit_probe"})

    if scenario_id == "inject_cred_stuffing":
        await _push_security_event("cred_stuffing",
            "credential_stuffing multiple_usernames=25 attempts=125 source_ip=203.0.113.55 common_password_attempts=125")
        return JSONResponse({"result": "injected", "expected": "anomaly score tăng, pattern=cred_stuffing"})

    return JSONResponse({"error": f"unknown scenario: {scenario_id}"}, status_code=404)


# ---------------------------------------------------------------------------
# Security / SOAR page
# ---------------------------------------------------------------------------

def _soar_headers() -> dict:
    return {"Authorization": f"Bearer {SOAR_API_TOKEN}"} if SOAR_API_TOKEN else {}


@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    roles = session.get("roles", [])
    if not any(r in roles for r in ("security-admin", "security-analyst")):
        raise HTTPException(status_code=403, detail="Chỉ security-admin hoặc security-analyst mới được truy cập")
    return templates.TemplateResponse("security.html", {
        "request":   request,
        "username":  session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "roles":     roles,
        "page":      "security",
        "is_admin":  "security-admin" in roles,
    })


@app.get("/api/soar/cases")
async def api_soar_cases(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    roles = session.get("roles", [])
    if not any(r in roles for r in ("security-admin", "security-analyst")):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(f"{SOAR_ENGINE_URL}/cases", headers=_soar_headers())
            return JSONResponse(r.json() if r.status_code == 200 else [])
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)


@app.get("/api/soar/blocked-ips")
async def api_soar_blocked_ips(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    roles = session.get("roles", [])
    if not any(r in roles for r in ("security-admin", "security-analyst")):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.get(f"{SOAR_ENGINE_URL}/blocked-ips", headers=_soar_headers())
            return JSONResponse(r.json() if r.status_code == 200 else {"blocked_ips": [], "count": 0})
        except Exception as exc:
            return JSONResponse({"error": str(exc), "blocked_ips": [], "count": 0})


@app.post("/api/soar/blocked-ips/{ip}")
async def api_soar_block_ip(ip: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if "security-admin" not in session.get("roles", []):
        return JSONResponse({"error": "security-admin required"}, status_code=403)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.post(f"{SOAR_ENGINE_URL}/blocked-ips/{ip}", headers=_soar_headers())
            return JSONResponse(r.json(), status_code=r.status_code)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)


@app.delete("/api/soar/blocked-ips/{ip}")
async def api_soar_unblock_ip(ip: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if "security-admin" not in session.get("roles", []):
        return JSONResponse({"error": "security-admin required"}, status_code=403)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.delete(f"{SOAR_ENGINE_URL}/blocked-ips/{ip}", headers=_soar_headers())
            return JSONResponse(r.json(), status_code=r.status_code)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)


@app.post("/api/soar/cases/{case_id}/rollback")
async def api_soar_rollback(case_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if "security-admin" not in session.get("roles", []):
        return JSONResponse({"error": "security-admin required"}, status_code=403)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.post(f"{SOAR_ENGINE_URL}/cases/{case_id}/rollback", headers=_soar_headers())
            return JSONResponse(r.json(), status_code=r.status_code)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)


@app.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    roles = session.get("roles", [])
    if not any(r in roles for r in ("security-admin", "security-analyst")):
        raise HTTPException(status_code=403, detail="Chỉ security-admin hoặc security-analyst mới được truy cập")
    return templates.TemplateResponse("monitor.html", {
        "request":   request,
        "username":  session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "roles":     roles,
        "page":      "monitor",
        "is_admin":  "security-admin" in roles,
    })


@app.get("/api/system/health")
async def api_system_health(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)

    # Services reachable from AWS cluster (web-portal pod)
    probes: dict[str, str] = {
        "api-gateway":          f"{API_GATEWAY_URL}/health",
        "fraud-detection":      f"{FRAUD_DETECTION_URL}/health",
        "payment-service":      "http://payment-service.financial.svc.cluster.local:8080/health",
        "notification-service": "http://notification-service.financial.svc.cluster.local:8080/health",
        "security-scorer":      f"{SECURITY_SCORER_URL}/health",
        "soar-engine":          f"{SOAR_ENGINE_URL}/health",
        "loki":                 "http://loki.plg-stack.svc.cluster.local:3100/ready",
        "grafana":              "http://grafana.plg-stack.svc.cluster.local:3000/api/health",
        "prometheus":           "http://prometheus.plg-stack.svc.cluster.local:9090/-/ready",
        "keycloak":             f"{KEYCLOAK_URL}/health",
    }

    async def _probe(url: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as c:
                r = await c.get(url)
            return {"status": "up" if r.status_code < 400 else "down"}
        except Exception:
            return {"status": "down"}

    import asyncio
    keys = list(probes.keys())
    results_list = await asyncio.gather(*[_probe(u) for u in probes.values()])
    services: dict[str, Any] = dict(zip(keys, results_list))

    # web-portal is always up (this response proves it)
    services["web-portal"] = {"status": "up"}

    # Cross-cluster OS services — not reachable from AWS pod, show as unknown
    for svc in ("core-banking", "account-service", "transaction-service", "spire-agent-os"):
        services[svc] = {"status": "check"}

    # Non-HTTP services (SPIRE, OPA sidecar) — not directly probeable
    for svc in ("spire-server", "spire-agent-aws", "opa", "promtail"):
        services[svc] = {"status": "check"}

    # Redis: derive from SOAR /blocked-ips which reads Redis DB2
    redis_info: dict[str, Any] = {"status": "down", "blocked_ips": None, "velocity_keys": None, "latency_ms": None}
    try:
        import time as _time
        t0 = _time.monotonic()
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{SOAR_ENGINE_URL}/blocked-ips", headers=_soar_headers())
        if r.status_code < 400:
            data = r.json()
            redis_info = {
                "status": "up",
                "blocked_ips": data.get("count", 0),
                "velocity_keys": None,
                "latency_ms": round((_time.monotonic() - t0) * 1000),
            }
    except Exception:
        pass
    services["redis"] = redis_info

    return JSONResponse({"services": services})
