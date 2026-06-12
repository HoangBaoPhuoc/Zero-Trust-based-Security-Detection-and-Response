import asyncio
import json
import logging
import os
import random
import secrets
import string
import time
from collections import defaultdict, deque
from typing import Any

import httpx
from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware

SERVICE = "web-portal"
CLOUD = os.getenv("CLOUD_PROVIDER", "aws")

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.identity.svc.cluster.local:8080").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "ztlab")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "web-portal")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASS = os.getenv("KEYCLOAK_ADMIN_PASS", "")

API_GATEWAY_URL = os.getenv("API_GATEWAY_URL", "http://api-gateway.financial.svc.cluster.local:8080").rstrip("/")
ACCOUNT_SERVICE_URL = os.getenv("ACCOUNT_SERVICE_URL", "http://account-service.financial.svc.cluster.local:8080").rstrip("/")
LOKI_URL = os.getenv("LOKI_URL", "http://loki.plg-stack.svc.cluster.local:3100").rstrip("/")
AI_ANALYZER_URL = os.getenv("AI_ANALYZER_URL", "http://ai-analyzer.plg-stack.svc.cluster.local:8080").rstrip("/")

SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_urlsafe(32)
SESSION_COOKIE = "ztlab_session"
SESSION_MAX_AGE = 3600

INITIAL_BALANCE = float(os.getenv("INITIAL_BALANCE", "10000000"))  # 10 triệu VND
HTTPS_ENABLED = os.getenv("HTTPS_ENABLED", "").lower() == "true"
REGISTER_LIMIT_PER_HOUR = int(os.getenv("REGISTER_LIMIT_PER_HOUR", "5"))

_register_attempts: dict[str, deque] = defaultdict(deque)
_sessions: dict[str, dict[str, Any]] = {}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(SERVICE)

app = FastAPI(title="ZTLab Web Portal")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

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
    import base64
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
        logger.error(json.dumps({"event": "admin_token_error", "error": "KEYCLOAK_ADMIN_PASS is not configured"}))
        return None
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                _admin_token_url(),
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": KEYCLOAK_ADMIN_USER,
                    "password": KEYCLOAK_ADMIN_PASS,
                },
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
        except Exception as exc:
            logger.error(json.dumps({"event": "admin_token_error", "error": str(exc)}))
    return None


async def _keycloak_create_user(
    admin_token: str,
    username: str,
    email: str,
    full_name: str,
    password: str,
) -> tuple[bool, str]:
    """Create user in Keycloak. Returns (success, error_message)."""
    parts = full_name.strip().split(" ", 1)
    first_name = parts[0]
    last_name = parts[1] if len(parts) > 1 else ""

    admin_base = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}"
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=10) as client:
        # Create user
        resp = await client.post(
            f"{admin_base}/users",
            headers=headers,
            json={
                "username": username,
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "enabled": True,
                "emailVerified": True,
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        if resp.status_code == 409:
            return False, "Tên đăng nhập hoặc email đã tồn tại"
        if resp.status_code not in (201, 200):
            err = resp.json().get("errorMessage", resp.text[:200])
            return False, f"Không thể tạo tài khoản Keycloak: {err}"

        # Fetch the user ID
        search = await client.get(
            f"{admin_base}/users",
            headers=headers,
            params={"username": username, "exact": "true"},
        )
        users = search.json()
        if not users:
            return False, "Tạo user thành công nhưng không tìm được ID"
        user_id = users[0]["id"]

        # Fetch roles
        roles_to_assign = []
        for role_name in ("financial-read", "financial-write"):
            r = await client.get(f"{admin_base}/roles/{role_name}", headers=headers)
            if r.status_code == 200:
                roles_to_assign.append(r.json())

        # Assign roles
        if roles_to_assign:
            await client.post(
                f"{admin_base}/users/{user_id}/role-mappings/realm",
                headers=headers,
                json=roles_to_assign,
            )

    logger.info(json.dumps({"event": "keycloak_user_created", "username": username}))
    return True, ""


async def _create_bank_account(username: str) -> tuple[str, str]:
    """Create a bank account in account-service. Returns (account_id, error)."""
    for _ in range(5):
        account_id = _gen_account_id()
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.post(
                    f"{ACCOUNT_SERVICE_URL}/accounts",
                    json={
                        "account_id": account_id,
                        "owner": username,
                        "balance": INITIAL_BALANCE,
                        "currency": "VND",
                    },
                )
                if resp.status_code == 201:
                    return account_id, ""
                if resp.status_code == 409:
                    continue  # collision, retry with new ID
                return "", f"account-service error {resp.status_code}: {resp.text[:100]}"
            except Exception as exc:
                return "", f"account-service unavailable: {exc}"
    return "", "Không thể tạo tài khoản ngân hàng (collision)"


async def _lookup_account(username: str) -> str:
    """Look up the first bank account for this user. Returns account_id or empty string."""
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            resp = await client.get(
                f"{ACCOUNT_SERVICE_URL}/accounts",
                params={"owner": username},
            )
            if resp.status_code == 200:
                accounts = resp.json()
                if accounts:
                    return accounts[0]["account_id"]
        except Exception:
            pass
    return ""


async def _cleanup_sessions() -> None:
    while True:
        await asyncio.sleep(300)  # every 5 minutes
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
# Core routes
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
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/auth/login", response_class=HTMLResponse)
async def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                _token_url(),
                data={
                    "grant_type": "password",
                    "client_id": KEYCLOAK_CLIENT_ID,
                    "username": username,
                    "password": password,
                },
            )
            if resp.status_code != 200:
                err_data = resp.json()
                err_msg = err_data.get("error_description", err_data.get("error", "Sai tên đăng nhập hoặc mật khẩu"))
                return RedirectResponse(f"/login?error={err_msg}", status_code=302)
            token_data = resp.json()
        except Exception as exc:
            logger.error(json.dumps({"event": "keycloak_error", "error": str(exc)}))
            return RedirectResponse("/login?error=Không+thể+kết+nối+Keycloak", status_code=302)

    access_token = token_data.get("access_token", "")
    claims = _decode_jwt_payload(access_token)
    preferred_username = claims.get("preferred_username", username)
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    full_name = " ".join(filter(None, [claims.get("given_name", ""), claims.get("family_name", "")])) or preferred_username

    # Dynamically look up bank account
    account_id = await _lookup_account(preferred_username)

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
    _set_session(response, session_data)
    logger.info(json.dumps({"event": "user_login", "username": preferred_username, "account_id": account_id}))
    return response


@app.get("/auth/logout")
async def logout(request: Request):
    session = _get_session(request)
    # Revoke Keycloak session (best-effort)
    if session:
        refresh_token = session.get("refresh_token", "")
        if refresh_token:
            async with httpx.AsyncClient(timeout=5) as client:
                try:
                    await client.post(
                        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout",
                        data={
                            "client_id": KEYCLOAK_CLIENT_ID,
                            "refresh_token": refresh_token,
                        },
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
    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": error,
        "success": success,
    })


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
    # Rate limit: max 5 registrations per IP per hour
    client_ip = request.client.host if request.client else "unknown"
    if not _check_register_rate(client_ip):
        return RedirectResponse("/register?error=Quá+nhiều+yêu+cầu+đăng+ký.+Thử+lại+sau+1+giờ.", status_code=302)

    # Validate
    username = username.strip().lower()
    if len(username) < 3:
        return RedirectResponse("/register?error=Tên+đăng+nhập+phải+có+ít+nhất+3+ký+tự", status_code=302)
    if len(password) < 8:
        return RedirectResponse("/register?error=Mật+khẩu+phải+có+ít+nhất+8+ký+tự", status_code=302)
    if password != confirm_password:
        return RedirectResponse("/register?error=Mật+khẩu+xác+nhận+không+khớp", status_code=302)
    if not email or "@" not in email:
        return RedirectResponse("/register?error=Email+không+hợp+lệ", status_code=302)

    # Get admin token
    admin_token = await _get_admin_token()
    if not admin_token:
        return RedirectResponse("/register?error=Hệ+thống+tạm+thời+không+khả+dụng", status_code=302)

    # Create Keycloak user
    ok, err = await _keycloak_create_user(admin_token, username, email, full_name, password)
    if not ok:
        from urllib.parse import quote
        return RedirectResponse(f"/register?error={quote(err)}", status_code=302)

    # Create bank account
    account_id, acc_err = await _create_bank_account(username)
    if acc_err:
        logger.error(json.dumps({"event": "account_create_failed", "username": username, "error": acc_err}))

    logger.info(json.dumps({
        "event": "user_registered",
        "username": username,
        "account_id": account_id,
    }))
    return RedirectResponse(
        f"/login?success=Đăng+ký+thành+công!+Tài+khoản+ngân+hàng+{account_id}+đã+được+tạo.+Hãy+đăng+nhập.",
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


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "page": "logs",
    })


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "roles": session.get("roles", []),
        "page": "alerts",
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
# REST API endpoints (called via fetch() from frontend)
# ---------------------------------------------------------------------------

@app.get("/api/balance/{account_id}")
async def get_balance(account_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    access_token = session.get("access_token", "")
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                f"{API_GATEWAY_URL}/accounts/{account_id}",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception as exc:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/transactions")
async def get_transactions(request: Request, account_id: str = "", limit: int = 20):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    access_token = session.get("access_token", "")
    params: dict[str, Any] = {"limit": limit}
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
        except Exception as exc:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.post("/api/transfer")
async def do_transfer(request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = await request.json()
    access_token = session.get("access_token", "")
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                f"{API_GATEWAY_URL}/payments",
                json=body,
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception as exc:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/account/me")
async def get_my_account(request: Request):
    """Return current user's account info (refreshes from account-service)."""
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    username = session.get("username", "")
    async with httpx.AsyncClient(timeout=8) as client:
        try:
            resp = await client.get(f"{ACCOUNT_SERVICE_URL}/accounts", params={"owner": username})
            if resp.status_code == 200:
                accounts = resp.json()
                return JSONResponse({"accounts": accounts, "username": username})
            return JSONResponse({"accounts": [], "username": username})
        except Exception as exc:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/logs")
async def get_security_logs(request: Request, limit: int = 50):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    end_ns = time.time_ns()
    start_ns = end_ns - 3600 * 1_000_000_000
    query = '{job=~"ai-analyzer|soar-engine|envoy-access|opa-decisions|kubernetes-pods"}'
    params = {
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(limit),
        "direction": "backward",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
            data = resp.json()
            entries = []
            for stream in data.get("data", {}).get("result", []):
                labels = stream.get("stream", {})
                for ts_ns, line in stream.get("values", []):
                    ts_sec = int(ts_ns) / 1e9
                    ts_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts_sec))
                    try:
                        msg = json.loads(line)
                    except Exception:
                        msg = {"message": line}
                    entries.append({
                        "timestamp": ts_iso,
                        "ts_ns": ts_ns,
                        "job": labels.get("job", ""),
                        "service": labels.get("service", labels.get("app", "")),
                        "severity": labels.get("severity", msg.get("level", msg.get("severity", "info"))),
                        "event_type": msg.get("event_type", msg.get("event", "")),
                        "message": msg.get("message", msg.get("summary", line[:200])),
                        "raw": msg,
                    })
            entries.sort(key=lambda e: e["ts_ns"], reverse=True)
            return JSONResponse(entries[:limit])
        except Exception as exc:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.get("/api/alerts")
async def get_ai_alerts(request: Request, status: str = "pending"):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{AI_ANALYZER_URL}/pending", params={"status": status} if status else {})
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception as exc:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


def _has_security_role(session: dict) -> bool:
    roles = session.get("roles", [])
    return any(r in roles for r in ("security-admin", "security-analyst"))


@app.post("/api/alerts/{alert_id}/approve")
async def approve_alert(alert_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if not _has_security_role(session):
        logger.warning(json.dumps({
            "event": "rbac_denied", "action": "approve_alert",
            "user": session.get("username"), "alert_id": alert_id,
        }))
        return JSONResponse({"error": "security-admin or security-analyst role required"}, status_code=403)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(f"{AI_ANALYZER_URL}/pending/{alert_id}/approve", json=body)
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


@app.post("/api/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if not _has_security_role(session):
        logger.warning(json.dumps({
            "event": "rbac_denied", "action": "dismiss_alert",
            "user": session.get("username"), "alert_id": alert_id,
        }))
        return JSONResponse({"error": "security-admin or security-analyst role required"}, status_code=403)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(f"{AI_ANALYZER_URL}/pending/{alert_id}/dismiss", json=body)
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception:
            return JSONResponse({"error": "service unavailable"}, status_code=503)


# ---------------------------------------------------------------------------
# Scenarios page + runner
# ---------------------------------------------------------------------------

@app.get("/scenarios", response_class=HTMLResponse)
async def scenarios_page(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("scenarios.html", {
        "request": request,
        "username": session.get("username"),
        "full_name": session.get("full_name", session.get("username")),
        "page": "scenarios",
    })


_FAKE_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJoYWNrZXIiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9"
    ".INVALIDSIGNATURE_NOT_KEYCLOAK"
)


async def _call_gateway(
    method: str,
    path: str,
    token: str | None = None,
    json_body: dict | None = None,
    extra_headers: dict | None = None,
    timeout: int = 10,
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


async def _inject_ai(logs: list[dict]) -> tuple[int, Any]:
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{AI_ANALYZER_URL}/analyze",
            json={"source": "web_scenario", "logs": logs},
        )
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"raw": resp.text[:300]}


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str, request: Request) -> JSONResponse:
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)

    token = session.get("access_token", "")
    account_id = session.get("account_id", "ACC-1001")

    if scenario_id == "no_jwt":
        sc, body = await _call_gateway("POST", "/payments",
            json_body={"from_account": account_id, "to_account": "ACC-2001", "amount": 1000, "currency": "VND"})
        return JSONResponse({"status_code": sc, "result": body, "expected": "403 – OPA deny: missing JWT"})

    if scenario_id == "jwt_forgery":
        sc, body = await _call_gateway("POST", "/payments", token=_FAKE_JWT,
            json_body={"from_account": account_id, "to_account": "ACC-2001", "amount": 1000, "currency": "VND"})
        return JSONResponse({"status_code": sc, "result": body, "expected": "401 – invalid JWT signature"})

    if scenario_id == "lateral_movement":
        sc, body = await _call_gateway("POST", "/payments/internal/execute",
            extra_headers={"X-Forwarded-Client-Cert": "URI=spiffe://evil.corp/attacker"},
            json_body={"from_account": account_id, "to_account": "ACC-9999", "amount": 999_999_999})
        return JSONResponse({"status_code": sc, "result": body, "expected": "403 – SVID not in trust domain"})

    if scenario_id == "fraud_gate":
        sc, body = await _call_gateway("POST", "/payments", token=token,
            json_body={"from_account": account_id, "to_account": "ACC-2001",
                       "amount": 500_000_000, "currency": "VND", "channel": "tor"})
        return JSONResponse({"status_code": sc, "result": body, "expected": "403 – fraud_block (score=75)"})

    if scenario_id == "high_velocity":
        results = []
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(10):
                resp = await client.post(
                    f"{API_GATEWAY_URL}/payments", timeout=8,
                    json={"from_account": account_id, "to_account": "ACC-2001",
                          "amount": 1_000, "currency": "VND"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                try:
                    d = resp.json()
                except Exception:
                    d = {}
                fraud = d.get("fraud", {})
                results.append({
                    "attempt": i + 1,
                    "status_code": resp.status_code,
                    "fraud_score": fraud.get("score", "?"),
                    "gate": fraud.get("gate", "?" if resp.status_code < 400 else "blocked"),
                })
        return JSONResponse({"results": results,
                             "expected": "fraud score tăng dần theo velocity; count>5 → score+10"})

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
        sc, body = await _inject_ai([{
            "timestamp": _now_iso(),
            "message": (
                "jwt_verification_failed reason=invalid_jwt attempt=20 username=testuser01 "
                "source_ip=10.9.8.55 brute_force_detected within_30s auth_method=password"
            ),
            "labels": {"namespace": "financial", "app": "api-gateway",
                       "job": "kubernetes-pods", "cloud": "aws"},
        }])
        return JSONResponse({"status_code": sc, "result": body,
                             "expected": "verdict=malicious, attack_type=brute_force, severity=high"})

    if scenario_id == "inject_port_scan":
        sc, body = await _inject_ai([{
            "timestamp": _now_iso(),
            "message": (
                "nmap syn scan detected source_ip=10.9.8.99 ports_tried=1024 "
                "target=api-gateway duration_s=12 scan_type=SYN"
            ),
            "labels": {"namespace": "financial", "app": "api-gateway",
                       "job": "envoy-access", "cloud": "aws"},
        }])
        return JSONResponse({"status_code": sc, "result": body,
                             "expected": "verdict=malicious, playbook=block_source_ip"})

    if scenario_id == "inject_exfiltration":
        sc, body = await _inject_ai([{
            "timestamp": _now_iso(),
            "message": (
                "bytes_sent=8388608 method=GET path=/accounts/ACC-1001/history "
                "response_code=200 duration_ms=3200 source_ip=10.9.8.77"
            ),
            "labels": {"namespace": "financial", "app": "account-service",
                       "job": "envoy-access", "cloud": "openstack"},
        }])
        return JSONResponse({"status_code": sc, "result": body,
                             "expected": "verdict=malicious, attack_type=large_response, playbook=restrict_egress"})

    if scenario_id == "inject_cryptomining":
        sc, body = await _inject_ai([{
            "timestamp": _now_iso(),
            "message": (
                "xmrig stratum+tcp://pool.minexmr.com:4444 connected "
                "worker=api-gateway-pod cpu_usage=98pct hashrate=1.2kH/s"
            ),
            "labels": {"namespace": "financial", "app": "api-gateway",
                       "job": "kubernetes-pods", "cloud": "aws"},
        }])
        return JSONResponse({"status_code": sc, "result": body,
                             "expected": "verdict=malicious, attack_type=cryptomining, playbook=quarantine_workload"})

    if scenario_id == "sqli_probe":
        sc_live, body_live = await _call_gateway("POST", "/payments", token=token,
            json_body={"from_account": "1' OR '1'='1", "to_account": "ACC-2001",
                       "amount": 100, "currency": "VND"})
        _, ai_body = await _inject_ai([{
            "timestamp": _now_iso(),
            "message": (
                "request_validation_failed path=/payments from_account=\"1' OR '1'='1\" "
                "payload_anomaly=sql_injection source_ip=10.9.8.33"
            ),
            "labels": {"namespace": "financial", "app": "payment-service",
                       "job": "kubernetes-pods", "cloud": "aws"},
        }])
        return JSONResponse({
            "status_code": sc_live,
            "result": body_live,
            "ai_analysis": ai_body,
            "expected": "HTTP 422 validation error + AI: exploit_probe",
        })

    if scenario_id == "inject_cred_stuffing":
        sc, body = await _inject_ai([{
            "timestamp": _now_iso(),
            "message": (
                "credential_stuffing detected unique_usernames=25 attempts_per_user=5 "
                "total_attempts=125 window_seconds=60 source_ip=203.0.113.55 "
                "success_rate=0.0 jwt_verification_failed=125"
            ),
            "labels": {"namespace": "financial", "app": "api-gateway",
                       "job": "kubernetes-pods", "cloud": "aws"},
        }])
        return JSONResponse({"status_code": sc, "result": body,
                             "expected": "verdict=malicious, playbook=revoke_user_sessions"})

    return JSONResponse({"error": f"unknown scenario: {scenario_id}"}, status_code=404)
