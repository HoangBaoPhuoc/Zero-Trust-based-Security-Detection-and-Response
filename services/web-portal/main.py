import json
import logging
import os
import time
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
API_GATEWAY_URL = os.getenv("API_GATEWAY_URL", "http://api-gateway.financial.svc.cluster.local:8080").rstrip("/")
ACCOUNT_SERVICE_URL = os.getenv("ACCOUNT_SERVICE_URL", "http://account-service.financial.svc.cluster.local:8080").rstrip("/")
TRANSACTION_SERVICE_URL = os.getenv("TRANSACTION_SERVICE_URL", "http://transaction-service.financial.svc.cluster.local:8080").rstrip("/")
LOKI_URL = os.getenv("LOKI_URL", "http://loki.plg-stack.svc.cluster.local:3100").rstrip("/")
AI_ANALYZER_URL = os.getenv("AI_ANALYZER_URL", "http://ai-analyzer.plg-stack.svc.cluster.local:8080").rstrip("/")
SESSION_SECRET = os.getenv("SESSION_SECRET", "ztlab-web-portal-secret-2026")
SESSION_COOKIE = "ztlab_session"
SESSION_MAX_AGE = 3600

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(SERVICE)

app = FastAPI(title="ZTLab Web Portal")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

_signer = URLSafeTimedSerializer(SESSION_SECRET)

ACCOUNT_OWNER_MAP = {
    "testuser01": "ACC-1001",
    "merchant01": "ACC-2001",
}


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
    return _load_session(token)


def _set_session(response: Response, data: dict) -> None:
    token = _sign_session(data)
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax")


def _clear_session(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)


def _token_url() -> str:
    return f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"


def _fmt_vnd(amount) -> str:
    try:
        return f"{float(amount):,.0f} ₫"
    except (TypeError, ValueError):
        return str(amount)


templates.env.filters["fmt_vnd"] = _fmt_vnd


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
                err_msg = err_data.get("error_description", err_data.get("error", "Authentication failed"))
                return RedirectResponse(f"/login?error={err_msg}", status_code=302)
            token_data = resp.json()
        except Exception as exc:
            logger.error(json.dumps({"event": "keycloak_error", "error": str(exc)}))
            return RedirectResponse("/login?error=Keycloak+unavailable", status_code=302)

    access_token = token_data.get("access_token", "")
    import base64
    try:
        parts = access_token.split(".")
        padding = 4 - len(parts[1]) % 4
        payload_json = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        claims = json.loads(payload_json)
        preferred_username = claims.get("preferred_username", username)
        realm_roles = claims.get("realm_access", {}).get("roles", [])
    except Exception:
        preferred_username = username
        realm_roles = []

    session_data = {
        "username": preferred_username,
        "access_token": access_token,
        "refresh_token": token_data.get("refresh_token", ""),
        "roles": realm_roles,
        "account_id": ACCOUNT_OWNER_MAP.get(preferred_username, ""),
        "logged_in_at": time.time(),
    }
    response = RedirectResponse("/dashboard", status_code=302)
    _set_session(response, session_data)
    logger.info(json.dumps({"event": "user_login", "username": preferred_username}))
    return response


@app.get("/auth/logout")
async def logout(request: Request):
    response = RedirectResponse("/login", status_code=302)
    _clear_session(response)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "username": session.get("username"),
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
        "page": "alerts",
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
            return JSONResponse({"error": str(exc)}, status_code=503)


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
            return JSONResponse({"error": str(exc)}, status_code=503)


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
            return JSONResponse({"error": str(exc)}, status_code=503)


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
            return JSONResponse({"error": str(exc)}, status_code=503)


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
            return JSONResponse({"error": str(exc)}, status_code=503)


@app.post("/api/alerts/{alert_id}/approve")
async def approve_alert(alert_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(f"{AI_ANALYZER_URL}/pending/{alert_id}/approve", json=body)
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)


@app.post("/api/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str, request: Request):
    session = _get_session(request)
    if not session:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(f"{AI_ANALYZER_URL}/pending/{alert_id}/dismiss", json=body)
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=503)


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

    # ── Nhóm 1: Zero Trust enforcement ──────────────────────────────────

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

    # ── Nhóm 2: Velocity & Rate Limit ────────────────────────────────────

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

    # ── Nhóm 3: AI Detection (inject log) ────────────────────────────────

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
        # Try actual bad input first
        sc_live, body_live = await _call_gateway("POST", "/payments", token=token,
            json_body={"from_account": "1' OR '1'='1", "to_account": "ACC-2001",
                       "amount": 100, "currency": "VND"})
        # Also inject AI log for the pattern
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
