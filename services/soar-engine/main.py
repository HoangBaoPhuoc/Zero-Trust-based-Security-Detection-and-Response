import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Literal

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Header, HTTPException, Request
from kubernetes import client, config
from kubernetes.client import ApiException
from pydantic import BaseModel, Field


APP_NAME = "soar-engine"
LOKI_URL = os.getenv("LOKI_URL", "http://loki.plg-stack.svc.cluster.local:3100").rstrip("/")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis.financial.svc.cluster.local:6379/2")
REDIS_BLOCKED_IPS_KEY = "ztlab:blocked_ips"
REDIS_BLOCKED_IPS_TTL = int(os.getenv("SOAR_BLOCK_IP_TTL_SECONDS", "86400"))  # 24h default

_redis: aioredis.Redis | None = None
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.identity.svc.cluster.local:8080").rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "ztlab")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "")
SOAR_DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"
SOAR_AUTO_EXECUTE = os.getenv("SOAR_AUTO_EXECUTE", "true").lower() == "true"
SOAR_MIN_SEVERITY = os.getenv("SOAR_MIN_SEVERITY", "high").lower()
SOAR_NAMESPACE = os.getenv("SOAR_NAMESPACE", "financial")
SOAR_ALLOWED_CONTEXTS = {item.strip() for item in os.getenv("SOAR_ALLOWED_CONTEXTS", "ctx-aws,ctx-openstack").split(",") if item.strip()}
SOAR_API_TOKEN = os.getenv("SOAR_API_TOKEN", "").strip()
CASE_STORE_PATH = os.getenv("SOAR_CASE_STORE_PATH", "/data/cases.jsonl")
SOAR_HITL_SEVERITY = os.getenv("SOAR_HITL_SEVERITY", "high").lower()
SOAR_PUBLIC_URL = os.getenv("SOAR_PUBLIC_URL", "http://127.0.0.1:8091").rstrip("/")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

TARGETS_BY_ATTACK = {
    "fraud_gate_bypass":    {"context": "ctx-aws",        "workload": "payment-service"},
    "lateral_movement":     {"context": "ctx-aws",        "workload": "payment-service"},
    "large_response":       {"context": "ctx-aws",        "workload": "api-gateway"},
    "cryptomining":         {"context": "ctx-aws",        "workload": "api-gateway"},
    "port_scan":            {"context": "ctx-aws",        "workload": "api-gateway"},
    "exploit_probe":        {"context": "ctx-aws",        "workload": "api-gateway"},
    "brute_force":          {"context": "ctx-aws",        "workload": "api-gateway"},
    "credential_stuffing":  {"context": "ctx-aws",        "workload": "api-gateway"},
    "access_denied":        {"context": "ctx-aws",        "workload": "api-gateway"},
    "jwt_replay":           {"context": "ctx-aws",        "workload": "api-gateway"},
}

PLAYBOOK_BY_ATTACK = {
    "fraud_gate_bypass":    "isolate_workload",
    "lateral_movement":     "isolate_workload",
    "large_response":       "restrict_egress",
    "cryptomining":         "quarantine_workload",
    "port_scan":            "block_source_ip",
    "exploit_probe":        "block_source_ip",
    "brute_force":          "revoke_user_sessions",
    "credential_stuffing":  "revoke_user_sessions",
    "access_denied":        "block_source_ip",
    "jwt_replay":           "revoke_user_sessions",
}

ALLOWED_PLAYBOOKS = {
    "isolate_workload",
    "restrict_egress",
    "quarantine_workload",
    "block_source_ip",
    "revoke_user_sessions",
    "monitor_only",
}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(APP_NAME)
app = FastAPI(title="ZTLab SOAR Engine")


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError:
        logger.warning(json.dumps({"event_type": "invalid_env_float", "name": name, "value": raw, "default": default}))
        return default
    return max(minimum, min(maximum, value))


SOAR_MIN_CONFIDENCE = _env_float("SOAR_MIN_CONFIDENCE", 0.70, 0.0, 1.0)
if SOAR_MIN_SEVERITY not in SEVERITY_RANK:
    logger.warning(json.dumps({"event_type": "invalid_soar_min_severity", "value": SOAR_MIN_SEVERITY, "default": "high"}))
    SOAR_MIN_SEVERITY = "high"


# ── Models ──────────────────────────────────────────────────────────────────

class SecurityAlert(BaseModel):
    event_type: str = "ai_security_alert"
    analyzer: str = "soar-engine"
    provider: str = "unknown"
    model: str = "unknown"
    source: str = "unknown"
    verdict: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    attack_type: str = "unknown"
    summary: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = "monitor"
    recommended_playbook: str | None = None
    affected_service: str | None = None
    source_ip: str | None = None
    username: str | None = None
    log_count: int = 0
    log_hash: str | None = None
    ts: str | None = None


class PlaybookStep(BaseModel):
    phase: Literal["contain", "investigate", "eradicate", "recover"]
    status: Literal["completed", "failed", "skipped"]
    action: str
    ts: str
    error: str | None = None


class CaseRecord(BaseModel):
    case_id: str
    status: Literal["pending_approval", "skipped", "dry_run", "executed", "failed", "rolled_back", "rollback_failed"]
    alert_hash: str
    attack_type: str
    severity: str
    confidence: float
    playbook: str
    target_context: str | None = None
    target_namespace: str = SOAR_NAMESPACE
    target_workload: str | None = None
    source_ip: str | None = None
    username: str | None = None
    action: str
    reason: str
    error: str | None = None
    dry_run: bool
    steps: list[PlaybookStep] = Field(default_factory=list)
    ts: str


CASES: dict[str, CaseRecord] = {}

# case_id → (draft CaseRecord, playbook, target) chờ admin phê duyệt
_HITL_QUEUE: dict[str, tuple[CaseRecord, str, dict[str, Any]]] = {}


# ── Auth & persistence ───────────────────────────────────────────────────────

def require_soar_token(authorization: str | None) -> None:
    if not SOAR_API_TOKEN:
        return  # token not configured — open access (lab/demo mode)
    expected = f"Bearer {SOAR_API_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="invalid SOAR API token")


def load_cases() -> None:
    path = os.path.abspath(CASE_STORE_PATH)
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                case = CaseRecord.model_validate_json(line)
                CASES[case.case_id] = case
            except Exception as exc:
                logger.error(json.dumps({"event_type": "soar_case_load_failed", "error": str(exc)}))


def persist_case(case: CaseRecord) -> None:
    path = os.path.abspath(CASE_STORE_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(case.model_dump_json() + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_alert(alert: SecurityAlert) -> str:
    raw = alert.model_dump_json(exclude_none=True, exclude_defaults=False)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _case_id(alert_hash: str) -> str:
    return f"case-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{alert_hash[:6]}"


def _attack_tokens(attack_type: str) -> list[str]:
    return [token.strip().lower() for token in re.split(r"[,;/\s]+", attack_type or "") if token.strip()]


def _first_known_attack(alert: SecurityAlert) -> str:
    tokens = [t for t in _attack_tokens(alert.attack_type) if t in PLAYBOOK_BY_ATTACK]
    if not tokens:
        return "unknown"
    # Prefer the token whose playbook matches AI's recommended_playbook
    if alert.recommended_playbook:
        for token in tokens:
            if PLAYBOOK_BY_ATTACK.get(token) == alert.recommended_playbook:
                return token
    return tokens[0]


def _infer_target(alert: SecurityAlert, attack: str) -> dict[str, str | None]:
    target = dict(TARGETS_BY_ATTACK.get(attack, {}))
    if alert.affected_service:
        target["workload"] = alert.affected_service
    if not target.get("context"):
        text = " ".join(alert.evidence + [alert.summary, alert.recommended_action]).lower()
        target["context"] = "ctx-openstack" if "openstack" in text or "/os/" in text else "ctx-aws"
    return {"context": target.get("context"), "workload": target.get("workload")}


def _select_playbook(alert: SecurityAlert, attack: str) -> str:
    # AI recommended_playbook takes priority — it has full log context
    if alert.recommended_playbook in ALLOWED_PLAYBOOKS and alert.recommended_playbook != "monitor_only":
        return alert.recommended_playbook
    if attack in PLAYBOOK_BY_ATTACK:
        return PLAYBOOK_BY_ATTACK[attack]
    if alert.recommended_playbook in ALLOWED_PLAYBOOKS:
        return alert.recommended_playbook
    return "monitor_only"


def _should_execute(alert: SecurityAlert) -> tuple[bool, str]:
    if not SOAR_AUTO_EXECUTE:
        return False, "SOAR_AUTO_EXECUTE is disabled"
    if alert.verdict == "normal":
        return False, "normal verdict"
    if SEVERITY_RANK.get(alert.severity, 0) < SEVERITY_RANK.get(SOAR_MIN_SEVERITY, 3):
        return False, f"severity below threshold {SOAR_MIN_SEVERITY}"
    if alert.confidence < SOAR_MIN_CONFIDENCE:
        return False, f"confidence below threshold {SOAR_MIN_CONFIDENCE}"
    return True, "eligible for automated response"


def _needs_hitl(alert: SecurityAlert) -> bool:
    """Severity >= SOAR_HITL_SEVERITY yêu cầu admin phê duyệt trước khi thực thi."""
    return SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK.get(SOAR_HITL_SEVERITY, 3)


def _hitl_token(case_id: str) -> str:
    secret = (SOAR_API_TOKEN or "ztlab-soar-hitl").encode()
    return hmac.new(secret, case_id.encode(), "sha256").hexdigest()[:20]


def _verify_hitl_token(case_id: str, token: str) -> bool:
    return hmac.compare_digest(_hitl_token(case_id), token)


def _hitl_email_html(case: CaseRecord, alert_name: str, mitre: str, log_lines: list[str]) -> str:
    approve_url = f"{SOAR_PUBLIC_URL}/cases/{case.case_id}/approve?token={_hitl_token(case.case_id)}"
    deny_url    = f"{SOAR_PUBLIC_URL}/cases/{case.case_id}/deny?token={_hitl_token(case.case_id)}"
    severity_color = {"low": "#4CAF50", "medium": "#FF9800", "high": "#F44336", "critical": "#9C27B0"}.get(case.severity, "#F44336")
    logs_html = "".join(f"<li style='font-size:12px;color:#555'>{l}</li>" for l in log_lines[:10]) or "<li>Không có log evidence</li>"
    return f"""
<div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden">
  <div style="background:#1a1a2e;padding:20px 24px">
    <h2 style="color:#fff;margin:0;font-size:18px">🚨 ZTLab Security Alert — Cần phê duyệt</h2>
  </div>
  <div style="padding:24px">
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold;width:140px">Alert</td><td style="padding:6px 12px">{alert_name}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Severity</td><td style="padding:6px 12px"><span style="background:{severity_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{case.severity.upper()}</span></td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">MITRE ATT&CK</td><td style="padding:6px 12px">{mitre}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Playbook</td><td style="padding:6px 12px"><code>{case.playbook}</code></td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Target</td><td style="padding:6px 12px">{case.target_context or '—'} / {case.target_workload or '—'}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Source IP</td><td style="padding:6px 12px">{case.source_ip or '—'}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Case ID</td><td style="padding:6px 12px"><code style="font-size:11px">{case.case_id}</code></td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Thời gian</td><td style="padding:6px 12px">{case.ts}</td></tr>
    </table>
    <h4 style="margin:0 0 8px;color:#333">Log Evidence (Loki):</h4>
    <ul style="background:#f9f9f9;border:1px solid #e0e0e0;border-radius:4px;padding:12px 12px 12px 28px;margin:0 0 24px">{logs_html}</ul>
    <p style="color:#555;font-size:13px;margin:0 0 20px">
      Playbook <strong>{case.playbook}</strong> sẽ được thực thi trên <strong>{case.target_context}/{case.target_workload or case.source_ip}</strong>.
      Vui lòng xem xét log evidence và phê duyệt hoặc từ chối.
    </p>
    <div style="text-align:center;margin-bottom:8px">
      <a href="{approve_url}" style="display:inline-block;background:#4CAF50;color:#fff;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:15px;margin-right:16px">
        ✅ PHÊ DUYỆT &amp; THỰC THI
      </a>
      <a href="{deny_url}" style="display:inline-block;background:#9e9e9e;color:#fff;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:15px">
        ❌ TỪ CHỐI
      </a>
    </div>
    <p style="text-align:center;font-size:11px;color:#aaa;margin-top:16px">
      Link có hiệu lực 24h. SOAR Engine: {SOAR_PUBLIC_URL}
    </p>
  </div>
</div>
"""


def _smtp_send(subject: str, html: str) -> None:
    if not ADMIN_EMAIL or not SMTP_USER or not SMTP_PASS:
        logger.warning(json.dumps({"event_type": "hitl_email_skip", "reason": "SMTP not configured"}))
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM or SMTP_USER
    msg["To"]      = ADMIN_EMAIL
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.ehlo()
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_FROM or SMTP_USER, ADMIN_EMAIL, msg.as_string())


async def _send_hitl_email(case: CaseRecord, alert_name: str, mitre: str, log_lines: list[str]) -> None:
    subject = f"[ZTLab SOAR — {case.severity.upper()}] {alert_name} — Cần phê duyệt phản ứng"
    html    = _hitl_email_html(case, alert_name, mitre, log_lines)
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _smtp_send, subject, html)
        logger.info(json.dumps({"event_type": "hitl_email_sent", "case_id": case.case_id, "to": ADMIN_EMAIL}))
    except Exception as exc:
        logger.error(json.dumps({"event_type": "hitl_email_failed", "case_id": case.case_id, "error": str(exc)}))


# ── Kubernetes API helpers ───────────────────────────────────────────────────

def _load_k8s(context: str | None) -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config(context=context)


def _load_core_api(context: str | None) -> client.CoreV1Api:
    _load_k8s(context)
    return client.CoreV1Api()


def _load_apps_api(context: str | None) -> client.AppsV1Api:
    _load_k8s(context)
    return client.AppsV1Api()


def _load_networking_api(context: str | None) -> client.NetworkingV1Api:
    _load_k8s(context)
    return client.NetworkingV1Api()


# ── Playbook: isolate_workload ───────────────────────────────────────────────

def _isolate_service(context: str, workload: str) -> str:
    api = _load_core_api(context)
    service = api.read_namespaced_service(name=workload, namespace=SOAR_NAMESPACE)
    selector = dict(service.spec.selector or {})
    selector["soar.ztlab.io/isolated"] = "true"
    body = {
        "metadata": {
            "annotations": {
                "soar.ztlab.io/original-selector": json.dumps(service.spec.selector or {}, sort_keys=True),
                "soar.ztlab.io/isolated-at": _now_iso(),
            }
        },
        "spec": {"selector": selector},
    }
    api.patch_namespaced_service(name=workload, namespace=SOAR_NAMESPACE, body=body)
    return f"patched Service/{workload} selector → no traffic; pods still running for forensics"


def _restore_service(context: str, workload: str) -> str:
    api = _load_core_api(context)
    service = api.read_namespaced_service(name=workload, namespace=SOAR_NAMESPACE)
    annotations = service.metadata.annotations or {}
    raw_selector = annotations.get("soar.ztlab.io/original-selector")
    if not raw_selector:
        raise ValueError("original service selector annotation is missing")
    selector = json.loads(raw_selector)
    service = api.read_namespaced_service(name=workload, namespace=SOAR_NAMESPACE)
    service.spec.selector = selector
    if service.metadata.annotations is None:
        service.metadata.annotations = {}
    service.metadata.annotations["soar.ztlab.io/rolled-back-at"] = _now_iso()
    service.metadata.managed_fields = None
    api.replace_namespaced_service(name=workload, namespace=SOAR_NAMESPACE, body=service)
    return f"restored original Service/{workload} selector"


# ── Playbook: restrict_egress / quarantine_workload ──────────────────────────

def _scale_deployment(context: str, workload: str, reason: str) -> str:
    api = _load_apps_api(context)
    deployment = api.read_namespaced_deployment(name=workload, namespace=SOAR_NAMESPACE)
    current_replicas = deployment.spec.replicas if deployment.spec.replicas is not None else 1
    api.patch_namespaced_deployment(
        name=workload,
        namespace=SOAR_NAMESPACE,
        body={
            "metadata": {
                "annotations": {
                    "soar.ztlab.io/original-replicas": str(current_replicas),
                    "soar.ztlab.io/scaled-at": _now_iso(),
                    "soar.ztlab.io/scale-reason": reason,
                }
            }
        },
    )
    api.patch_namespaced_deployment_scale(name=workload, namespace=SOAR_NAMESPACE, body={"spec": {"replicas": 0}})
    return f"scaled Deployment/{workload} from {current_replicas} → 0 replicas ({reason})"


def _restore_deployment(context: str, workload: str) -> str:
    api = _load_apps_api(context)
    deployment = api.read_namespaced_deployment(name=workload, namespace=SOAR_NAMESPACE)
    annotations = deployment.metadata.annotations or {}
    replicas = int(annotations.get("soar.ztlab.io/original-replicas", "1"))
    api.patch_namespaced_deployment_scale(name=workload, namespace=SOAR_NAMESPACE, body={"spec": {"replicas": replicas}})
    api.patch_namespaced_deployment(
        name=workload,
        namespace=SOAR_NAMESPACE,
        body={"metadata": {"annotations": {"soar.ztlab.io/rolled-back-at": _now_iso()}}},
    )
    return f"restored Deployment/{workload} to {replicas} replicas"


# ── Playbook: block_source_ip ────────────────────────────────────────────────

def _block_policy_name(source_ip: str) -> str:
    ip_hash = hashlib.md5(source_ip.encode()).hexdigest()[:8]
    return f"soar-block-{ip_hash}"


def _block_source_ip(context: str, source_ip: str) -> str:
    """Create a NetworkPolicy in SOAR_NAMESPACE that blocks all ingress from source_ip/32.

    K8s NetworkPolicy uses additive whitelist: policies already allow traffic from
    namespace selectors.  This new policy adds an ipBlock exception so that any
    ipBlock-based path (NodePort with externalTrafficPolicy=Local, Cilium, Calico)
    is blocked.  It also creates an explicit DENY by having policyTypes=[Ingress]
    with a single from-rule that covers 0.0.0.0/0 EXCEPT the target IP — meaning
    the target IP is excluded from the allow-all rule and no other policy covers it.
    """
    api = _load_networking_api(context)
    policy_name = _block_policy_name(source_ip)

    # Strip /prefix if caller passed CIDR notation
    host_ip = source_ip.split("/")[0]
    cidr = f"{host_ip}/32"

    body = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": policy_name,
            "namespace": SOAR_NAMESPACE,
            "annotations": {
                "soar.ztlab.io/blocked-ip": host_ip,
                "soar.ztlab.io/created-at": _now_iso(),
                "soar.ztlab.io/reason": "SOAR automated block",
            },
            "labels": {
                "soar.ztlab.io/managed": "true",
                "soar.ztlab.io/type": "ip-block",
            },
        },
        "spec": {
            "podSelector": {},   # all pods in namespace
            "policyTypes": ["Ingress"],
            "ingress": [
                {
                    "from": [
                        {
                            "ipBlock": {
                                "cidr": "0.0.0.0/0",
                                "except": [cidr],
                            }
                        }
                    ]
                }
            ],
        },
    }

    try:
        existing = api.read_namespaced_network_policy(name=policy_name, namespace=SOAR_NAMESPACE)
        existing.metadata.annotations = existing.metadata.annotations or {}
        existing.metadata.annotations["soar.ztlab.io/updated-at"] = _now_iso()
        existing.spec.ingress[0]["from"][0]["ipBlock"]["except"] = [cidr]
        api.replace_namespaced_network_policy(name=policy_name, namespace=SOAR_NAMESPACE, body=existing)
        return f"updated NetworkPolicy/{policy_name} — blocked {cidr}"
    except ApiException as exc:
        if exc.status != 404:
            raise
        api.create_namespaced_network_policy(namespace=SOAR_NAMESPACE, body=body)
        return f"created NetworkPolicy/{policy_name} — blocked {cidr} in {SOAR_NAMESPACE}"


def _unblock_source_ip(context: str, source_ip: str) -> str:
    api = _load_networking_api(context)
    policy_name = _block_policy_name(source_ip)
    try:
        api.delete_namespaced_network_policy(name=policy_name, namespace=SOAR_NAMESPACE)
        return f"deleted NetworkPolicy/{policy_name} — {source_ip} unblocked"
    except ApiException as exc:
        if exc.status == 404:
            return f"NetworkPolicy/{policy_name} not found (already removed)"
        raise


# ── Playbook: revoke_user_sessions ───────────────────────────────────────────

async def _get_keycloak_admin_token() -> str:
    if not KEYCLOAK_ADMIN_PASSWORD:
        raise RuntimeError("KEYCLOAK_ADMIN_PASSWORD is not configured")
    async with httpx.AsyncClient(timeout=10) as h:
        resp = await h.post(
            f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KEYCLOAK_ADMIN_USER,
                "password": KEYCLOAK_ADMIN_PASSWORD,
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


async def _revoke_user_sessions(username: str) -> str:
    """Revoke all active Keycloak sessions for username via Admin REST API."""
    token = await _get_keycloak_admin_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}"

    async with httpx.AsyncClient(timeout=15) as h:
        # Find user ID
        resp = await h.get(f"{base}/users", params={"username": username, "exact": "true"}, headers=headers)
        resp.raise_for_status()
        users = resp.json()
        if not users:
            return f"user '{username}' not found in realm {KEYCLOAK_REALM}"
        user_id = users[0]["id"]

        # Count active sessions (404 = no sessions, not an error)
        sessions_resp = await h.get(f"{base}/users/{user_id}/sessions", headers=headers)
        if sessions_resp.status_code == 404:
            session_count = 0
        else:
            sessions_resp.raise_for_status()
            session_count = len(sessions_resp.json())

        # Revoke all sessions — skip if none exist
        if session_count > 0:
            revoke_resp = await h.delete(f"{base}/users/{user_id}/sessions", headers=headers)
            if revoke_resp.status_code not in (204, 200, 404):
                revoke_resp.raise_for_status()

        # Also trigger brute-force attack-detection clear so Keycloak re-evaluates
        try:
            await h.delete(f"{base}/attack-detection/brute-force/users/{user_id}", headers=headers)
        except Exception:
            pass

        return (
            f"revoked {session_count} session(s) for user '{username}' "
            f"(user_id={user_id[:8]}...) in realm {KEYCLOAK_REALM}"
        )


# ── Investigate step — query Loki for evidence ──────────────────────────────

async def _investigate_loki(attack_type: str, workload: str | None, source_ip: str | None) -> str:
    """Query Loki for recent evidence related to the attack."""
    end_ns = time.time_ns()
    start_ns = end_ns - 30 * 60 * 10 ** 9  # last 30 minutes

    parts = []
    if workload:
        parts.append(f'app="{workload}"')
    base_filter = "{" + ", ".join(parts) + "}" if parts else '{job="kubernetes-pods", namespace="financial"}'

    search_terms = {
        "brute_force":          "401|403|login.fail|authentication.fail",
        "credential_stuffing":  "401|403|login.fail|too.many",
        "lateral_movement":     "svid|denied|lateral|spiffe",
        "fraud_gate_bypass":    "fraud_gate|fraud_score|bypass",
        "port_scan":            "port.scan|nmap|syn.scan|masscan",
        "exploit_probe":        "sqlmap|union.select|cmd.injection|payload",
        "cryptomining":         "xmrig|stratum|cryptomin|cpu",
        "large_response":       "bytes_sent|data.exfil|large.response",
        "jwt_replay":           "jwt.replay|token.reuse|duplicate.jti",
        "access_denied":        "denied|403|unauthorized",
    }
    term = search_terms.get(attack_type, "denied|error|attack|fail")
    if source_ip:
        term = f"{source_ip}|{term}"

    query = f'{base_filter} |~ "(?i)({term})"'

    try:
        async with httpx.AsyncClient(timeout=10) as h:
            resp = await h.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={"query": query, "start": start_ns, "end": end_ns, "limit": 10},
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("data", {}).get("result", [])
            count = sum(len(stream.get("values", [])) for stream in results)
            return f"Loki evidence: {count} log entries matched query for {attack_type}" + (
                f" from {source_ip}" if source_ip else ""
            )
    except Exception as exc:
        return f"Loki query failed: {exc}"


# ── 4-step playbook runner ───────────────────────────────────────────────────

async def _run_steps(
    playbook: str,
    context: str | None,
    workload: str | None,
    source_ip: str | None,
    username: str | None,
    attack_type: str,
    dry_run: bool,
) -> tuple[str, list[PlaybookStep]]:
    """Execute the 4-phase playbook (contain → investigate → eradicate → recover).

    Returns (summary_action, steps_list).
    """
    steps: list[PlaybookStep] = []

    def _step(phase: str, fn_result: str | None = None, error: str | None = None, skipped: bool = False) -> None:
        status: Literal["completed", "failed", "skipped"]
        if skipped:
            status = "skipped"
            action = "skipped"
        elif error:
            status = "failed"
            action = fn_result or "failed"
        else:
            status = "completed"
            action = fn_result or "ok"
        steps.append(PlaybookStep(
            phase=phase,  # type: ignore[arg-type]
            status=status,
            action=action,
            ts=_now_iso(),
            error=error,
        ))

    # ── PHASE 1: contain ────────────────────────────────────────────────────
    if dry_run:
        _step("contain", f"dry_run: would execute {playbook} on {context}/{SOAR_NAMESPACE}/{workload or source_ip}")
        _step("investigate", "dry_run: skipped", skipped=True)
        _step("eradicate", "dry_run: skipped", skipped=True)
        _step("recover", "pending admin rollback trigger")
        return f"dry_run: would run {playbook}", steps

    contain_action = "skipped"
    try:
        if playbook == "isolate_workload" and workload and context:
            contain_action = _isolate_service(context, workload)
        elif playbook in {"restrict_egress", "quarantine_workload"} and workload and context:
            reason = "suspected exfiltration" if playbook == "restrict_egress" else "suspected cryptomining/compromise"
            contain_action = _scale_deployment(context, workload, reason)
        elif playbook == "block_source_ip":
            if source_ip and context:
                contain_action = _block_source_ip(context, source_ip)
                # Also write to Redis so api-gateway can enforce in real-time
                await redis_block_ip(source_ip, reason=f"SOAR: {attack_type}")
            else:
                contain_action = "skipped: no source_ip or context available"
        elif playbook == "revoke_user_sessions":
            if username:
                contain_action = await _revoke_user_sessions(username)
            else:
                contain_action = "skipped: no username in alert"
        elif playbook == "monitor_only":
            contain_action = "monitor only — no automated action"
        # Always write source_ip to Redis blocklist for any playbook when IP is known
        if source_ip and playbook not in {"revoke_user_sessions", "monitor_only"}:
            await redis_block_ip(source_ip, reason=f"SOAR: {attack_type} via {playbook}")
        _step("contain", contain_action)
    except Exception as exc:
        _step("contain", error=str(exc))

    # ── PHASE 2: investigate ────────────────────────────────────────────────
    try:
        inv_result = await _investigate_loki(attack_type, workload, source_ip)
        _step("investigate", inv_result)
    except Exception as exc:
        _step("investigate", error=str(exc))

    # ── PHASE 3: eradicate ──────────────────────────────────────────────────
    try:
        if playbook in {"isolate_workload", "restrict_egress", "quarantine_workload"} and source_ip and context:
            # Secondary action: also block the attacking source IP
            block_action = _block_source_ip(context, source_ip)
            _step("eradicate", block_action)
        elif playbook == "block_source_ip":
            # IP already blocked in contain; confirm
            _step("eradicate", f"IP {source_ip} already blocked in contain phase; no additional action")
        elif playbook == "revoke_user_sessions":
            _step("eradicate", f"sessions revoked in contain phase; user must re-authenticate with valid credentials")
        else:
            _step("eradicate", "no automated eradication action for this playbook", skipped=True)
    except Exception as exc:
        _step("eradicate", error=str(exc))

    # ── PHASE 4: recover ────────────────────────────────────────────────────
    # Recovery is always manual — admin triggers POST /cases/{id}/rollback
    _step("recover", "pending: admin must trigger POST /cases/{case_id}/rollback to restore service")

    summary = f"executed {playbook} ({contain_action})"
    return summary, steps


# ── Rollback ────────────────────────────────────────────────────────────────

def rollback_playbook(case: CaseRecord) -> str:
    context = case.target_context
    workload = case.target_workload
    source_ip = case.source_ip

    if not context or context not in SOAR_ALLOWED_CONTEXTS:
        raise ValueError(f"context {context!r} is not allowed")

    if case.playbook == "isolate_workload":
        if not workload:
            raise ValueError("target workload is required")
        return _restore_service(context, workload)

    if case.playbook in {"restrict_egress", "quarantine_workload"}:
        if not workload:
            raise ValueError("target workload is required")
        action = _restore_deployment(context, workload)
        # Also unblock source IP if it was blocked in eradicate phase
        if source_ip:
            try:
                unblock = _unblock_source_ip(context, source_ip)
                action = f"{action}; {unblock}"
            except Exception as exc:
                action = f"{action}; unblock failed: {exc}"
        return action

    if case.playbook == "block_source_ip":
        if not source_ip:
            raise ValueError("source_ip is required to rollback block_source_ip")
        return _unblock_source_ip(context, source_ip)

    if case.playbook == "revoke_user_sessions":
        return "revoke_user_sessions has no automatic rollback — admin must manually unlock user in Keycloak"

    raise ValueError(f"playbook {case.playbook!r} has no rollback action")


# ── Loki + record helpers ────────────────────────────────────────────────────

async def push_case_to_loki(case: CaseRecord) -> None:
    line = json.dumps({"event_type": "soar_action", "engine": APP_NAME, **case.model_dump()}, ensure_ascii=True)
    payload = {
        "streams": [
            {
                "stream": {
                    "job": "soar-engine",
                    "service": APP_NAME,
                    "status": case.status,
                    "playbook": case.playbook,
                    "attack_type": case.attack_type[:80],
                },
                "values": [[str(time.time_ns()), line]],
            }
        ]
    }
    async with httpx.AsyncClient() as client_:
        response = await client_.post(f"{LOKI_URL}/loki/api/v1/push", json=payload, timeout=10)
        response.raise_for_status()


async def record_case(case: CaseRecord) -> CaseRecord:
    CASES[case.case_id] = case
    persist_case(case)
    logger.warning(json.dumps({"event_type": "soar_action", "engine": APP_NAME, **case.model_dump()}, ensure_ascii=True))
    try:
        await push_case_to_loki(case)
    except Exception as exc:
        logger.error(json.dumps({"event_type": "soar_audit_push_failed", "error": str(exc), "case_id": case.case_id}))
    return case


# ── Redis helpers ────────────────────────────────────────────────────────────

async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
    return _redis


async def redis_block_ip(ip: str, reason: str = "SOAR automated block") -> None:
    try:
        r = await _get_redis()
        key = f"ztlab:blocked_ip:{ip}"
        await r.setex(key, REDIS_BLOCKED_IPS_TTL, json.dumps({
            "ip": ip, "reason": reason, "ts": _now_iso(),
            "ttl_seconds": REDIS_BLOCKED_IPS_TTL,
        }))
        await r.sadd(REDIS_BLOCKED_IPS_KEY, ip)
    except Exception as exc:
        logger.error(json.dumps({"event_type": "redis_block_ip_failed", "ip": ip, "error": str(exc)}))


async def redis_unblock_ip(ip: str) -> None:
    try:
        r = await _get_redis()
        await r.delete(f"ztlab:blocked_ip:{ip}")
        await r.srem(REDIS_BLOCKED_IPS_KEY, ip)
    except Exception as exc:
        logger.error(json.dumps({"event_type": "redis_unblock_ip_failed", "ip": ip, "error": str(exc)}))


async def redis_get_blocked_ips() -> list[dict]:
    try:
        r = await _get_redis()
        members = await r.smembers(REDIS_BLOCKED_IPS_KEY)
        result = []
        for ip in members:
            raw = await r.get(f"ztlab:blocked_ip:{ip}")
            if raw:
                result.append(json.loads(raw))
            else:
                # Entry in set but no TTL key — stale, clean up
                await r.srem(REDIS_BLOCKED_IPS_KEY, ip)
        return sorted(result, key=lambda x: x.get("ts", ""), reverse=True)
    except Exception as exc:
        logger.error(json.dumps({"event_type": "redis_get_blocked_ips_failed", "error": str(exc)}))
        return []


# ── FastAPI lifecycle ────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    load_cases()
    try:
        await _get_redis()
        logger.info(json.dumps({"event_type": "redis_connected", "url": REDIS_URL}))
    except Exception as exc:
        logger.warning(json.dumps({"event_type": "redis_connect_failed", "error": str(exc)}))


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "dry_run": SOAR_DRY_RUN,
        "auto_execute": SOAR_AUTO_EXECUTE,
        "min_severity": SOAR_MIN_SEVERITY,
        "min_confidence": SOAR_MIN_CONFIDENCE,
        "namespace": SOAR_NAMESPACE,
        "allowed_contexts": sorted(SOAR_ALLOWED_CONTEXTS),
        "case_store_path": CASE_STORE_PATH,
        "case_count": len(CASES),
        "pending_hitl": len(_HITL_QUEUE),
        "hitl_severity": SOAR_HITL_SEVERITY,
        "hitl_email": ADMIN_EMAIL or "not configured",
        "auth_required": bool(SOAR_API_TOKEN),
        "playbooks": sorted(ALLOWED_PLAYBOOKS),
    }


@app.get("/playbooks")
async def list_playbooks(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_soar_token(authorization)
    return {
        "thresholds": {"min_severity": SOAR_MIN_SEVERITY, "min_confidence": SOAR_MIN_CONFIDENCE},
        "dry_run": SOAR_DRY_RUN,
        "playbook_by_attack": PLAYBOOK_BY_ATTACK,
        "targets_by_attack": TARGETS_BY_ATTACK,
        "allowed_contexts": sorted(SOAR_ALLOWED_CONTEXTS),
        "playbooks": {
            "isolate_workload": "Patch Service selector → no traffic; pod still running for forensics",
            "restrict_egress": "Scale Deployment to 0 → stops outbound data transfer",
            "quarantine_workload": "Scale Deployment to 0 → full workload shutdown",
            "block_source_ip": "Create NetworkPolicy blocking source IP/32 from all financial pods",
            "revoke_user_sessions": "Revoke all active Keycloak sessions for compromised user",
            "monitor_only": "Log and monitor only — no automated K8s action",
        },
    }


@app.get("/cases")
async def cases(authorization: str | None = Header(default=None)) -> list[CaseRecord]:
    require_soar_token(authorization)
    return list(CASES.values())[-100:]


@app.get("/cases/{case_id}", response_model=CaseRecord)
async def case_detail(case_id: str, authorization: str | None = Header(default=None)) -> CaseRecord:
    require_soar_token(authorization)
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@app.post("/cases/{case_id}/rollback", response_model=CaseRecord)
async def rollback_case(case_id: str, authorization: str | None = Header(default=None)) -> CaseRecord:
    require_soar_token(authorization)
    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    if case.status not in {"executed", "dry_run", "rollback_failed"}:
        raise HTTPException(status_code=409, detail=f"case status {case.status} is not rollbackable")
    try:
        if case.dry_run:
            action = f"dry_run: would rollback {case.playbook} on {case.target_context}/{SOAR_NAMESPACE}/{case.target_workload or case.source_ip}"
        else:
            action = rollback_playbook(case)
        rollback = case.model_copy(update={"status": "rolled_back", "action": action, "error": None, "ts": _now_iso()})
    except Exception as exc:
        rollback = case.model_copy(update={"status": "rollback_failed", "action": "rollback failed", "error": str(exc), "ts": _now_iso()})
    result = await record_case(rollback)
    if result.status == "rollback_failed":
        raise HTTPException(status_code=500, detail=result.model_dump())
    return result


@app.post("/alerts", response_model=CaseRecord)
async def alerts(alert: SecurityAlert, authorization: str | None = Header(default=None)) -> CaseRecord:
    require_soar_token(authorization)
    alert_hash = alert.log_hash or _hash_alert(alert)
    case_id = _case_id(alert_hash)
    attack = _first_known_attack(alert)
    playbook = _select_playbook(alert, attack)
    target = _infer_target(alert, attack)
    eligible, reason = _should_execute(alert)

    status: Literal["pending_approval", "skipped", "dry_run", "executed", "failed", "rolled_back", "rollback_failed"]
    action = "no action"
    error: str | None = None
    steps: list[PlaybookStep] = []

    if playbook == "monitor_only" or not eligible:
        status = "skipped"
        reason = reason if playbook != "monitor_only" else f"no automated playbook for attack_type={alert.attack_type}"
    else:
        try:
            action, steps = await _run_steps(
                playbook=playbook,
                context=target.get("context"),
                workload=target.get("workload"),
                source_ip=alert.source_ip,
                username=alert.username,
                attack_type=attack,
                dry_run=SOAR_DRY_RUN,
            )
            status = "dry_run" if SOAR_DRY_RUN else "executed"
        except Exception as exc:
            status = "failed"
            error = str(exc)
            action = "execution failed"

    case = CaseRecord(
        case_id=case_id,
        status=status,
        alert_hash=alert_hash,
        attack_type=attack,
        severity=alert.severity,
        confidence=alert.confidence,
        playbook=playbook,
        target_context=target.get("context"),
        target_workload=target.get("workload"),
        source_ip=alert.source_ip,
        username=alert.username,
        action=action,
        reason=reason,
        error=error,
        dry_run=SOAR_DRY_RUN,
        steps=steps,
        ts=_now_iso(),
    )
    result = await record_case(case)
    if result.status == "failed":
        raise HTTPException(status_code=500, detail=result.model_dump())
    return result


# ── Grafana Alertmanager webhook ─────────────────────────────────────────────

GRAFANA_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "info": "low",
    "low": "low",
}

GRAFANA_ATTACK_MAP = {
    "fraud": "fraud_gate_bypass",
    "brute": "brute_force",
    "anomaly": "access_denied",
    "lateral": "lateral_movement",
    "port_scan": "port_scan",
    "exploit": "exploit_probe",
    "jwt": "jwt_replay",
}


def _grafana_to_alert(alert_data: dict) -> SecurityAlert | None:
    """Convert a single Grafana alert object to SecurityAlert. Returns None if not firing."""
    labels      = alert_data.get("labels", {})
    annotations = alert_data.get("annotations", {})

    if alert_data.get("status", "firing") != "firing":
        return None

    raw_severity = labels.get("severity", "medium").lower()
    severity = GRAFANA_SEVERITY_MAP.get(raw_severity, "medium")
    summary  = annotations.get("summary", labels.get("alertname", "unknown alert"))
    desc     = annotations.get("description", "")

    # Prefer explicit attack_type label (set in alert rule YAML).
    # Fall back to keyword matching on summary+description for older rules.
    attack_type = labels.get("attack_type", "")
    if not attack_type:
        text_lower = (summary + " " + desc).lower()
        attack_type = "access_denied"
        for keyword, mapped in GRAFANA_ATTACK_MAP.items():
            if keyword in text_lower:
                attack_type = mapped
                break

    # gap1 label means OpenStack-side exfiltration
    affected_service = "core-banking" if labels.get("gap") == "gap1" else None
    source_ip = labels.get("source_ip") or annotations.get("source_ip")
    fingerprint = alert_data.get("fingerprint", "")
    evidence = [e for e in [desc, f"mitre={labels.get('mitre', '')}", f"fingerprint={fingerprint}"] if e]

    return SecurityAlert(
        analyzer     = "grafana",
        provider     = "grafana-alertmanager",
        model        = "rule-based",
        source       = labels.get("alertname", "grafana-alert"),
        verdict      = "malicious",
        severity     = severity,  # type: ignore[arg-type]
        confidence   = 0.85,
        attack_type  = attack_type,
        summary      = summary,
        evidence     = evidence,
        recommended_action = f"respond to {attack_type}",
        recommended_playbook = PLAYBOOK_BY_ATTACK.get(attack_type),
        affected_service = affected_service,
        source_ip    = source_ip,
        ts           = _now_iso(),
    )


@app.post("/grafana-webhook")
async def grafana_webhook(request: Request) -> dict[str, Any]:
    """
    Receives Grafana alertmanager-compatible webhook (no auth — internal network only).
    Processes ALL firing alerts in the payload, one SOAR case per alert.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")

    firing_data = [a for a in payload.get("alerts", []) if a.get("status") == "firing"]
    if not firing_data:
        logger.info(json.dumps({"event_type": "grafana_webhook_noop", "total": len(payload.get("alerts", []))}))
        return {"processed": 0, "message": "no firing alerts"}

    results: list[dict[str, Any]] = []
    for alert_data in firing_data:
        alert = _grafana_to_alert(alert_data)
        if alert is None:
            continue

        fingerprint = alert_data.get("fingerprint", "")
        alert_hash = fingerprint or _hash_alert(alert)
        case_id    = _case_id(alert_hash)
        attack     = _first_known_attack(alert)
        playbook   = _select_playbook(alert, attack)
        target     = _infer_target(alert, attack)
        eligible, reason = _should_execute(alert)

        status: Literal["pending_approval", "skipped", "dry_run", "executed", "failed", "rolled_back", "rollback_failed"]
        action = "no action"
        error:  str | None = None
        steps:  list[PlaybookStep] = []

        if not eligible or playbook == "monitor_only":
            status = "skipped"
        elif _needs_hitl(alert):
            # Severity cao — giữ lại chờ admin phê duyệt
            status = "pending_approval"
            action = f"awaiting admin approval for playbook {playbook}"
            reason = f"severity={alert.severity} >= hitl_threshold={SOAR_HITL_SEVERITY}"
        else:
            try:
                action, steps = await _run_steps(
                    playbook    = playbook,
                    context     = target.get("context"),
                    workload    = target.get("workload"),
                    source_ip   = alert.source_ip,
                    username    = alert.username,
                    attack_type = attack,
                    dry_run     = SOAR_DRY_RUN,
                )
                status = "dry_run" if SOAR_DRY_RUN else "executed"
            except Exception as exc:
                status = "failed"
                error  = str(exc)
                action = "execution failed"

        case = CaseRecord(
            case_id         = case_id,
            status          = status,
            alert_hash      = alert_hash,
            attack_type     = attack,
            severity        = alert.severity,
            confidence      = alert.confidence,
            playbook        = playbook,
            target_context  = target.get("context"),
            target_workload = target.get("workload"),
            source_ip       = alert.source_ip,
            username        = alert.username,
            action          = action,
            reason          = reason,
            error           = error,
            dry_run         = SOAR_DRY_RUN,
            steps           = steps,
            ts              = _now_iso(),
        )
        await record_case(case)

        if status == "pending_approval":
            _HITL_QUEUE[case_id] = (case, playbook, target)
            ann = alert_data.get("annotations", {})
            lbs = alert_data.get("labels", {})
            await _send_hitl_email(
                case       = case,
                alert_name = lbs.get("alertname", attack),
                mitre      = lbs.get("mitre", "—"),
                log_lines  = ann.get("description", "").splitlines(),
            )

        logger.warning(json.dumps({"event_type": "grafana_soar_triggered", "case_id": case_id, "attack_type": attack, "playbook": playbook, "status": status}))
        results.append({"case_id": case_id, "attack_type": attack, "playbook": playbook, "status": status})

    return {"processed": len(results), "cases": results}


# ── HITL approve / deny endpoints ────────────────────────────────────────────

@app.get("/cases/{case_id}/approve")
async def hitl_approve(case_id: str, token: str = "") -> Any:
    from fastapi.responses import HTMLResponse
    if not _verify_hitl_token(case_id, token):
        raise HTTPException(status_code=403, detail="token không hợp lệ hoặc đã hết hạn")

    queued = _HITL_QUEUE.pop(case_id, None)
    if queued is None:
        stored = CASES.get(case_id)
        if stored and stored.status != "pending_approval":
            return HTMLResponse(_hitl_result_html(case_id, stored.status, already_done=True))
        raise HTTPException(status_code=404, detail="case không tồn tại hoặc đã xử lý")

    draft, playbook, target = queued
    action = "no action"
    error: str | None = None
    steps: list[PlaybookStep] = []
    try:
        action, steps = await _run_steps(
            playbook    = playbook,
            context     = target.get("context"),
            workload    = target.get("workload"),
            source_ip   = draft.source_ip,
            username    = draft.username,
            attack_type = draft.attack_type,
            dry_run     = SOAR_DRY_RUN,
        )
        final_status: Any = "dry_run" if SOAR_DRY_RUN else "executed"
    except Exception as exc:
        final_status = "failed"
        error = str(exc)
        action = "execution failed"

    approved = draft.model_copy(update={
        "status": final_status,
        "action": action,
        "reason": "admin approved via email link",
        "error":  error,
        "steps":  steps,
        "ts":     _now_iso(),
    })
    await record_case(approved)
    logger.warning(json.dumps({"event_type": "hitl_approved", "case_id": case_id, "status": final_status}))
    return HTMLResponse(_hitl_result_html(case_id, final_status))


@app.get("/cases/{case_id}/deny")
async def hitl_deny(case_id: str, token: str = "") -> Any:
    from fastapi.responses import HTMLResponse
    if not _verify_hitl_token(case_id, token):
        raise HTTPException(status_code=403, detail="token không hợp lệ hoặc đã hết hạn")

    queued = _HITL_QUEUE.pop(case_id, None)
    if queued is None:
        stored = CASES.get(case_id)
        if stored and stored.status != "pending_approval":
            return HTMLResponse(_hitl_result_html(case_id, stored.status, already_done=True))
        raise HTTPException(status_code=404, detail="case không tồn tại hoặc đã xử lý")

    draft, _pb, _tgt = queued
    denied = draft.model_copy(update={
        "status": "skipped",
        "action": "admin denied via email link",
        "reason": "admin rejected HITL approval",
        "ts":     _now_iso(),
    })
    await record_case(denied)
    logger.warning(json.dumps({"event_type": "hitl_denied", "case_id": case_id}))
    return HTMLResponse(_hitl_result_html(case_id, "skipped", denied=True))


def _hitl_result_html(case_id: str, status: str, denied: bool = False, already_done: bool = False) -> str:
    if already_done:
        icon, msg, color = "ℹ️", f"Case này đã được xử lý trước đó (status: {status}).", "#2196F3"
    elif denied:
        icon, msg, color = "✅", "Đã từ chối. Playbook không được thực thi.", "#9e9e9e"
    elif status in {"executed", "dry_run"}:
        icon, msg, color = "✅", f"Playbook đã thực thi thành công (status: {status}).", "#4CAF50"
    else:
        icon, msg, color = "⚠️", f"Có lỗi khi thực thi (status: {status}).", "#F44336"
    return f"""<!DOCTYPE html><html><body style="font-family:Arial;text-align:center;padding:60px">
<div style="max-width:480px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;padding:40px">
  <div style="font-size:48px">{icon}</div>
  <h2 style="color:{color}">{msg}</h2>
  <p style="color:#777;font-size:13px">Case ID: <code>{case_id}</code></p>
  <a href="{SOAR_PUBLIC_URL}/cases" style="color:#1976D2;font-size:13px">Xem tất cả cases →</a>
</div></body></html>"""


# ── Blocked IPs management ───────────────────────────────────────────────────

@app.get("/blocked-ips")
async def list_blocked_ips(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_soar_token(authorization)
    ips = await redis_get_blocked_ips()
    return {"blocked_ips": ips, "count": len(ips), "ttl_seconds": REDIS_BLOCKED_IPS_TTL}


@app.post("/blocked-ips/{ip}")
async def manual_block_ip(ip: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_soar_token(authorization)
    ip = ip.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        raise HTTPException(status_code=400, detail="invalid IPv4 address")
    await redis_block_ip(ip, reason="manual block via SOAR API")
    logger.warning(json.dumps({"event_type": "manual_ip_block", "ip": ip}))
    return {"status": "blocked", "ip": ip, "ttl_seconds": REDIS_BLOCKED_IPS_TTL}


@app.delete("/blocked-ips/{ip}")
async def unblock_ip(ip: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_soar_token(authorization)
    ip = ip.strip()
    await redis_unblock_ip(ip)
    logger.warning(json.dumps({"event_type": "ip_unblocked", "ip": ip}))
    return {"status": "unblocked", "ip": ip}
