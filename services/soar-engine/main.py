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
    "large_response":       {"context": "ctx-openstack",  "workload": "core-banking"},
    "cryptomining":         {"context": "ctx-aws",        "workload": "api-gateway"},
    "port_scan":            {"context": "ctx-aws",        "workload": "api-gateway"},
    "exploit_probe":        {"context": "ctx-aws",        "workload": "api-gateway"},
    "brute_force":          {"context": "ctx-aws",        "workload": "api-gateway"},
    "credential_stuffing":  {"context": "ctx-aws",        "workload": "api-gateway"},
    "access_denied":        {"context": "ctx-aws",        "workload": "api-gateway"},
    "jwt_replay":           {"context": "ctx-aws",        "workload": "api-gateway"},
    "account_manipulation": {"context": "ctx-openstack",  "workload": "account-service"},
    "data_staging":         {"context": "ctx-openstack",  "workload": "account-service"},
    "container_escape":     {"context": "ctx-aws",        "workload": "api-gateway"},
    "impair_defenses":      {"context": "ctx-aws",        "workload": "api-gateway"},
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
    "account_manipulation": "isolate_workload",
    "data_staging":         "restrict_egress",
    "container_escape":     "quarantine_workload",
    "impair_defenses":      "quarantine_workload",
}

MITRE_BY_ATTACK: dict[str, str] = {
    "brute_force":          "T1110.001",
    "credential_stuffing":  "T1110.004",
    "jwt_replay":           "T1539",
    "fraud_gate_bypass":    "T1078.004",
    "lateral_movement":     "T1021.007",
    "cryptomining":         "T1496",
    "port_scan":            "T1046",
    "exploit_probe":        "T1203",
    "large_response":       "T1041",
    "access_denied":        "T1078",
    "account_manipulation": "T1098",
    "data_staging":         "T1074",
    "container_escape":     "T1611",
    "impair_defenses":      "T1562",
}

ALLOWED_PLAYBOOKS = {
    "isolate_workload",
    "restrict_egress",
    "quarantine_workload",
    "block_source_ip",
    "revoke_user_sessions",
    "monitor_only",
}

# Tên hiển thị thân thiện cho từng loại tấn công (dùng trong email, không dùng "kịch bản")
ATTACK_DISPLAY_NAMES: dict[str, str] = {
    "brute_force":          "Brute Force Login (T1110.001)",
    "credential_stuffing":  "Credential Stuffing (T1110.004)",
    "jwt_replay":           "JWT Token Replay (T1539)",
    "fraud_gate_bypass":    "Fraud Gate Bypass (T1078.004)",
    "lateral_movement":     "Lateral Movement — Invalid SVID (T1021.007)",
    "cryptomining":         "Cryptomining Detected (T1496)",
    "port_scan":            "Port Scan Detected (T1046)",
    "exploit_probe":        "Exploit Probe / Injection (T1203)",
    "large_response":       "Data Exfiltration — Large Response (T1041)",
    "access_denied":        "Access Denied Spike (T1078)",
    "account_manipulation": "Account Manipulation (T1098)",
    "data_staging":         "Data Staging — Bulk Export (T1074)",
    "container_escape":     "Container Escape Attempt (T1611)",
    "impair_defenses":      "Impair Defenses (T1562)",
}

# Danh sách playbooks gợi ý cho từng loại tấn công (admin chọn, không giới hạn)
SUGGESTED_PLAYBOOKS: dict[str, list[str]] = {
    "brute_force":          ["revoke_user_sessions", "block_source_ip", "isolate_workload", "monitor_only"],
    "credential_stuffing":  ["revoke_user_sessions", "block_source_ip", "isolate_workload", "monitor_only"],
    "jwt_replay":           ["revoke_user_sessions", "block_source_ip", "isolate_workload", "monitor_only"],
    "fraud_gate_bypass":    ["isolate_workload", "restrict_egress", "block_source_ip", "revoke_user_sessions", "monitor_only"],
    "lateral_movement":     ["isolate_workload", "restrict_egress", "block_source_ip", "revoke_user_sessions", "monitor_only"],
    "cryptomining":         ["quarantine_workload", "isolate_workload", "block_source_ip", "monitor_only"],
    "port_scan":            ["block_source_ip", "isolate_workload", "monitor_only"],
    "exploit_probe":        ["block_source_ip", "isolate_workload", "restrict_egress", "monitor_only"],
    "large_response":       ["restrict_egress", "quarantine_workload", "isolate_workload", "block_source_ip", "monitor_only"],
    "access_denied":        ["block_source_ip", "isolate_workload", "monitor_only"],
    "account_manipulation": ["isolate_workload", "revoke_user_sessions", "block_source_ip", "monitor_only"],
    "data_staging":         ["restrict_egress", "quarantine_workload", "block_source_ip", "monitor_only"],
    "container_escape":     ["quarantine_workload", "isolate_workload", "block_source_ip", "monitor_only"],
    "impair_defenses":      ["quarantine_workload", "isolate_workload", "block_source_ip", "monitor_only"],
    "privilege_escalation": ["quarantine_workload", "isolate_workload", "block_source_ip", "monitor_only"],
}

PLAYBOOK_LABELS: dict[str, str] = {
    "isolate_workload":     "Cô lập dịch vụ",
    "restrict_egress":      "Hạn chế lưu lượng ra",
    "quarantine_workload":  "Cách ly workload",
    "block_source_ip":      "Chặn IP nguồn",
    "revoke_user_sessions": "Thu hồi phiên đăng nhập",
    "monitor_only":         "Chỉ theo dõi",
}


def _clean_alert_name(raw: str, attack_type: str = "") -> str:
    """Trả về tên alert sạch, không có tiền tố 'Kịch bản N —' hay 'Heuristic:'."""
    import re as _re
    # Bỏ tiền tố "Kịch bản N — " hoặc "Kịch bản N - "
    cleaned = _re.sub(r'^Kịch bản \d+\s*[—–\-]+\s*', '', raw).strip()
    # Nếu vẫn còn hoặc rỗng → dùng display name của attack_type
    if not cleaned or cleaned == raw:
        cleaned = ATTACK_DISPLAY_NAMES.get(attack_type, raw)
    return cleaned


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
    human_pre_approved: bool = False  # True khi admin đã duyệt ở AI Analyzer → bỏ qua SOAR HITL


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
    email_sent: bool = False


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


_OPENSTACK_WORKLOADS = {"core-banking", "account-service", "transaction-service"}


# ── Heuristic Log Poller (replaces ai-analyzer) ─────────────────────────────

_HEURISTIC_RULES: list[tuple[re.Pattern, str, str, float]] = [
    (re.compile(r"jwt_verification_failed|invalid_jwt|authentication.fail|login.fail", re.I), "brute_force", "high", 0.80),
    (re.compile(r"fraud.gate.bypass|fraud_block|channel.*tor", re.I), "fraud_gate_bypass", "high", 0.85),
    (re.compile(r"invalid.*svid|spiffe.*evil|lateral.move", re.I), "lateral_movement", "critical", 0.90),
    (re.compile(r"port.scan|nmap|masscan|syn.scan", re.I), "port_scan", "medium", 0.75),
    (re.compile(r"sqlmap|union.select|/etc/passwd|cmd=|command.inject", re.I), "exploit_probe", "high", 0.85),
    (re.compile(r"xmrig|stratum\+tcp|cryptomin", re.I), "cryptomining", "critical", 0.90),
    (re.compile(r"credential.stuf|multiple.usernames|common.password", re.I), "credential_stuffing", "high", 0.80),
    (re.compile(r"bytes_sent[=: ]\d{7,}|large.response|data.exfil", re.I), "large_response", "medium", 0.75),
    (re.compile(r"jwt.*replay|stolen.token|duplicate.jti|token.reuse", re.I), "jwt_replay", "high", 0.80),
]

_HEURISTIC_MIN_COUNT: dict[str, int] = {
    "brute_force": 5, "fraud_gate_bypass": 1, "lateral_movement": 1,
    "port_scan": 3, "exploit_probe": 1, "cryptomining": 1,
    "credential_stuffing": 2, "large_response": 1, "jwt_replay": 1,
}

_HEURISTIC_POLL_INTERVAL = int(os.getenv("HEURISTIC_POLL_INTERVAL", "60"))
_HEURISTIC_WINDOW_S = 300   # 5 min lookback trong Loki
_HEURISTIC_DEDUP_S  = 600   # 10 min dedup — không gửi alert trùng cùng loại
_heuristic_last_seen: dict[str, float] = {}

# Grafana webhook dedup: {attack_type: (case_id, severity_rank, timestamp)}
_WEBHOOK_DEDUP_S: int = 300  # 5 min — ngăn Grafana real-alert tạo case trùng với script
_webhook_recent: dict[str, tuple[str, int, float]] = {}


def _infer_target(alert: SecurityAlert, attack: str) -> dict[str, str | None]:
    target = dict(TARGETS_BY_ATTACK.get(attack, {}))
    if alert.affected_service:
        target["workload"] = alert.affected_service
        if alert.affected_service in _OPENSTACK_WORKLOADS:
            target["context"] = "ctx-openstack"
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
    """Severity >= SOAR_HITL_SEVERITY yêu cầu admin phê duyệt. Bỏ qua nếu đã được duyệt ở AI Analyzer."""
    if alert.human_pre_approved:
        return False
    return SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK.get(SOAR_HITL_SEVERITY, 3)


def _hitl_token(case_id: str) -> str:
    secret = (SOAR_API_TOKEN or "ztlab-soar-hitl").encode()
    return hmac.new(secret, case_id.encode(), "sha256").hexdigest()[:20]


def _verify_hitl_token(case_id: str, token: str) -> bool:
    return hmac.compare_digest(_hitl_token(case_id), token)


def _hitl_email_html(case: CaseRecord, alert_name: str, mitre: str, log_lines: list[str]) -> str:
    token = _hitl_token(case.case_id)
    deny_url = f"{SOAR_PUBLIC_URL}/cases/{case.case_id}/deny?token={token}"
    severity_color = {"low": "#4CAF50", "medium": "#FF9800", "high": "#F44336", "critical": "#9C27B0"}.get(case.severity, "#F44336")
    logs_html = "".join(f"<li style='font-size:11px;color:#a8d8a8;word-break:break-all;font-family:monospace;margin-bottom:4px'>{l}</li>" for l in log_lines[:8]) or "<li style='color:#aaa'>Không có log evidence trong 30 phút qua</li>"

    # Extract source_ip from Loki evidence if not in case record
    display_source_ip = case.source_ip or _source_ip_from_evidence(log_lines)
    source_ip_label = display_source_ip or "—"
    source_ip_note = " <span style='font-size:10px;color:#888'>(từ log evidence)</span>" if (display_source_ip and not case.source_ip) else ""

    # Các hành động phản ứng được gợi ý cho loại tấn công này
    suggested = SUGGESTED_PLAYBOOKS.get(case.attack_type, ["block_source_ip", "monitor_only"])
    action_colors = {
        "isolate_workload": "#E53935", "quarantine_workload": "#E53935",
        "restrict_egress": "#F57C00", "block_source_ip": "#C62828",
        "revoke_user_sessions": "#1565C0", "monitor_only": "#757575",
    }
    action_icons = {
        "isolate_workload": "🔒", "quarantine_workload": "⚠️",
        "restrict_egress": "🚧", "block_source_ip": "🚫",
        "revoke_user_sessions": "🔑", "monitor_only": "📊",
    }
    action_buttons_html = ""
    for pb in suggested:
        url = f"{SOAR_PUBLIC_URL}/cases/{case.case_id}/choose-action?playbook={pb}&token={token}"
        color = action_colors.get(pb, "#555")
        icon = action_icons.get(pb, "▶")
        label = PLAYBOOK_LABELS.get(pb, pb)
        action_buttons_html += f"""
      <a href="{url}" style="display:inline-block;background:{color};color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:13px;margin:4px">
        {icon} {label}
      </a>"""

    return f"""
<div style="font-family:Arial,sans-serif;max-width:660px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden">
  <div style="background:#1a1a2e;padding:20px 24px">
    <h2 style="color:#fff;margin:0;font-size:18px">🚨 ZTLab Security Alert — Yêu cầu xử lý</h2>
  </div>
  <div style="padding:24px">
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold;width:140px">Alert</td><td style="padding:6px 12px">{alert_name}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Severity</td><td style="padding:6px 12px"><span style="background:{severity_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{case.severity.upper()}</span></td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">MITRE ATT&CK</td><td style="padding:6px 12px">{mitre}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Loại tấn công</td><td style="padding:6px 12px"><code>{case.attack_type}</code></td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Target</td><td style="padding:6px 12px">{case.target_context or '—'} / {case.target_workload or '—'}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Source IP</td><td style="padding:6px 12px"><code>{source_ip_label}</code>{source_ip_note}</td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Case ID</td><td style="padding:6px 12px"><code style="font-size:11px">{case.case_id}</code></td></tr>
      <tr><td style="padding:6px 12px;background:#f5f5f5;font-weight:bold">Thời gian</td><td style="padding:6px 12px">{case.ts}</td></tr>
    </table>
    <h4 style="margin:0 0 8px;color:#333">📋 Log Evidence (từ Loki — log thật):</h4>
    <ul style="background:#1e1e1e;border-radius:4px;padding:12px 12px 12px 16px;margin:0 0 20px;list-style:none;overflow-x:auto">{logs_html}</ul>
    <div style="text-align:center;margin-bottom:20px">
      <a href="http://localhost:18081/security" style="display:inline-block;background:#1565C0;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:15px">
        🛡️ Xem &amp; Xử lý tại Web Portal
      </a>
      <p style="font-size:11px;color:#888;margin:6px 0 0">http://localhost:18081/security → đăng nhập analyst01 / Test1234!</p>
    </div>
    <div style="background:#fff8e1;border:1px solid #ffe082;border-radius:6px;padding:14px 16px;margin-bottom:16px">
      <p style="margin:0 0 10px;font-weight:bold;color:#555;font-size:12px">Hoặc xử lý nhanh qua API (chỉ hoạt động nếu truy cập từ máy chạy demo):</p>
      <div style="display:flex;flex-wrap:wrap;gap:4px">{action_buttons_html}
      </div>
    </div>
    <div style="text-align:center">
      <a href="{deny_url}" style="display:inline-block;background:#9e9e9e;color:#fff;padding:8px 24px;border-radius:6px;text-decoration:none;font-size:12px">
        ❌ Bỏ qua — không thực hiện
      </a>
    </div>
    <p style="text-align:center;font-size:11px;color:#aaa;margin-top:12px">
      ZTLab SOAR Engine · Case <code>{case.case_id}</code>
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


async def _send_hitl_email(case: CaseRecord, alert_name: str, mitre: str, log_lines: list[str]) -> bool:
    subject = f"[ZTLab SOAR — {case.severity.upper()}] {alert_name} — Cần phê duyệt phản ứng"
    html    = _hitl_email_html(case, alert_name, mitre, log_lines)
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _smtp_send, subject, html)
        logger.info(json.dumps({"event_type": "hitl_email_sent", "case_id": case.case_id, "to": ADMIN_EMAIL}))
        return True
    except Exception as exc:
        logger.error(json.dumps({"event_type": "hitl_email_failed", "case_id": case.case_id, "error": str(exc)}))
        return False


# ── Kubernetes API helpers ───────────────────────────────────────────────────

_OPENSTACK_KUBECONFIG = "/etc/soar/openstack-kubeconfig/kubeconfig"


def _load_k8s(context: str | None) -> None:
    if context == "ctx-openstack" and os.path.exists(_OPENSTACK_KUBECONFIG):
        config.load_kube_config(config_file=_OPENSTACK_KUBECONFIG, context=context)
        return
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


# Exact Loki LogQL queries per attack type — mirror the Grafana alert queries exactly
# so email evidence matches what triggered the alert.
_LOKI_EXACT_QUERIES: dict[str, str] = {
    # KB1: envoy-access 403 từ api-gateway, path=/payments — xác nhận brute force bị Envoy block
    "brute_force":       '{job="envoy-access", response_code="403", service_name="api-gateway", path="/payments"}',
    # KB5: OPA structured deny log từ opa-server app (compact, có subject/roles/reason rõ ràng)
    # Dùng stream này thay vì {job="opa-decisions", opa_result="false", request_path="/payments"}
    # vì stream kia cũng bắt KB1 brute force (cùng path /payments, cùng OPA deny)
    "access_denied":     '{app="opa-server", job="opa-decisions"} |= "rbac_deny"',
    # KB3: OPA decision log cho /payments/internal/execute — chỉ lateral movement mới dùng path này
    "lateral_movement":  '{job="opa-decisions", opa_result="false", request_path="/payments/internal/execute"}',
    # KB2: payment-service AUDIT log event payment_blocked_fraud
    "fraud_gate_bypass": '{namespace="financial", app="payment-service"} | json | event="payment_blocked_fraud"',
}

_LOKI_SEARCH_TERMS: dict[str, str] = {
    "credential_stuffing":  "401|403|login.fail|too.many|credential.stuff|multiple.fail",
    "jwt_replay":           "jwt.replay|token.reuse|duplicate.jti|jti.already.used|token_reuse",
    "cryptomining":         "xmrig|stratum|cryptomin|cpu.spike|mining",
    "port_scan":            "port.scan|nmap|syn.scan|masscan|port_scan",
    "exploit_probe":        "sqlmap|union.select|cmd.injection|payload|exploit",
    "account_manipulation": "account.manip|role.change|privilege.grant|account_manipulation|T1098",
    "data_staging":         "bulk.export|data.staging|large.query|bulk_export|staging",
    "container_escape":     "container.escape|cap_sys_admin|cap_net_admin|seccomp|privileged|escape",
    "impair_defenses":      "impair.defense|disable.log|opa.admin|prometheus.scrape|loki.push|impair",
}

_EVIDENCE_NAMESPACE_WIDE = {"lateral_movement", "fraud_gate_bypass"}


def _format_evidence_line(attack_type: str, raw_line: str, stream_labels: dict) -> str:
    """Parse raw Loki log JSON and extract key fields proving the attack scenario."""
    try:
        d = json.loads(raw_line)
    except Exception:
        tag = stream_labels.get("app") or stream_labels.get("job") or "?"
        return f"[{tag}] {raw_line[:300]}"

    ts = d.get("timestamp") or d.get("ts") or d.get("time") or ""
    if ts:
        ts = ts[:19].replace("T", " ")

    if attack_type == "brute_force":
        # Envoy access log thật từ api-gateway sidecar
        src  = d.get("source_ip", "?")
        code = d.get("response_code", "?")
        path = d.get("path", "?")
        meth = d.get("method", "POST")
        svid = d.get("svid") or "null"
        rt   = d.get("response_time", "?")
        return f"[envoy-access] {ts} | {meth} {path} → HTTP {code} | src={src} | svid={svid} | response_time={rt}ms"

    if attack_type == "fraud_gate_bypass":
        # payment-service AUDIT log thật — event payment_blocked_fraud
        score   = d.get("fraud_score") or d.get("fraud", {}).get("score", "?")
        verdict = d.get("fraud", {}).get("verdict") or d.get("verdict", "?")
        gate    = d.get("fraud", {}).get("gate", "?")
        reasons = ", ".join(d.get("fraud", {}).get("reason") or [d.get("reason", "?")])
        trace   = (d.get("trace_id") or "")[:16]
        svc     = d.get("service", "payment-service")
        return f"[{svc}] {ts} | event={d.get('event','payment_blocked_fraud')} | level={d.get('level','AUDIT')} | fraud_score={score} | verdict={verdict} | gate={gate} | reason=[{reasons}] | trace_id={trace}"

    if attack_type == "lateral_movement":
        # OPA decision log thật — full input từ Envoy ext_authz gRPC call
        result   = "DENIED" if not d.get("result", True) else "ALLOWED"
        req_http = d.get("input", {}).get("attributes", {}).get("request", {}).get("http", {})
        path     = req_http.get("path", "?")
        method   = req_http.get("method", "?")
        headers  = req_http.get("headers", {})
        xfcc     = headers.get("x-forwarded-client-cert", "") or ""
        caller_ip = d.get("input", {}).get("attributes", {}).get("source", {}).get("address", {}).get("socketAddress", {}).get("address", "?")
        dec_id   = (d.get("decision_id") or "")[:16]
        if xfcc:
            m = re.search(r'URI=([^,;]+)', xfcc)
            svid_info = f"xfcc_uri={m.group(1)}" if m else f"xfcc={xfcc[:60]}"
        else:
            svid_info = f"xfcc=null"
        return f"[opa-decisions] {ts} | result={result} | {method} {path} | caller_ip={caller_ip} | {svid_info} | decision_id={dec_id}"

    if attack_type == "access_denied":
        # OPA structured deny log thật từ opa-server app
        # Format: {"result":"deny","source_ip":...,"path":...,"method":...,"reason":"rbac_deny_...","subject":...,"subject_roles":[...],"required_roles":[...]}
        result         = d.get("result", "?")
        subject        = d.get("subject", "?")
        subject_roles  = d.get("subject_roles", [])
        required_roles = d.get("required_roles", [])
        reason         = d.get("reason", "?")
        path           = d.get("path", "?")
        method         = d.get("method", "?")
        src_ip         = d.get("source_ip", "?")
        return f"[opa-server] {ts} | result={result} | {method} {path} | subject={subject} | subject_roles={subject_roles} | required_roles={required_roles} | reason={reason} | src={src_ip}"

    # Fallback generic format
    tag = stream_labels.get("app") or stream_labels.get("job") or stream_labels.get("service_name") or "?"
    return f"[{tag}] {raw_line[:300]}"


async def _fetch_loki_lines(
    attack_type: str,
    source_ip: str | None,
    workload: str | None,
    limit: int = 8,
) -> list[str]:
    """Fetch actual log lines from Loki matching the attack pattern. Returns list of strings."""
    end_ns = time.time_ns()
    start_ns = end_ns - 30 * 60 * 10**9  # last 30 minutes

    # Use exact query matching the Grafana alert rule when available
    if attack_type in _LOKI_EXACT_QUERIES:
        query = _LOKI_EXACT_QUERIES[attack_type]
        if source_ip and source_ip not in query:
            query = f'{query} |~ "{source_ip}"'
    elif attack_type in _EVIDENCE_NAMESPACE_WIDE:
        term = _LOKI_SEARCH_TERMS.get(attack_type, "denied|error|attack|fail")
        if source_ip:
            term = f"{source_ip}|{term}"
        query = f'{{namespace="financial"}} |~ "(?i)({term})"'
    else:
        parts = []
        if workload:
            parts.append(f'app="{workload}"')
        base = "{" + ", ".join(parts) + "}" if parts else '{namespace="financial"}'
        term = _LOKI_SEARCH_TERMS.get(attack_type, "denied|error|attack|fail")
        if source_ip:
            term = f"{source_ip}|{term}"
        query = f'{base} |~ "(?i)({term})"'

    try:
        async with httpx.AsyncClient(timeout=10) as h:
            resp = await h.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={"query": query, "start": start_ns, "end": end_ns, "limit": limit},
            )
            resp.raise_for_status()
            data = resp.json()
            lines: list[str] = []
            for stream in data.get("data", {}).get("result", []):
                labels = stream.get("stream", {})
                for _, raw_line in stream.get("values", []):
                    lines.append(_format_evidence_line(attack_type, raw_line, labels))
                    if len(lines) >= limit:
                        return lines
            return lines
    except Exception:
        return []


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
            contain_action = _scale_deployment(context, workload, "workload isolation — suspected compromise")
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

    if case.playbook in {"isolate_workload", "restrict_egress", "quarantine_workload"}:
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


# ── Heuristic analysis functions ────────────────────────────────────────────

def _extract_source_ip_from_line(line: str) -> str | None:
    # Handles JSON ("source_ip":"10.x"), k=v (source_ip=10.x), label (source_ip: 10.x)
    m = re.search(r'source_ip[=:"\s]+(\d{1,3}(?:\.\d{1,3}){3})', line)
    if m:
        return m.group(1)
    # Fallback: public non-RFC1918 IP in line
    m = re.search(r"\b((?!10\.|127\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d{1,3}(?:\.\d{1,3}){3})\b", line)
    return m.group(1) if m else None


def _source_ip_from_evidence(lines: list[str]) -> str | None:
    """Extract first source_ip found across Loki log evidence lines."""
    for line in lines:
        ip = _extract_source_ip_from_line(line)
        if ip:
            return ip
    return None


async def _heuristic_analyze() -> None:
    """Poll Loki, apply heuristic rules, create SOAR cases for detected attacks."""
    end_ns = time.time_ns()
    start_ns = end_ns - _HEURISTIC_WINDOW_S * 10**9
    try:
        async with httpx.AsyncClient(timeout=15) as h:
            resp = await h.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={"query": '{namespace="financial"}', "start": start_ns, "end": end_ns, "limit": 1000},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(json.dumps({"event_type": "heuristic_loki_query_failed", "error": str(exc)}))
        return

    log_items: list[tuple[str, str]] = []
    for stream in data.get("data", {}).get("result", []):
        app = stream.get("stream", {}).get("app", "unknown")
        for _, line in stream.get("values", []):
            log_items.append((app, line))

    if not log_items:
        return

    now = time.time()
    detected: dict[str, dict] = {}
    for rule_pat, attack_type, severity, confidence in _HEURISTIC_RULES:
        for app, line in log_items:
            if rule_pat.search(line):
                if attack_type not in detected:
                    detected[attack_type] = {"count": 0, "evidence": [], "source_ip": None,
                                              "severity": severity, "confidence": confidence}
                info = detected[attack_type]
                info["count"] += 1
                if len(info["evidence"]) < 5:
                    info["evidence"].append(f"[{app}] {line[:500]}")
                if not info["source_ip"]:
                    info["source_ip"] = _extract_source_ip_from_line(line)

    for attack_type, info in detected.items():
        if info["count"] < _HEURISTIC_MIN_COUNT.get(attack_type, 1):
            continue
        if now - _heuristic_last_seen.get(attack_type, 0) < _HEURISTIC_DEDUP_S:
            continue
        # Cross-check: skip if Grafana webhook already created a case for this attack_type recently
        _wh_entry = _webhook_recent.get(attack_type)
        if _wh_entry and now - _wh_entry[2] < _WEBHOOK_DEDUP_S:
            continue
        _heuristic_last_seen[attack_type] = now

        alert = SecurityAlert(
            analyzer="heuristic",
            provider="loki-poller",
            model="rule-based",
            source="heuristic-log-poller",
            verdict="malicious",
            severity=info["severity"],  # type: ignore[arg-type]
            confidence=info["confidence"],
            attack_type=attack_type,
            summary=f"Heuristic detection: {attack_type} ({info['count']} log entries matched in {_HEURISTIC_WINDOW_S}s window)",
            evidence=info["evidence"],
            recommended_action=f"respond to {attack_type}",
            recommended_playbook=PLAYBOOK_BY_ATTACK.get(attack_type),
            source_ip=info["source_ip"],
            log_count=info["count"],
            ts=_now_iso(),
        )
        logger.warning(json.dumps({
            "event_type": "heuristic_detection",
            "attack_type": attack_type,
            "severity": info["severity"],
            "count": info["count"],
            "source_ip": info["source_ip"],
        }))
        try:
            await _process_heuristic_alert(alert)
        except Exception as exc:
            logger.error(json.dumps({"event_type": "heuristic_alert_failed", "attack_type": attack_type, "error": str(exc)}))


async def _process_heuristic_alert(alert: SecurityAlert) -> CaseRecord:
    """Xử lý alert từ heuristic poller — tạo case và gửi email HITL nếu cần."""
    alert_hash = _hash_alert(alert)
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
        reason = reason if playbook != "monitor_only" else f"no automated playbook for {alert.attack_type}"
    elif _needs_hitl(alert):
        status = "pending_approval"
        action = f"awaiting admin approval for playbook {playbook}"
        reason = f"severity={alert.severity} >= hitl_threshold={SOAR_HITL_SEVERITY}"
    else:
        try:
            action, steps = await _run_steps(
                playbook=playbook, context=target.get("context"), workload=target.get("workload"),
                source_ip=alert.source_ip, username=alert.username, attack_type=attack,
                dry_run=SOAR_DRY_RUN,
            )
            status = "dry_run" if SOAR_DRY_RUN else "executed"
        except Exception as exc:
            status = "failed"
            error = str(exc)
            action = "execution failed"

    case = CaseRecord(
        case_id=case_id, status=status, alert_hash=alert_hash, attack_type=attack,
        severity=alert.severity, confidence=alert.confidence, playbook=playbook,
        target_context=target.get("context"), target_workload=target.get("workload"),
        source_ip=alert.source_ip, username=alert.username, action=action, reason=reason,
        error=error, dry_run=SOAR_DRY_RUN, steps=steps, ts=_now_iso(),
    )
    result = await record_case(case)
    # Register in _webhook_recent so Grafana real-alert won't create a duplicate case
    _webhook_recent[attack] = (case_id, SEVERITY_RANK.get(alert.severity, 0), time.time())

    if status == "pending_approval":
        _HITL_QUEUE[case_id] = (case, playbook, target)
        evidence = list(alert.evidence)
        if len(evidence) < 3:
            loki_lines = await _fetch_loki_lines(attack, alert.source_ip, target.get("workload"))
            evidence = loki_lines + evidence

        # Enrich case.source_ip from Loki evidence if not in alert
        if not case.source_ip:
            enrich_ip = _source_ip_from_evidence(evidence)
            if enrich_ip:
                case = case.model_copy(update={"source_ip": enrich_ip})
                CASES[case_id] = case
                persist_case(case)
                _HITL_QUEUE[case_id] = (case, playbook, target)
                result = case

        sent = await _send_hitl_email(
            case=case,
            alert_name=ATTACK_DISPLAY_NAMES.get(attack, attack.replace("_", " ").title()),
            mitre=MITRE_BY_ATTACK.get(attack, "—"),
            log_lines=evidence,
        )
        if sent:
            case = case.model_copy(update={"email_sent": True})
            CASES[case_id] = case
            persist_case(case)
            _HITL_QUEUE[case_id] = (case, playbook, target)
            result = case
    return result


async def _heuristic_poll() -> None:
    """Background task: poll Loki mỗi HEURISTIC_POLL_INTERVAL giây."""
    await asyncio.sleep(30)
    while True:
        try:
            await _heuristic_analyze()
        except Exception as exc:
            logger.error(json.dumps({"event_type": "heuristic_poll_error", "error": str(exc)}))
        await asyncio.sleep(_HEURISTIC_POLL_INTERVAL)


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
    # heuristic poller disabled — Grafana real alert là trigger duy nhất
    logger.info(json.dumps({"event_type": "heuristic_poller_disabled", "reason": "grafana-only mode"}))

    # Restore HITL queue for ALL pending cases (approve/deny links always work after restart)
    # Re-send email only for recent cases (≤2h) that never got a notification
    _now_dt = datetime.now(timezone.utc)
    pending = [c for c in CASES.values() if c.status == "pending_approval"]
    restored = 0
    resent = 0
    for case in pending:
        playbook = case.playbook
        target = {
            "context": case.target_context,
            "workload": case.target_workload,
            "namespace": case.target_namespace,
        }
        _HITL_QUEUE[case.case_id] = (case, playbook, target)
        restored += 1
        if not case.email_sent:
            try:
                case_dt = datetime.fromisoformat(case.ts)
                age_h = (_now_dt - case_dt).total_seconds() / 3600
            except Exception:
                age_h = 99
            if age_h <= 2:
                alert_name = ATTACK_DISPLAY_NAMES.get(case.attack_type, case.attack_type.replace("_", " ").title())
                mitre = MITRE_BY_ATTACK.get(case.attack_type, "—")
                loki_lines = await _fetch_loki_lines(case.attack_type, case.source_ip, case.target_workload)
                sent = await _send_hitl_email(case=case, alert_name=alert_name, mitre=mitre, log_lines=loki_lines)
                if sent:
                    updated = case.model_copy(update={"email_sent": True})
                    CASES[case.case_id] = updated
                    persist_case(updated)
                    _HITL_QUEUE[case.case_id] = (updated, playbook, target)
                    resent += 1
    logger.info(json.dumps({"event_type": "soar_startup_restore", "pending_cases": len(pending), "hitl_queue_restored": restored, "emails_resent": resent}))


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
    elif _needs_hitl(alert):
        status = "pending_approval"
        action = f"awaiting admin approval for playbook {playbook}"
        reason = f"severity={alert.severity} >= hitl_threshold={SOAR_HITL_SEVERITY}"
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
    if status == "pending_approval":
        _HITL_QUEUE[case_id] = (case, playbook, target)
        evidence = list(alert.evidence)
        if len(evidence) < 3:
            loki_lines = await _fetch_loki_lines(attack, alert.source_ip, target.get("workload"))
            evidence = loki_lines + evidence

        # Enrich case.source_ip from evidence if not in alert
        if not case.source_ip:
            enrich_ip = _source_ip_from_evidence(evidence)
            if enrich_ip:
                case = case.model_copy(update={"source_ip": enrich_ip})
                CASES[case_id] = case
                persist_case(case)
                _HITL_QUEUE[case_id] = (case, playbook, target)
                result = case

        sent = await _send_hitl_email(
            case=case,
            alert_name=ATTACK_DISPLAY_NAMES.get(attack, attack.replace("_", " ").title()),
            mitre=MITRE_BY_ATTACK.get(attack, "—"),
            log_lines=evidence,
        )
        if sent:
            case = case.model_copy(update={"email_sent": True})
            CASES[case_id] = case
            persist_case(case)
            _HITL_QUEUE[case_id] = (case, playbook, target)
            result = case
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

    # Skip health/ops monitoring alerts — they fire on SOAR's own logs and create feedback loops
    if labels.get("category", "") in ("health", "ops"):
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

        # Dedup: mỗi attack_type chỉ tạo 1 case trong 5 phút
        # Ngăn Grafana real-alert tạo case trùng với case đã được script tạo trước
        _now_ts = time.time()
        _recent = _webhook_recent.get(attack)
        if _recent:
            _old_case_id, _old_sev_rank, _old_ts = _recent
            if _now_ts - _old_ts < _WEBHOOK_DEDUP_S:
                _new_sev_rank = SEVERITY_RANK.get(alert.severity, 0)
                if _new_sev_rank <= _old_sev_rank:
                    # Duplicate với severity thấp hơn hoặc bằng → bỏ qua
                    logger.info(json.dumps({
                        "event_type": "grafana_webhook_deduped",
                        "attack_type": attack,
                        "existing_case": _old_case_id,
                        "new_severity": alert.severity,
                        "reason": "same attack_type within 5 min dedup window",
                    }))
                    results.append({
                        "case_id": _old_case_id,
                        "attack_type": attack,
                        "playbook": playbook,
                        "status": "deduped",
                        "deduped_by": _old_case_id,
                    })
                    continue
        # Cập nhật registry với case mới (severity cao hơn hoặc mới)
        _webhook_recent[attack] = (case_id, SEVERITY_RANK.get(alert.severity, 0), _now_ts)

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
            lbs = alert_data.get("labels", {})
            ann = alert_data.get("annotations", {})
            loki_lines = await _fetch_loki_lines(attack, alert.source_ip, target.get("workload"))
            desc_lines = [l for l in ann.get("description", "").splitlines() if l.strip()]
            evidence = loki_lines if loki_lines else desc_lines
            if not evidence:
                evidence = [f"Grafana alert fired: {lbs.get('alertname', attack)} — no Loki evidence in last 30 min"]

            # Enrich case.source_ip from Loki evidence if not provided in alert labels
            if not case.source_ip:
                enrich_ip = _source_ip_from_evidence(evidence)
                if enrich_ip:
                    case = case.model_copy(update={"source_ip": enrich_ip})
                    CASES[case_id] = case
                    persist_case(case)
                    _HITL_QUEUE[case_id] = (case, playbook, target)

            sent = await _send_hitl_email(
                case       = case,
                alert_name = _clean_alert_name(lbs.get("alertname", attack), attack),
                mitre      = lbs.get("mitre", MITRE_BY_ATTACK.get(attack, "—")),
                log_lines  = evidence,
            )
            if sent:
                case = case.model_copy(update={"email_sent": True})
                CASES[case_id] = case
                persist_case(case)
                _HITL_QUEUE[case_id] = (case, playbook, target)

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


@app.post("/cases/{case_id}/approve-admin", response_model=CaseRecord)
async def hitl_approve_admin(case_id: str, authorization: str | None = Header(default=None)) -> CaseRecord:
    """Web Portal admin approve — xác thực bằng SOAR API token (không cần HMAC email token)."""
    require_soar_token(authorization)

    queued = _HITL_QUEUE.pop(case_id, None)
    if queued is None:
        stored = CASES.get(case_id)
        if stored and stored.status != "pending_approval":
            return stored
        raise HTTPException(status_code=404, detail="case không tồn tại hoặc đã xử lý")

    draft, playbook, target = queued
    action = "no action"
    error: str | None = None
    steps: list[PlaybookStep] = []
    try:
        action, steps = await _run_steps(
            playbook=playbook, context=target.get("context"), workload=target.get("workload"),
            source_ip=draft.source_ip, username=draft.username,
            attack_type=draft.attack_type, dry_run=SOAR_DRY_RUN,
        )
        final_status: Any = "dry_run" if SOAR_DRY_RUN else "executed"
    except Exception as exc:
        final_status = "failed"
        error = str(exc)
        action = "execution failed"

    approved = draft.model_copy(update={
        "status": final_status, "action": action,
        "reason": "admin approved via web portal", "error": error, "steps": steps, "ts": _now_iso(),
    })
    result = await record_case(approved)
    logger.warning(json.dumps({"event_type": "hitl_approved_portal", "case_id": case_id, "status": final_status}))
    return result


@app.post("/cases/{case_id}/deny-admin", response_model=CaseRecord)
async def hitl_deny_admin(case_id: str, authorization: str | None = Header(default=None)) -> CaseRecord:
    """Web Portal admin deny — xác thực bằng SOAR API token (không cần HMAC email token)."""
    require_soar_token(authorization)

    queued = _HITL_QUEUE.pop(case_id, None)
    if queued is None:
        stored = CASES.get(case_id)
        if stored and stored.status != "pending_approval":
            return stored
        raise HTTPException(status_code=404, detail="case không tồn tại hoặc đã xử lý")

    draft, _pb, _tgt = queued
    denied = draft.model_copy(update={
        "status": "skipped", "action": "admin denied via web portal",
        "reason": "admin rejected via web portal", "ts": _now_iso(),
    })
    result = await record_case(denied)
    logger.warning(json.dumps({"event_type": "hitl_denied_portal", "case_id": case_id}))
    return result


# ── Execute chosen playbook (admin tự chọn hành động) ───────────────────────

class PlaybookExecuteRequest(BaseModel):
    playbook: str


async def _execute_chosen_playbook(case_id: str, chosen_playbook: str, actor: str) -> CaseRecord:
    """Thực thi playbook do admin chọn cho case pending_approval."""
    if chosen_playbook not in ALLOWED_PLAYBOOKS:
        raise HTTPException(status_code=400, detail=f"playbook không được phép: {chosen_playbook}")

    case = CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case không tồn tại")
    if case.status != "pending_approval":
        return case  # đã xử lý — trả về kết quả hiện tại

    _HITL_QUEUE.pop(case_id, None)

    if chosen_playbook == "monitor_only":
        result = case.model_copy(update={
            "status": "skipped", "playbook": "monitor_only",
            "action": "admin chọn chỉ theo dõi — không thực thi hành động nào",
            "reason": f"admin decision via {actor}", "error": None, "ts": _now_iso(),
        })
    else:
        error: str | None = None
        steps: list[PlaybookStep] = []
        try:
            action, steps = await _run_steps(
                playbook=chosen_playbook,
                context=case.target_context,
                workload=case.target_workload,
                source_ip=case.source_ip,
                username=case.username,
                attack_type=case.attack_type,
                dry_run=SOAR_DRY_RUN,
            )
            final_status: Any = "dry_run" if SOAR_DRY_RUN else "executed"
        except Exception as exc:
            action = "execution failed"
            error = str(exc)
            final_status = "failed"
        result = case.model_copy(update={
            "status": final_status, "playbook": chosen_playbook, "action": action,
            "reason": f"admin chọn playbook {chosen_playbook} via {actor}",
            "error": error, "steps": steps, "ts": _now_iso(),
        })

    await record_case(result)
    logger.warning(json.dumps({
        "event_type": "playbook_executed_by_admin",
        "case_id": case_id, "playbook": chosen_playbook,
        "status": result.status, "actor": actor,
    }))
    return result


@app.get("/cases/{case_id}/choose-action")
async def choose_action_email(case_id: str, playbook: str = "", token: str = "") -> Any:
    """Endpoint cho email link: admin click → chọn playbook cụ thể → thực thi → HTML xác nhận."""
    from fastapi.responses import HTMLResponse
    if not _verify_hitl_token(case_id, token):
        raise HTTPException(status_code=403, detail="token không hợp lệ hoặc đã hết hạn")
    try:
        result = await _execute_chosen_playbook(case_id, playbook, actor="email-link")
    except HTTPException as exc:
        return HTMLResponse(_hitl_result_html(case_id, "failed", already_done=(exc.status_code == 409)))
    label = PLAYBOOK_LABELS.get(playbook, playbook)
    return HTMLResponse(_hitl_action_result_html(case_id, result.status, label))


@app.post("/cases/{case_id}/execute-playbook", response_model=CaseRecord)
async def execute_playbook_portal(
    case_id: str,
    body: PlaybookExecuteRequest,
    authorization: str | None = Header(default=None),
) -> CaseRecord:
    """Web Portal: admin chọn và thực thi một playbook cụ thể cho case pending_approval."""
    require_soar_token(authorization)
    return await _execute_chosen_playbook(case_id, body.playbook, actor="web-portal")


def _hitl_action_result_html(case_id: str, status: str, playbook_label: str) -> str:
    if status in {"executed", "dry_run"}:
        icon, msg, color = "✅", f"Đã thực thi: <strong>{playbook_label}</strong> (status: {status})", "#4CAF50"
    elif status == "skipped":
        icon, msg, color = "📊", "Đã chọn theo dõi — không có hành động tự động", "#757575"
    else:
        icon, msg, color = "⚠️", f"Lỗi khi thực thi {playbook_label} (status: {status})", "#F44336"
    return f"""<!DOCTYPE html><html><body style="font-family:Arial;text-align:center;padding:60px">
<div style="max-width:480px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;padding:40px">
  <div style="font-size:48px">{icon}</div>
  <h2 style="color:{color}">{msg}</h2>
  <p style="color:#777;font-size:13px">Case ID: <code>{case_id}</code></p>
  <a href="{SOAR_PUBLIC_URL}/cases" style="color:#1976D2;font-size:13px">Xem tất cả cases →</a>
</div></body></html>"""


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
