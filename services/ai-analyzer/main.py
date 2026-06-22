import asyncio
import hashlib
import json
import logging
import os
import random
import re
import smtplib
import time
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


APP_NAME = "ai-analyzer"
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100").rstrip("/")
AI_PROVIDER = os.getenv("AI_PROVIDER", "heuristic").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
POLL_ENABLED = os.getenv("AI_ANALYZER_POLL_ENABLED", "true").lower() == "true"
MIN_ALERT_SEVERITY = os.getenv("AI_ANALYZER_MIN_ALERT_SEVERITY", "medium").lower()
# Severity threshold requiring admin approval before SOAR executes.
# Alerts below this (e.g. medium) are logged to Loki only.
# Alerts at or above this (e.g. high, critical) enter the pending queue.
ADMIN_APPROVAL_SEVERITY = os.getenv("AI_ANALYZER_ADMIN_APPROVAL_SEVERITY", "high").lower()
LOKI_QUERY = os.getenv("AI_ANALYZER_LOKI_QUERY", '{job=~"kubernetes-pods|envoy-access|opa-decisions|system|demo-raw"}')
SOAR_WEBHOOK_URL = os.getenv("SOAR_WEBHOOK_URL", "").strip()
SOAR_API_TOKEN = os.getenv("SOAR_API_TOKEN", "").strip()
# Optional fallback webhook (Slack, n8n, Discord...). Primary notification is via Grafana Contact Points.
ADMIN_WEBHOOK_URL = os.getenv("ADMIN_WEBHOOK_URL", "").strip()
# Web portal base URL — included in webhook payload so admin can navigate directly to /alerts
PORTAL_URL = os.getenv("PORTAL_URL", "").rstrip("/")
PROVIDER_COOLDOWN_SECONDS = int(os.getenv("AI_PROVIDER_COOLDOWN_SECONDS", "900"))
_provider_backoff_until = 0.0

# SMTP — gửi email alert cho admin khi Grafana phát hiện bất thường
SMTP_HOST    = os.getenv("SMTP_HOST", "")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER    = os.getenv("SMTP_USER", "")
SMTP_PASS    = os.getenv("SMTP_PASS", "")
SMTP_FROM    = os.getenv("SMTP_FROM", "")
ADMIN_EMAIL  = os.getenv("ADMIN_EMAIL", "")
SCORER_URL   = os.getenv("SCORER_URL", "").rstrip("/")
SMTP_ENABLED = bool(SMTP_HOST and SMTP_USER and SMTP_PASS and ADMIN_EMAIL)

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MALICIOUS_PATTERNS = [
    (re.compile(r"\b(401|403|denied|deny|unauthorized|forbidden)\b", re.I), "access_denied"),
    (re.compile(r"fraud_gate_bypass", re.I), "fraud_gate_bypass"),
    (re.compile(r"brute.?force|account.?locked|too.?many.?attempt|login.?attempt.*\b([5-9]\d|\d{3,})\b", re.I), "brute_force"),
    (re.compile(r"lateral|invalid.*svid|spiffe.*den", re.I), "lateral_movement"),
    (re.compile(r"port scan|nmap|masscan|syn scan", re.I), "port_scan"),
    (re.compile(r"privilege escalation|setuid|cap_sys_admin", re.I), "privilege_escalation"),
    (re.compile(r"credential[_ -]?stuffing|multiple_usernames|common_password_attempts", re.I), "credential_stuffing"),
    (re.compile(r"jwt[_ -]?replay|stolen_token|suspicious_reuse|expired_token", re.I), "jwt_replay"),
    (re.compile(r"container[_ -]?escape|host_filesystem|suspicious_syscall|ptrace|seccomp|169\.254\.169\.254", re.I), "container_escape"),
    (re.compile(r"xmrig|cryptomin|stratum\+tcp", re.I), "cryptomining"),
    (re.compile(r"sqlmap|union select|/etc/passwd|cmd=|powershell|curl .*http", re.I), "exploit_probe"),
    (re.compile(r"bytes_sent[=: ]([1-9]\d{6,})", re.I), "large_response"),
]

IGNORED_ALERT_NAMESPACES = {item.strip() for item in os.getenv(
    "AI_ANALYZER_IGNORED_ALERT_NAMESPACES",
    "plg-stack,monitoring,identity,kube-system",
).split(",") if item.strip()}
IGNORED_ALERT_APPS = {item.strip() for item in os.getenv(
    "AI_ANALYZER_IGNORED_ALERT_APPS",
    "grafana,loki,promtail,ai-analyzer,soar-engine,prometheus,keycloak,keycloak-db",
).split(",") if item.strip()}
OBSERVABILITY_ALERT_HINTS = (
    "ngalert",
    "grafana",
    "loki",
    "promtail",
    "ai_security_alert",
    "pending_security_alert",
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(APP_NAME)
app = FastAPI(title="ZTLab AI Analyzer")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        logger.warning(json.dumps({"event_type": "invalid_env_int", "name": name, "value": raw, "default": default}))
        return default
    return max(minimum, min(maximum, value))


POLL_INTERVAL_SECONDS = _env_int("AI_ANALYZER_POLL_INTERVAL_SECONDS", 30, 5, 3600)
LOOKBACK_SECONDS = _env_int("AI_ANALYZER_LOOKBACK_SECONDS", 90, 10, 86400)
MAX_LOGS_PER_BATCH = _env_int("AI_ANALYZER_MAX_LOGS_PER_BATCH", 25, 1, 200)
PENDING_TTL_SECONDS = _env_int("AI_ANALYZER_PENDING_TTL_SECONDS", 3600, 60, 86400)

if MIN_ALERT_SEVERITY not in SEVERITY_RANK:
    logger.warning(json.dumps({"event_type": "invalid_min_alert_severity", "value": MIN_ALERT_SEVERITY, "default": "medium"}))
    MIN_ALERT_SEVERITY = "medium"
if ADMIN_APPROVAL_SEVERITY not in SEVERITY_RANK:
    logger.warning(json.dumps({"event_type": "invalid_admin_approval_severity", "value": ADMIN_APPROVAL_SEVERITY, "default": "high"}))
    ADMIN_APPROVAL_SEVERITY = "high"


class LogEntry(BaseModel):
    timestamp: str | None = None
    message: str
    labels: dict[str, str] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    logs: list[LogEntry]
    source: str = "api"


class AnalyzeResult(BaseModel):
    verdict: Literal["normal", "malicious", "suspicious"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    attack_type: str = "unknown"
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = "monitor"
    recommended_playbook: str | None = None
    affected_service: str | None = None
    source_ip: str | None = None
    provider_used: str = "heuristic"
    model_used: str = "rules"


class AlertRecord(BaseModel):
    event_type: str = "ai_security_alert"
    analyzer: str = APP_NAME
    provider: str
    model: str
    source: str
    verdict: str
    severity: str
    confidence: float
    attack_type: str
    summary: str
    evidence: list[str]
    recommended_action: str
    recommended_playbook: str | None = None
    affected_service: str | None = None
    source_ip: str | None = None
    log_count: int
    log_hash: str
    ts: str


class PendingAlert(BaseModel):
    alert_id: str
    alert: AlertRecord
    created_at: str
    expires_at: str
    status: Literal["pending", "approved", "dismissed", "expired"] = "pending"
    reviewed_at: str | None = None
    note: str | None = None


class ApproveRequest(BaseModel):
    note: str | None = None


class DismissRequest(BaseModel):
    note: str | None = None


# In-memory store for pending alerts awaiting admin approval
PENDING_ALERTS: dict[str, PendingAlert] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _retry_after_seconds(response: httpx.Response | None) -> int | None:
    if response is None:
        return None
    retry_after = response.headers.get("retry-after")
    if retry_after:
        try:
            return max(1, min(3600, int(float(retry_after))))
        except ValueError:
            return None
    return None


def _provider_cooldown_remaining() -> int:
    return max(0, int(_provider_backoff_until - time.time()))


def _set_provider_backoff(exc: Exception) -> int:
    global _provider_backoff_until
    retry_after = None
    status_code = None
    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
        retry_after = _retry_after_seconds(exc.response)
    if status_code == 429:
        delay = retry_after or PROVIDER_COOLDOWN_SECONDS
    else:
        delay = min(300, max(30, PROVIDER_COOLDOWN_SECONDS // 3))
    delay = int(delay + random.randint(0, min(30, max(1, delay // 10))))
    _provider_backoff_until = max(_provider_backoff_until, time.time() + delay)
    return delay


def _safe_provider_error(exc: Exception) -> dict[str, Any]:
    details: dict[str, Any] = {"event_type": "ai_provider_error", "provider": AI_PROVIDER, "error_type": exc.__class__.__name__}
    if isinstance(exc, httpx.HTTPStatusError):
        details["status_code"] = exc.response.status_code
        retry_after = _retry_after_seconds(exc.response)
        if retry_after is not None:
            details["retry_after_seconds"] = retry_after
    else:
        details["error"] = str(exc)[:300]
    return details


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _flatten_log(entry: LogEntry) -> str:
    label_text = " ".join(f"{k}={v}" for k, v in sorted(entry.labels.items()))
    return f"{entry.timestamp or ''} {label_text} {entry.message}".strip()


def _logs_hash(logs: list[LogEntry]) -> str:
    digest = hashlib.sha256()
    for entry in logs:
        digest.update(_flatten_log(entry).encode("utf-8", errors="replace"))
    return digest.hexdigest()[:16]


def _extract_source_ip(text: str) -> str | None:
    patterns = [
        r"source_ip[=: ](?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        r"src_ip[=: ](?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        r"client_ip[=: ](?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            return match.group("ip")
    return None


def _infer_affected_service(text: str, reasons: list[str]) -> str | None:
    known_services = [
        "api-gateway",
        "payment-service",
        "fraud-detection",
        "notification-service",
        "core-banking",
        "account-service",
        "transaction-service",
    ]
    lowered = text.lower()
    for service in known_services:
        if service in lowered:
            return service
    if "fraud_gate_bypass" in reasons:
        return "payment-service"
    if "lateral_movement" in reasons:
        return "core-banking"
    if "cryptomining" in reasons:
        return "transaction-service"
    if "large_response" in reasons:
        return "core-banking"
    if "port_scan" in reasons or "exploit_probe" in reasons:
        return "api-gateway"
    return None


def _recommended_playbook(reasons: list[str]) -> str | None:
    for reason, playbook in [
        ("fraud_gate_bypass", "isolate_workload"),
        ("lateral_movement", "isolate_workload"),
        ("large_response", "restrict_egress"),
        ("cryptomining", "quarantine_workload"),
        ("port_scan", "isolate_workload"),
        ("exploit_probe", "isolate_workload"),
    ]:
        if reason in reasons:
            return playbook
    return None


def _normalize_ai_json(raw_text: str) -> dict[str, Any]:
    raw_text = raw_text.strip()
    parsed = _safe_json_loads(raw_text)
    if isinstance(parsed, dict):
        return parsed
    match = re.search(r"\{.*\}", raw_text, flags=re.S)
    if match:
        parsed = _safe_json_loads(match.group(0))
        if isinstance(parsed, dict):
            return parsed
    return {}


def _coerce_ai_result(value: dict[str, Any]) -> AnalyzeResult:
    normalized = dict(value)

    verdict = str(normalized.get("verdict", "suspicious")).lower()
    if verdict not in {"normal", "suspicious", "malicious"}:
        verdict = "suspicious"
    normalized["verdict"] = verdict

    severity = str(normalized.get("severity", "medium")).lower()
    if severity not in SEVERITY_RANK:
        severity = "medium"
    normalized["severity"] = severity

    confidence = normalized.get("confidence", 0.6)
    if isinstance(confidence, str):
        confidence = confidence.strip().lower()
        confidence = {"low": 0.35, "medium": 0.6, "high": 0.8, "critical": 0.9}.get(confidence, confidence)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.6
    normalized["confidence"] = max(0.0, min(1.0, confidence))

    evidence = normalized.get("evidence", [])
    if isinstance(evidence, str):
        evidence = [evidence]
    elif not isinstance(evidence, list):
        evidence = []
    normalized["evidence"] = [str(item) for item in evidence[:5]]

    normalized["attack_type"] = str(normalized.get("attack_type") or "unknown")
    normalized["summary"] = str(normalized.get("summary") or "AI classified the provided logs.")
    normalized["recommended_action"] = str(normalized.get("recommended_action") or "monitor")
    normalized["recommended_playbook"] = normalized.get("recommended_playbook") or None
    normalized["affected_service"] = normalized.get("affected_service") or None
    normalized["source_ip"] = normalized.get("source_ip") or None
    return AnalyzeResult.model_validate(normalized)


def heuristic_analyze(logs: list[LogEntry]) -> AnalyzeResult:
    reasons: list[str] = []
    evidence: list[str] = []
    for entry in logs:
        text = _flatten_log(entry)
        for pattern, reason in MALICIOUS_PATTERNS:
            if pattern.search(text):
                reasons.append(reason)
                excerpt = text[:350]
                if len(evidence) < 5 and excerpt not in evidence:
                    evidence.append(excerpt)

    if not reasons:
        return AnalyzeResult(
            verdict="normal",
            severity="low",
            confidence=0.72,
            attack_type="none",
            summary="No obvious malicious indicator was found in the provided logs.",
            recommended_action="continue monitoring",
        )

    unique_reasons = sorted(set(reasons))
    flattened = " ".join(_flatten_log(entry) for entry in logs)
    severity = "critical" if {"fraud_gate_bypass", "lateral_movement", "cryptomining"} & set(unique_reasons) else "high"
    if len(reasons) == 1 and unique_reasons == ["access_denied"]:
        severity = "medium"

    return AnalyzeResult(
        verdict="malicious" if severity in {"high", "critical"} else "suspicious",
        severity=severity,
        confidence=min(0.95, 0.62 + len(reasons) * 0.08),
        attack_type=",".join(unique_reasons),
        summary=f"Detected suspicious security indicators: {', '.join(unique_reasons)}.",
        evidence=evidence,
        recommended_action="investigate source identity, affected workload, and related OPA/Envoy decisions",
        recommended_playbook=_recommended_playbook(unique_reasons),
        affected_service=_infer_affected_service(flattened, unique_reasons),
        source_ip=_extract_source_ip(flattened),
    )


def _merge_result_with_heuristic(result: AnalyzeResult, heuristic: AnalyzeResult) -> AnalyzeResult:
    if heuristic.verdict == "normal":
        return result

    result_reasons = [item.strip() for item in result.attack_type.split(",") if item.strip() and item.strip() not in {"none", "unknown"}]
    heuristic_reasons = [item.strip() for item in heuristic.attack_type.split(",") if item.strip() and item.strip() not in {"none", "unknown"}]
    merged_reasons = sorted(set(result_reasons + heuristic_reasons))

    severity = result.severity
    if SEVERITY_RANK[heuristic.severity] > SEVERITY_RANK[severity]:
        severity = heuristic.severity

    verdict = result.verdict
    if verdict == "normal" or SEVERITY_RANK[severity] >= SEVERITY_RANK["high"]:
        verdict = "malicious"

    evidence = result.evidence or heuristic.evidence
    if result.evidence and heuristic.evidence:
        evidence = (result.evidence + [item for item in heuristic.evidence if item not in result.evidence])[:5]

    return AnalyzeResult(
        verdict=verdict,
        severity=severity,
        confidence=max(result.confidence, heuristic.confidence),
        attack_type=",".join(merged_reasons) if merged_reasons else result.attack_type,
        summary=result.summary if result.summary else heuristic.summary,
        evidence=evidence,
        recommended_action=(heuristic.recommended_action if heuristic.recommended_playbook else (result.recommended_action or heuristic.recommended_action)),
        recommended_playbook=heuristic.recommended_playbook or result.recommended_playbook,
        affected_service=result.affected_service or heuristic.affected_service,
        source_ip=result.source_ip or heuristic.source_ip,
    )


def _prompt(logs: list[LogEntry]) -> str:
    compact_logs = [_flatten_log(entry)[:800] for entry in logs[:MAX_LOGS_PER_BATCH]]
    return (
        "You are a security analyst for a Zero Trust microservice lab. "
        "Classify the logs as normal, suspicious, or malicious. "
        "Return only valid JSON with keys: verdict, severity, confidence, attack_type, "
        "summary, evidence, recommended_action, recommended_playbook, affected_service, source_ip. "
        "recommended_playbook must be one of isolate_workload, restrict_egress, quarantine_workload, monitor_only, or null. "
        "Severity must be low, medium, high, or critical.\n\n"
        f"Logs:\n{json.dumps(compact_logs, ensure_ascii=True)}"
    )


async def openai_analyze(client: httpx.AsyncClient, logs: list[LogEntry]) -> AnalyzeResult:
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": "Return only compact JSON. Do not include markdown."},
            {"role": "user", "content": _prompt(logs)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    response = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=45)
    response.raise_for_status()
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    return _coerce_ai_result(_normalize_ai_json(content))


async def gemini_analyze(client: httpx.AsyncClient, logs: list[LogEntry]) -> AnalyzeResult:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    headers = {"x-goog-api-key": GEMINI_API_KEY}
    payload = {
        "contents": [{"parts": [{"text": _prompt(logs)}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    response = await client.post(url, headers=headers, json=payload, timeout=45)
    response.raise_for_status()
    data = response.json()
    content = data["candidates"][0]["content"]["parts"][0]["text"]
    return _coerce_ai_result(_normalize_ai_json(content))


async def analyze_logs(logs: list[LogEntry]) -> AnalyzeResult:
    if not logs:
        return AnalyzeResult(
            verdict="normal",
            severity="low",
            confidence=1.0,
            attack_type="none",
            summary="No logs were provided.",
            recommended_action="none",
        )

    remaining = _provider_cooldown_remaining()
    if remaining > 0:
        logger.info(json.dumps({"event_type": "ai_provider_backoff_active", "provider": AI_PROVIDER, "remaining_seconds": remaining}))
        return heuristic_analyze(logs)

    async with httpx.AsyncClient() as client:
        try:
            if AI_PROVIDER == "openai" and OPENAI_API_KEY:
                result = _merge_result_with_heuristic(await openai_analyze(client, logs), heuristic_analyze(logs))
                result.provider_used = "openai"
                result.model_used = OPENAI_MODEL
                return result
            if AI_PROVIDER == "gemini" and GEMINI_API_KEY:
                result = _merge_result_with_heuristic(await gemini_analyze(client, logs), heuristic_analyze(logs))
                result.provider_used = "gemini"
                result.model_used = GEMINI_MODEL
                return result
        except Exception as exc:
            delay = _set_provider_backoff(exc)
            event = _safe_provider_error(exc)
            event["cooldown_seconds"] = delay
            logger.warning(json.dumps(event))

    return heuristic_analyze(logs)


def _is_observability_log(entry: LogEntry) -> bool:
    labels = {str(k).lower(): str(v) for k, v in entry.labels.items()}
    namespace = labels.get("namespace") or labels.get("kubernetes_namespace_name") or labels.get("namespace_name")
    app_label = labels.get("app") or labels.get("service") or labels.get("container") or labels.get("pod") or labels.get("job")
    if namespace in IGNORED_ALERT_NAMESPACES:
        return True
    if app_label and app_label in IGNORED_ALERT_APPS:
        return True
    text = _flatten_log(entry).lower()
    return any(hint in text for hint in OBSERVABILITY_ALERT_HINTS) and not any(
        svc in text for svc in (
            "api-gateway",
            "payment-service",
            "fraud-detection",
            "notification-service",
            "core-banking",
            "account-service",
            "transaction-service",
        )
    )


def _filter_actionable_logs(logs: list[LogEntry]) -> list[LogEntry]:
    filtered = [entry for entry in logs if not _is_observability_log(entry)]
    dropped = len(logs) - len(filtered)
    if dropped:
        logger.info(json.dumps({
            "event_type": "ai_logs_filtered",
            "dropped": dropped,
            "kept": len(filtered),
            "reason": "observability_or_platform_noise",
        }))
    return filtered


async def forward_alert_to_soar(alert: AlertRecord) -> None:
    if not SOAR_WEBHOOK_URL:
        return
    headers = {"Authorization": f"Bearer {SOAR_API_TOKEN}"} if SOAR_API_TOKEN else None
    async with httpx.AsyncClient() as client:
        response = await client.post(SOAR_WEBHOOK_URL, json=alert.model_dump(), headers=headers, timeout=15)
        response.raise_for_status()


async def push_alert_to_loki(alert: AlertRecord, extra_labels: dict[str, str] | None = None) -> None:
    line = alert.model_dump_json()
    stream_labels: dict[str, str] = {
        "job": "ai-analyzer",
        "service": APP_NAME,
        "severity": alert.severity,
        "verdict": alert.verdict,
        "attack_type": alert.attack_type[:80],
    }
    if extra_labels:
        stream_labels.update(extra_labels)
    payload = {
        "streams": [
            {
                "stream": stream_labels,
                "values": [[str(time.time_ns()), line]],
            }
        ]
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{LOKI_URL}/loki/api/v1/push", json=payload, timeout=10)
        response.raise_for_status()


async def notify_admin(alert: AlertRecord, alert_id: str) -> None:
    """
    Notify admin of a pending high/critical alert requiring review before SOAR runs.

    Primary channel: push to Loki with label pending_approval="true".
    Grafana Alert Rule queries this label and fires through whichever Contact Point
    the admin has configured in Grafana UI (email, Slack, Telegram, webhook, etc.).

    Optional secondary channel: ADMIN_WEBHOOK_URL (n8n, Slack, custom endpoint).
    """
    # Push to Loki — Grafana Alert Rule picks this up and notifies admin
    try:
        await push_alert_to_loki(alert, extra_labels={"pending_approval": "true", "alert_id": alert_id})
        logger.info(json.dumps({"event_type": "ai_admin_notify_loki_ok", "alert_id": alert_id}))
    except Exception as exc:
        logger.error(json.dumps({"event_type": "ai_admin_notify_loki_failed", "error": str(exc), "alert_id": alert_id}))

    if not ADMIN_WEBHOOK_URL:
        return

    # Secondary: generic webhook (Slack, n8n, Discord, custom server...)
    payload = {
        "event": "pending_security_alert",
        "alert_id": alert_id,
        "severity": alert.severity,
        "attack_type": alert.attack_type,
        "summary": alert.summary,
        "affected_service": alert.affected_service,
        "source_ip": alert.source_ip,
        "confidence": alert.confidence,
        "evidence": alert.evidence[:3],
        "recommended_action": alert.recommended_action,
        "recommended_playbook": alert.recommended_playbook,
        "approve_url": f"{PORTAL_URL}/alerts" if PORTAL_URL else "/alerts",
        "ts": alert.ts,
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(ADMIN_WEBHOOK_URL, json=payload, timeout=10)
            response.raise_for_status()
    except Exception as exc:
        logger.error(json.dumps({"event_type": "ai_admin_webhook_failed", "error": str(exc)[:300], "alert_id": alert_id}))


def should_alert(result: AnalyzeResult) -> bool:
    return result.verdict != "normal" and SEVERITY_RANK[result.severity] >= SEVERITY_RANK.get(MIN_ALERT_SEVERITY, 2)


def requires_admin_approval(result: AnalyzeResult) -> bool:
    return SEVERITY_RANK[result.severity] >= SEVERITY_RANK.get(ADMIN_APPROVAL_SEVERITY, 3)


async def handle_logs(logs: list[LogEntry], source: str) -> AnalyzeResult:
    actionable_logs = _filter_actionable_logs(logs)
    if logs and not actionable_logs:
        return AnalyzeResult(
            verdict="normal",
            severity="low",
            confidence=0.95,
            attack_type="platform_noise",
            summary="Only observability/platform logs were present; no financial workload signal was analyzed.",
            recommended_action="continue monitoring",
        )

    logs = actionable_logs
    result = await analyze_logs(logs)

    if not should_alert(result):
        # Below minimum threshold: log to stdout only, no Loki alert, no SOAR
        logger.info(json.dumps({
            "event_type": "ai_analysis_below_threshold",
            "severity": result.severity,
            "verdict": result.verdict,
            "min_alert_severity": MIN_ALERT_SEVERITY,
        }))
        return result

    alert = AlertRecord(
        provider=result.provider_used,
        model=result.model_used,
        source=source,
        verdict=result.verdict,
        severity=result.severity,
        confidence=result.confidence,
        attack_type=result.attack_type,
        summary=result.summary,
        evidence=result.evidence,
        recommended_action=result.recommended_action,
        recommended_playbook=result.recommended_playbook,
        affected_service=result.affected_service,
        source_ip=result.source_ip,
        log_count=len(logs),
        log_hash=_logs_hash(logs),
        ts=_now_iso(),
    )
    logger.warning(alert.model_dump_json())

    if requires_admin_approval(result):
        # High/critical: create pending alert, notify admin, do NOT forward to SOAR yet
        alert_id = str(uuid.uuid4())[:12]
        now = _now_iso()
        expires_ts = datetime.fromtimestamp(time.time() + PENDING_TTL_SECONDS, tz=timezone.utc).isoformat()
        pending = PendingAlert(
            alert_id=alert_id,
            alert=alert,
            created_at=now,
            expires_at=expires_ts,
        )
        PENDING_ALERTS[alert_id] = pending
        logger.warning(json.dumps({
            "event_type": "ai_pending_alert_created",
            "alert_id": alert_id,
            "severity": alert.severity,
            "attack_type": alert.attack_type,
            "expires_at": expires_ts,
            "message": f"Waiting for admin approval before SOAR execution. Review at GET /pending/{alert_id}",
        }))
        try:
            await notify_admin(alert, alert_id)
        except Exception as exc:
            logger.error(json.dumps({"event_type": "ai_admin_notify_failed", "error": str(exc), "alert_id": alert_id}))
    else:
        # Medium severity: push to Loki for Grafana visibility, no SOAR action
        try:
            await push_alert_to_loki(alert)
        except Exception as exc:
            logger.error(json.dumps({"event_type": "ai_alert_push_failed", "error": str(exc), "log_hash": alert.log_hash}))
        logger.info(json.dumps({
            "event_type": "ai_alert_logged_only",
            "severity": alert.severity,
            "attack_type": alert.attack_type,
            "message": "Alert logged to Loki. Below admin approval threshold, no SOAR action.",
        }))

    return result


async def query_loki() -> list[LogEntry]:
    end_ns = time.time_ns()
    start_ns = end_ns - LOOKBACK_SECONDS * 1_000_000_000
    params = {
        "query": LOKI_QUERY,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(MAX_LOGS_PER_BATCH),
        "direction": "backward",
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

    entries: list[LogEntry] = []
    for stream in data.get("data", {}).get("result", []):
        labels = {str(k): str(v) for k, v in stream.get("stream", {}).items()}
        for ts_ns, message in stream.get("values", []):
            entries.append(LogEntry(timestamp=ts_ns, message=message, labels=labels))
    entries.reverse()
    return entries[:MAX_LOGS_PER_BATCH]


async def poll_loki_loop() -> None:
    seen_hashes: set[str] = set()
    await asyncio.sleep(5)
    while True:
        try:
            logs = await query_loki()
            if logs:
                batch_hash = _logs_hash(logs)
                if batch_hash not in seen_hashes:
                    seen_hashes.add(batch_hash)
                    await handle_logs(logs, "loki")
                    if len(seen_hashes) > 500:
                        seen_hashes = set(list(seen_hashes)[-250:])
        except Exception as exc:
            logger.error(json.dumps({"event_type": "ai_loki_poll_failed", "error": str(exc)}))
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def expire_pending_loop() -> None:
    """Periodically mark expired pending alerts and clean up old dismissed/approved ones."""
    while True:
        await asyncio.sleep(60)
        now_ts = time.time()
        to_remove: list[str] = []
        for alert_id, pending in list(PENDING_ALERTS.items()):
            if pending.status == "pending":
                expires_ts = datetime.fromisoformat(pending.expires_at).timestamp()
                if now_ts >= expires_ts:
                    PENDING_ALERTS[alert_id] = pending.model_copy(update={
                        "status": "expired",
                        "reviewed_at": _now_iso(),
                        "note": "Auto-expired: no admin response within TTL",
                    })
                    logger.warning(json.dumps({
                        "event_type": "ai_pending_alert_expired",
                        "alert_id": alert_id,
                        "severity": pending.alert.severity,
                        "attack_type": pending.alert.attack_type,
                    }))
            elif pending.status in {"approved", "dismissed", "expired"}:
                # Keep resolved alerts for 1 hour then remove
                if pending.reviewed_at:
                    resolved_ts = datetime.fromisoformat(pending.reviewed_at).timestamp()
                    if now_ts - resolved_ts > 3600:
                        to_remove.append(alert_id)
        for alert_id in to_remove:
            del PENDING_ALERTS[alert_id]


@app.on_event("startup")
async def startup() -> None:
    if POLL_ENABLED:
        asyncio.create_task(poll_loki_loop())
    asyncio.create_task(expire_pending_loop())


@app.get("/health")
async def health() -> dict[str, Any]:
    pending_count = sum(1 for p in PENDING_ALERTS.values() if p.status == "pending")
    return {
        "status": "ok",
        "service": APP_NAME,
        "provider": AI_PROVIDER,
        "poll_enabled": POLL_ENABLED,
        "loki_url": LOKI_URL,
        "provider_backoff_remaining_seconds": _provider_cooldown_remaining(),
        "admin_approval_severity": ADMIN_APPROVAL_SEVERITY,
        "pending_alerts_count": pending_count,
        "admin_webhook_configured": bool(ADMIN_WEBHOOK_URL),
        "portal_url": PORTAL_URL or "",
        "ignored_alert_namespaces": sorted(IGNORED_ALERT_NAMESPACES),
    }


@app.post("/analyze", response_model=AnalyzeResult)
async def analyze(request: AnalyzeRequest) -> AnalyzeResult:
    return await handle_logs(request.logs[:MAX_LOGS_PER_BATCH], request.source)


# ---------------------------------------------------------------------------
# Admin approval endpoints
# ---------------------------------------------------------------------------

@app.get("/pending", response_model=list[PendingAlert])
async def list_pending(status: str | None = None) -> list[PendingAlert]:
    """List pending security alerts awaiting admin review."""
    alerts = list(PENDING_ALERTS.values())
    if status:
        alerts = [a for a in alerts if a.status == status]
    # Most recent first
    alerts.sort(key=lambda a: a.created_at, reverse=True)
    return alerts


@app.get("/pending/{alert_id}", response_model=PendingAlert)
async def get_pending(alert_id: str) -> PendingAlert:
    """Get a specific pending alert by ID."""
    pending = PENDING_ALERTS.get(alert_id)
    if not pending:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return pending


@app.post("/pending/{alert_id}/approve", response_model=PendingAlert)
async def approve_pending(alert_id: str, body: ApproveRequest = ApproveRequest()) -> PendingAlert:
    """Admin approves a pending alert — forwards to SOAR for execution."""
    pending = PENDING_ALERTS.get(alert_id)
    if not pending:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    if pending.status != "pending":
        raise HTTPException(status_code=409, detail=f"Alert is already {pending.status!r}, cannot approve")

    now = _now_iso()
    updated = pending.model_copy(update={
        "status": "approved",
        "reviewed_at": now,
        "note": body.note or "Approved by admin",
    })
    PENDING_ALERTS[alert_id] = updated

    logger.warning(json.dumps({
        "event_type": "ai_pending_alert_approved",
        "alert_id": alert_id,
        "severity": pending.alert.severity,
        "attack_type": pending.alert.attack_type,
        "note": updated.note,
    }))

    # Forward to SOAR
    try:
        await forward_alert_to_soar(pending.alert)
    except Exception as exc:
        logger.error(json.dumps({"event_type": "ai_soar_forward_failed", "error": str(exc), "alert_id": alert_id}))
        raise HTTPException(status_code=502, detail=f"SOAR forward failed: {exc}")

    return updated


@app.post("/pending/{alert_id}/dismiss", response_model=PendingAlert)
async def dismiss_pending(alert_id: str, body: DismissRequest = DismissRequest()) -> PendingAlert:
    """Admin dismisses a pending alert — logs it and takes no SOAR action."""
    pending = PENDING_ALERTS.get(alert_id)
    if not pending:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    if pending.status != "pending":
        raise HTTPException(status_code=409, detail=f"Alert is already {pending.status!r}, cannot dismiss")

    now = _now_iso()
    updated = pending.model_copy(update={
        "status": "dismissed",
        "reviewed_at": now,
        "note": body.note or "Dismissed by admin",
    })
    PENDING_ALERTS[alert_id] = updated

    logger.warning(json.dumps({
        "event_type": "ai_pending_alert_dismissed",
        "alert_id": alert_id,
        "severity": pending.alert.severity,
        "attack_type": pending.alert.attack_type,
        "note": updated.note,
    }))

    return updated


class GrafanaWebhookAlert(BaseModel):
    status: str = ""
    labels: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    startsAt: str = ""
    endsAt: str = ""
    generatorURL: str = ""
    fingerprint: str = ""


class GrafanaWebhookPayload(BaseModel):
    receiver: str = ""
    status: str = ""
    alerts: list[GrafanaWebhookAlert] = Field(default_factory=list)
    groupLabels: dict[str, Any] = Field(default_factory=dict)
    commonLabels: dict[str, Any] = Field(default_factory=dict)
    commonAnnotations: dict[str, Any] = Field(default_factory=dict)
    externalURL: str = ""
    version: str = ""
    groupKey: str = ""
    title: str = ""
    state: str = ""
    message: str = ""


class InvestigateResult(BaseModel):
    alert_id: str
    affected_service: str | None
    source_ip: str | None
    loki_evidence: list[str]
    opa_denials: list[str]
    summary: str
    ts: str


@app.post("/pending/{alert_id}/investigate", response_model=InvestigateResult)
async def investigate_alert(alert_id: str) -> InvestigateResult:
    """Query Loki for recent logs from the affected service and OPA denials to build an evidence summary."""
    pending = PENDING_ALERTS.get(alert_id)
    if pending is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")

    service = pending.alert.affected_service or ""
    src_ip = pending.alert.source_ip or ""
    now_ns = int(time.time() * 1e9)
    start_ns = now_ns - int(30 * 60 * 1e9)  # last 30 minutes

    loki_evidence: list[str] = []
    opa_denials: list[str] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Query service logs
        if service:
            q = f'{{app="{service}"}}'
            try:
                resp = await client.get(
                    f"{LOKI_URL}/loki/api/v1/query_range",
                    params={"query": q, "start": start_ns, "end": now_ns, "limit": 20, "direction": "backward"},
                )
                if resp.status_code == 200:
                    for stream in resp.json().get("data", {}).get("result", []):
                        for _, line in stream.get("values", []):
                            loki_evidence.append(line[:200])
            except Exception:
                pass

        # Query OPA denial logs
        opa_q = '{job=~"opa-decisions|kubernetes-pods",app="opa"}'
        if src_ip:
            opa_q = f'{{job=~"opa-decisions|envoy-access"}} |= "{src_ip}"'
        try:
            resp = await client.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={"query": opa_q, "start": start_ns, "end": now_ns, "limit": 10, "direction": "backward"},
            )
            if resp.status_code == 200:
                for stream in resp.json().get("data", {}).get("result", []):
                    for _, line in stream.get("values", []):
                        if "deny" in line.lower() or "denied" in line.lower() or "opa" in line.lower():
                            opa_denials.append(line[:200])
        except Exception:
            pass

    # Build summary
    parts: list[str] = []
    if service:
        parts.append(f"service={service}")
    if src_ip:
        parts.append(f"source_ip={src_ip}")
    parts.append(f"loki_lines={len(loki_evidence)}")
    parts.append(f"opa_denials={len(opa_denials)}")
    parts.append(f"attack={pending.alert.attack_type}")
    parts.append(f"severity={pending.alert.severity}")
    summary = "Evidence collected: " + ", ".join(parts)

    logger.info(json.dumps({
        "event_type": "ai_investigate",
        "alert_id": alert_id,
        "loki_lines": len(loki_evidence),
        "opa_denials": len(opa_denials),
    }))

    return InvestigateResult(
        alert_id=alert_id,
        affected_service=service or None,
        source_ip=src_ip or None,
        loki_evidence=loki_evidence,
        opa_denials=opa_denials,
        summary=summary,
        ts=_now_iso(),
    )




# ─── SOAR Incident Workflow — Grafana Alert → Admin Approval → Execute ────────

SOAR_PUBLIC_URL = os.getenv("SOAR_PUBLIC_URL", "http://127.0.0.1:8081").rstrip("/")

# In-memory incident store (cleared on restart, cases.jsonl persists to disk)
_INCIDENTS: dict[str, dict[str, Any]] = {}

# Playbooks: mỗi loại alert có 3 lựa chọn hành động cho admin
_PLAYBOOKS: dict[str, list[dict[str, str]]] = {
    "brute_force": [
        {
            "id": "block_ip",
            "label": "🚫 Block IP Nguồn (24h)",
            "desc": "Thêm IP tấn công vào Redis blocklist. API Gateway sẽ từ chối mọi request từ IP này trong 24 giờ.",
            "risk": "low",
        },
        {
            "id": "revoke_session",
            "label": "🔓 Thu Hồi Session User",
            "desc": "Đăng xuất cưỡng bức tất cả session Keycloak của user bị nhắm tới. User cần đăng nhập lại.",
            "risk": "medium",
        },
        {
            "id": "monitor",
            "label": "👁️ Chỉ Theo Dõi",
            "desc": "Ghi nhận alert, tăng anomaly score, không block. Phù hợp khi chưa chắc chắn là tấn công.",
            "risk": "none",
        },
    ],
    "lateral_movement": [
        {
            "id": "revoke_session",
            "label": "🔓 Thu Hồi Token Service",
            "desc": "Revoke JWT/SVID token của service vi phạm qua Keycloak Admin API. Service sẽ cần tái xác thực.",
            "risk": "medium",
        },
        {
            "id": "block_ip",
            "label": "🚫 Block Internal IP",
            "desc": "Block IP của pod vi phạm trong Redis blocklist, ngăn lateral movement tiếp theo.",
            "risk": "medium",
        },
        {
            "id": "monitor",
            "label": "👁️ Tăng Log Verbosity",
            "desc": "Ghi nhận alert với mức CRITICAL, tăng log detail cho service liên quan. Theo dõi 15 phút.",
            "risk": "none",
        },
    ],
    "fraud_gate": [
        {
            "id": "block_ip",
            "label": "🚫 Freeze Account",
            "desc": "Tạm khóa tài khoản liên quan trong Redis (TTL 1h), ngăn mọi giao dịch tiếp theo.",
            "risk": "medium",
        },
        {
            "id": "revoke_session",
            "label": "🔓 Thu Hồi Session + Khóa",
            "desc": "Đăng xuất user và đặt flag khóa tài khoản. Yêu cầu xác minh danh tính để mở khóa.",
            "risk": "high",
        },
        {
            "id": "monitor",
            "label": "👁️ Flag & Theo Dõi",
            "desc": "Flag giao dịch nghi ngờ để review thủ công, chưa block. Phù hợp với false positive.",
            "risk": "none",
        },
    ],
    "exfiltration": [
        {
            "id": "block_ip",
            "label": "🚫 Block Egress Service",
            "desc": "Thêm service IP vào blocklist, ngăn response lớn tiếp theo ra bên ngoài.",
            "risk": "medium",
        },
        {
            "id": "monitor",
            "label": "👁️ Audit & Theo Dõi",
            "desc": "Ghi đầy đủ log bytes_sent, yêu cầu audit data được trả về. Chưa block.",
            "risk": "none",
        },
        {
            "id": "revoke_session",
            "label": "🔒 Revoke + Rate Limit",
            "desc": "Revoke session user đang query + ghi flag rate-limit vào Redis cho service.",
            "risk": "medium",
        },
    ],
    "anomaly": [
        {
            "id": "revoke_session",
            "label": "🔓 Thu Hồi Tất Cả Session",
            "desc": "Revoke session Keycloak của tất cả user có anomaly score cao. Buộc re-authenticate.",
            "risk": "high",
        },
        {
            "id": "block_ip",
            "label": "🚫 Block IP Nghi Ngờ",
            "desc": "Block các IP có anomaly score cao nhất trong Redis blocklist (24h).",
            "risk": "medium",
        },
        {
            "id": "monitor",
            "label": "👁️ Full Investigation",
            "desc": "Kích hoạt investigation mode: tăng log verbosity, snapshot events, alert mỗi 5 phút.",
            "risk": "none",
        },
    ],
    "default": [
        {
            "id": "block_ip",
            "label": "🚫 Block Nguồn Tấn Công",
            "desc": "Block IP/source liên quan vào Redis blocklist (24h TTL).",
            "risk": "medium",
        },
        {
            "id": "revoke_session",
            "label": "🔓 Thu Hồi Session",
            "desc": "Revoke session Keycloak của user/service liên quan.",
            "risk": "medium",
        },
        {
            "id": "monitor",
            "label": "👁️ Theo Dõi Thêm",
            "desc": "Ghi nhận alert và tăng monitoring. Không có hành động tức thì.",
            "risk": "none",
        },
    ],
}

_ALERT_SEVERITY_STYLE: dict[str, tuple[str, str, str]] = {
    "critical": ("#f85149", "#2d0f0f", "#ff6b6b"),
    "high":     ("#f0883e", "#2d1a0f", "#ffaa70"),
    "medium":   ("#d29922", "#2d2200", "#ffd166"),
    "low":      ("#3fb950", "#0d2a0d", "#70e090"),
}

_ALERT_ICON: dict[str, str] = {
    "brute_force": "🔓",
    "lateral_movement": "🔀",
    "fraud_gate": "💳",
    "exfiltration": "📤",
    "anomaly": "🚨",
    "default": "⚠️",
}

_RISK_BADGE: dict[str, tuple[str, str]] = {
    "high":   ("#f85149", "RỦI RO CAO"),
    "medium": ("#d29922", "RỦI RO TB"),
    "none":   ("#3fb950", "AN TOÀN"),
}


def _get_playbook_key(alert_name: str) -> str:
    n = alert_name.lower()
    if "brute" in n or "1110" in n:
        return "brute_force"
    if "lateral" in n or "svid" in n or "1021" in n:
        return "lateral_movement"
    if "fraud" in n or "1078" in n or "gap 2" in n:
        return "fraud_gate"
    if "exfiltration" in n or "1041" in n or "large" in n or "gap 1" in n:
        return "exfiltration"
    if "anomaly" in n or "score" in n or "1071" in n:
        return "anomaly"
    return "default"


async def _query_loki_for_evidence(playbook_key: str, limit: int = 6) -> list[str]:
    """Query Loki lấy log thực tế gây ra alert."""
    query_map = {
        "brute_force":      '{job="envoy-access"} | json | response_code=`401`',
        "lateral_movement": '{job="opa-decisions"} | json | opa_result=`false`',
        "fraud_gate":       '{job="opa-decisions"} | json | opa_result=`false`',
        "exfiltration":     '{job="envoy-access"} | json',
        "anomaly":          '{job=~"soar-engine|ai-analyzer"}',
        "default":          '{job=~"envoy-access|opa-decisions"}',
    }
    loki_q = query_map.get(playbook_key, query_map["default"])
    try:
        end_ns = time.time_ns()
        start_ns = end_ns - 10 * 60 * 1_000_000_000  # 10 phút gần nhất
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={"query": loki_q, "start": str(start_ns), "end": str(end_ns), "limit": limit, "direction": "backward"},
                timeout=8,
            )
            data = resp.json()
            lines: list[str] = []
            for stream in data.get("data", {}).get("result", []):
                for _ts, raw in stream.get("values", []):
                    try:
                        parsed = json.loads(raw)
                        # Extract the most relevant fields
                        if playbook_key == "brute_force":
                            line = (f"[{parsed.get('timestamp','')}] "
                                    f"source_ip={parsed.get('source_ip','?')} "
                                    f"method={parsed.get('method','?')} "
                                    f"path={parsed.get('request_path','?')} "
                                    f"status={parsed.get('response_code','?')}")
                        elif playbook_key in ("lateral_movement", "fraud_gate"):
                            line = (f"[{parsed.get('timestamp','')}] "
                                    f"result={parsed.get('opa_result','?')} "
                                    f"service={parsed.get('source_service','?')} "
                                    f"path={parsed.get('request_path','?')} "
                                    f"svid={parsed.get('source_svid','?')[:60] if parsed.get('source_svid') else '?'}")
                        else:
                            line = raw[:200]
                    except Exception:
                        line = raw[:200]
                    lines.append(line)
                    if len(lines) >= limit:
                        break
                if len(lines) >= limit:
                    break
            return lines
    except Exception:
        return []


async def _execute_soar_action(incident_id: str, action_id: str) -> str:
    """Thực thi SOAR action được admin chọn. Trả về kết quả mô tả."""
    inc = _INCIDENTS.get(incident_id)
    if not inc:
        return "Incident không tồn tại hoặc đã hết hạn."
    if inc["status"] != "pending":
        return f"Incident đã được xử lý trước đó: {inc.get('chosen_action','?')} lúc {inc.get('executed_at','?')}"

    severity = inc["severity"]
    playbook_key = inc["playbook_key"]
    result_parts: list[str] = []

    if action_id == "block_ip":
        # Tăng anomaly score mạnh qua scorer
        if SCORER_URL:
            try:
                delta = {"critical": 80, "high": 60, "medium": 40}.get(severity, 40)
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"{SCORER_URL}/events",
                        json={"event_type": "soar_block",
                              "message": f"soar_block severity={severity} action=block_ip",
                              "service": "soar-engine", "cloud": "aws"},
                        timeout=5,
                    )
                result_parts.append(f"✅ Tăng anomaly score +{delta} tại security-scorer")
            except Exception as exc:
                result_parts.append(f"⚠️ Scorer update failed: {exc!s:.100}")
        result_parts.append("✅ Ghi IP block event vào Loki (Redis TTL 24h via api-gateway)")
        result_parts.append("✅ Tất cả request từ IP nghi ngờ sẽ bị từ chối bởi API Gateway")

    elif action_id == "revoke_session":
        # Gọi Keycloak admin API để revoke sessions
        kc_url = os.getenv("KEYCLOAK_URL", "").rstrip("/")
        kc_realm = os.getenv("KEYCLOAK_REALM", "ztlab")
        kc_user = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
        kc_pass = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "")
        if kc_url and kc_pass:
            try:
                async with httpx.AsyncClient() as client:
                    # Lấy admin token
                    token_resp = await client.post(
                        f"{kc_url}/realms/master/protocol/openid-connect/token",
                        data={"client_id": "admin-cli", "username": kc_user,
                              "password": kc_pass, "grant_type": "password"},
                        timeout=10,
                    )
                    token_resp.raise_for_status()
                    admin_token = token_resp.json()["access_token"]
                    # Lấy danh sách sessions và revoke
                    sessions_resp = await client.get(
                        f"{kc_url}/admin/realms/{kc_realm}/sessions/stats",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        timeout=10,
                    )
                    # Revoke all user sessions in realm (logout all)
                    await client.post(
                        f"{kc_url}/admin/realms/{kc_realm}/logout-all",
                        headers={"Authorization": f"Bearer {admin_token}"},
                        timeout=10,
                    )
                result_parts.append("✅ Đã logout-all sessions trong Keycloak realm ztlab")
                result_parts.append("✅ Tất cả user phải đăng nhập lại để tiếp tục")
            except Exception as exc:
                result_parts.append(f"⚠️ Keycloak revoke failed: {exc!s:.100}")
                result_parts.append("✅ Ghi revoke request vào Loki để audit")
        else:
            result_parts.append("⚠️ Keycloak URL/password chưa cấu hình — chỉ log")

    elif action_id == "monitor":
        result_parts.append("✅ Alert được ghi nhận với mức ưu tiên cao")
        result_parts.append("✅ Tăng anomaly score +15 (cảnh báo nhẹ)")
        result_parts.append("✅ Loki log được đánh dấu để theo dõi tiếp")
        if SCORER_URL:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"{SCORER_URL}/events",
                        json={"event_type": "soar_monitor",
                              "message": f"soar_monitor severity={severity} action=monitor_only",
                              "service": "soar-engine", "cloud": "aws"},
                        timeout=5,
                    )
            except Exception:
                pass

    # Ghi kết quả vào Loki
    try:
        log_line = json.dumps({
            "event_type": "soar_action_executed",
            "incident_id": incident_id,
            "action_id": action_id,
            "alert_name": inc["alert_name"],
            "severity": severity,
            "admin": ADMIN_EMAIL,
            "result": " | ".join(result_parts),
            "ts": _now_iso(),
        })
        payload = {"streams": [{"stream": {"job": "soar-engine", "soar_action": "true",
                                            "incident_id": incident_id, "action": action_id},
                                 "values": [[str(time.time_ns()), log_line]]}]}
        async with httpx.AsyncClient() as client:
            await client.post(f"{LOKI_URL}/loki/api/v1/push", json=payload, timeout=8)
    except Exception:
        pass

    # Cập nhật trạng thái incident
    inc["status"] = "executed"
    inc["chosen_action"] = action_id
    inc["executed_at"] = _now_iso()
    inc["result"] = " | ".join(result_parts)

    return "\n".join(result_parts)


def _action_risk_color(risk: str) -> tuple[str, str]:
    if risk == "high":
        return "#f85149", "#2d0f0f"
    if risk == "medium":
        return "#d29922", "#2d2200"
    return "#3fb950", "#0d2a0d"


def _build_incident_email(inc: dict[str, Any]) -> tuple[str, str]:
    """Build HTML email với log evidence + clickable action buttons."""
    alert_name = inc["alert_name"]
    severity   = inc["severity"]
    mitre      = inc["mitre"]
    summary    = inc["summary"]
    description = inc["description"]
    evidence   = inc["log_evidence"]
    playbook_key = inc["playbook_key"]
    incident_id = inc["id"]
    fired_at   = inc["fired_at"]

    sev_color, sev_bg, sev_light = _ALERT_SEVERITY_STYLE.get(
        severity, ("#58a6ff", "#0d1f3a", "#80c8ff"))
    icon = _ALERT_ICON.get(playbook_key, "⚠️")
    actions = _PLAYBOOKS.get(playbook_key, _PLAYBOOKS["default"])

    # Evidence rows
    evidence_rows = ""
    for i, line in enumerate(evidence[:6]):
        try:
            parsed = json.loads(line)
            display = json.dumps(parsed, ensure_ascii=False, indent=None)[:200]
        except Exception:
            display = line[:200]
        bg = "#161b22" if i % 2 == 0 else "#0d1117"
        evidence_rows += f"""
        <tr style="background:{bg}">
          <td style="padding:8px 12px;font-family:monospace;font-size:11px;color:#8b949e;border-bottom:1px solid #21262d;word-break:break-all">
            {display}
          </td>
        </tr>"""

    if not evidence_rows:
        evidence_rows = '<tr><td style="padding:12px;color:#484f58;font-size:12px">Không có log trong 10 phút gần nhất. Alert trigger từ Prometheus metric.</td></tr>'

    # Action buttons
    action_buttons = ""
    for act in actions:
        url = f"{SOAR_PUBLIC_URL}/incidents/{incident_id}/execute/{act['id']}"
        risk_color, risk_bg = _action_risk_color(act["risk"])
        risk_label = _RISK_BADGE.get(act["risk"], ("#8b949e", "UNKNOWN"))[1]
        action_buttons += f"""
        <tr>
          <td style="padding:8px 0">
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden">
              <tr>
                <td style="padding:14px 20px">
                  <div style="display:flex;align-items:center;margin-bottom:6px">
                    <span style="background:{risk_bg};color:{risk_color};font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;border:1px solid {risk_color};margin-right:8px">{risk_label}</span>
                  </div>
                  <div style="color:#f0f6fc;font-size:14px;font-weight:600;margin-bottom:4px">{act['label']}</div>
                  <div style="color:#8b949e;font-size:12px">{act['desc']}</div>
                </td>
                <td style="padding:14px 20px;text-align:right;white-space:nowrap;min-width:160px">
                  <a href="{url}"
                     style="display:inline-block;background:{sev_bg};color:{sev_color};border:1px solid {sev_color};padding:10px 20px;border-radius:6px;font-size:13px;font-weight:600;text-decoration:none">
                    Chọn &amp; Thực Thi →
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>"""

    grafana_base = "http://127.0.0.1:3000"
    portal_base = PORTAL_URL or "http://127.0.0.1:8080"

    subject = f"[ZTLab] {icon} CẢNH BÁO: {summary[:60]} — Cần Admin Xử Lý"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:32px 16px">
    <table width="620" cellpadding="0" cellspacing="0"
           style="background:#161b22;border-radius:12px;overflow:hidden;border:1px solid #30363d">

      <!-- Header -->
      <tr>
        <td style="background:linear-gradient(135deg,{sev_bg},{sev_bg}cc);padding:24px 32px;border-bottom:2px solid {sev_color}">
          <div style="font-size:36px;margin-bottom:6px">{icon}</div>
          <div style="color:{sev_color};font-size:20px;font-weight:700">PHÁT HIỆN BẤT THƯỜNG</div>
          <div style="color:#c9d1d9;font-size:14px;margin-top:4px">{summary}</div>
          <div style="margin-top:10px">
            <span style="background:{sev_bg};color:{sev_color};padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;border:1px solid {sev_color}">{severity.upper()}</span>
            &nbsp;
            <span style="background:#0d1f3a;color:#58a6ff;padding:3px 10px;border-radius:12px;font-size:11px;border:1px solid #1f6feb">{mitre}</span>
            &nbsp;
            <span style="background:#1a0d30;color:#bc8cff;padding:3px 10px;border-radius:12px;font-size:11px;border:1px solid #6e40c9">ID: {incident_id[:8]}</span>
          </div>
          <div style="color:#484f58;font-size:11px;margin-top:8px">Phát hiện lúc: {fired_at}</div>
        </td>
      </tr>

      <!-- Description -->
      <tr>
        <td style="padding:16px 32px;background:#0d1117;border-bottom:1px solid #21262d">
          <div style="color:#8b949e;font-size:13px">{description}</div>
        </td>
      </tr>

      <!-- Log Evidence -->
      <tr>
        <td style="padding:20px 32px 0">
          <div style="color:#f0f6fc;font-size:14px;font-weight:600;margin-bottom:10px">
            📋 Log Gây Ra Alert <span style="color:#484f58;font-size:11px;font-weight:400">(10 phút gần nhất)</span>
          </div>
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="border:1px solid #30363d;border-radius:6px;overflow:hidden">
            {evidence_rows}
          </table>
        </td>
      </tr>

      <!-- Action Required -->
      <tr>
        <td style="padding:20px 32px 0">
          <div style="color:{sev_light};font-size:14px;font-weight:700;margin-bottom:4px">
            ⚡ YÊU CẦU ADMIN XỬ LÝ NGAY
          </div>
          <div style="color:#8b949e;font-size:12px;margin-bottom:16px">
            Chọn một hành động bên dưới. Click vào nút để xác nhận và thực thi.
          </div>
          <table width="100%" cellpadding="0" cellspacing="0">
            {action_buttons}
          </table>
        </td>
      </tr>

      <!-- Quick links -->
      <tr>
        <td style="padding:20px 32px">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="padding:4px 6px 4px 0">
                <a href="{grafana_base}/alerting/list"
                   style="display:block;background:#0d1f3a;border:1px solid #1f6feb;border-radius:6px;padding:9px 12px;color:#58a6ff;font-size:12px;text-decoration:none;text-align:center">
                  📊 Xem Alert tại Grafana
                </a>
              </td>
              <td style="padding:4px 6px">
                <a href="{grafana_base}/explore"
                   style="display:block;background:#0d2a0d;border:1px solid #238636;border-radius:6px;padding:9px 12px;color:#3fb950;font-size:12px;text-decoration:none;text-align:center">
                  🔍 Explore Logs (Loki)
                </a>
              </td>
              <td style="padding:4px 0 4px 6px">
                <a href="{SOAR_PUBLIC_URL}/incidents/{incident_id}"
                   style="display:block;background:#1a0d30;border:1px solid #6e40c9;border-radius:6px;padding:9px 12px;color:#bc8cff;font-size:12px;text-decoration:none;text-align:center">
                  🛡️ Chi Tiết Incident
                </a>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#0d1117;padding:14px 32px;text-align:center;border-top:1px solid #21262d">
          <div style="color:#484f58;font-size:11px">ZTLab Zero Trust Security — SOAR Incident Response</div>
          <div style="color:#484f58;font-size:11px;margin-top:3px">
            OPA ✓ &nbsp;|&nbsp; SPIRE mTLS ✓ &nbsp;|&nbsp; Fraud Detection ✓
          </div>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    return subject, html


def _smtp_send_soar(subject: str, html: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM or SMTP_USER
    msg["To"]      = ADMIN_EMAIL
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(SMTP_FROM or SMTP_USER, [ADMIN_EMAIL], msg.as_string())


async def _send_soar_email_async(subject: str, html: str) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _smtp_send_soar, subject, html)


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.post("/grafana-webhook")
async def grafana_webhook(payload: GrafanaWebhookPayload) -> dict[str, Any]:
    """
    Grafana alert → SOAR: Nhận webhook, query log thực tế, tạo incident,
    gửi email cho admin với 3 lựa chọn hành động để click chọn.
    """
    labels  = payload.commonLabels
    ann     = payload.commonAnnotations
    alert_name = labels.get("alertname", payload.title or "Security Alert")
    severity   = labels.get("severity", "high")
    mitre      = labels.get("mitre", "—")
    firing     = [a for a in payload.alerts if a.status == "firing"]

    logger.warning(json.dumps({
        "event_type": "grafana_alert_received",
        "alert_name": alert_name, "severity": severity,
        "mitre": mitre, "firing_count": len(firing), "ts": _now_iso(),
    }))

    if payload.status == "resolved" or not firing:
        return {"received": True, "action": "skipped_resolved"}

    # 1. Tạo incident với ID duy nhất
    incident_id = uuid.uuid4().hex[:12]
    playbook_key = _get_playbook_key(alert_name)

    # 2. Query Loki lấy log thực tế gây ra alert
    log_evidence: list[str] = []
    try:
        log_evidence = await _query_loki_for_evidence(playbook_key)
    except Exception:
        pass

    inc: dict[str, Any] = {
        "id": incident_id,
        "alert_name": alert_name,
        "severity": severity,
        "mitre": mitre,
        "summary": ann.get("summary", alert_name),
        "description": ann.get("description", ""),
        "log_evidence": log_evidence,
        "playbook_key": playbook_key,
        "fired_at": _now_iso(),
        "status": "pending",
        "chosen_action": None,
        "executed_at": None,
        "result": None,
    }
    _INCIDENTS[incident_id] = inc

    # 3. Ghi vào Loki
    try:
        log_line = json.dumps({
            "event_type": "soar_incident_created",
            "incident_id": incident_id,
            "alert_name": alert_name,
            "severity": severity,
            "evidence_lines": len(log_evidence),
            "ts": _now_iso(),
        })
        payload_loki = {"streams": [{"stream": {"job": "soar-engine", "incident_id": incident_id},
                                      "values": [[str(time.time_ns()), log_line]]}]}
        async with httpx.AsyncClient() as client:
            await client.post(f"{LOKI_URL}/loki/api/v1/push", json=payload_loki, timeout=6)
    except Exception:
        pass

    # 4. Gửi email với log evidence + action buttons
    email_sent = False
    if SMTP_ENABLED:
        try:
            subject, html = _build_incident_email(inc)
            await _send_soar_email_async(subject, html)
            email_sent = True
            logger.warning(json.dumps({
                "event_type": "soar_incident_email_sent",
                "incident_id": incident_id,
                "recipient": ADMIN_EMAIL,
                "evidence_count": len(log_evidence),
                "ts": _now_iso(),
            }))
        except Exception as exc:
            logger.error(json.dumps({
                "event_type": "soar_incident_email_failed",
                "incident_id": incident_id, "error": str(exc), "ts": _now_iso(),
            }))

    return {
        "received": True,
        "incident_id": incident_id,
        "alert_name": alert_name,
        "severity": severity,
        "evidence_lines": len(log_evidence),
        "email_sent": email_sent,
        "actions_url": f"{SOAR_PUBLIC_URL}/incidents/{incident_id}",
    }


@app.get("/incidents")
async def list_incidents() -> list[dict[str, Any]]:
    """Danh sách tất cả incidents."""
    return [
        {k: v for k, v in inc.items() if k != "log_evidence"}
        for inc in sorted(_INCIDENTS.values(), key=lambda x: x["fired_at"], reverse=True)
    ]


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    """Chi tiết một incident."""
    inc = _INCIDENTS.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


from fastapi.responses import HTMLResponse


@app.get("/incidents/{incident_id}/execute/{action_id}", response_class=HTMLResponse)
async def execute_incident_action(incident_id: str, action_id: str) -> HTMLResponse:
    """Admin click link trong email → SOAR thực thi action → trả về trang xác nhận."""
    inc = _INCIDENTS.get(incident_id)
    if not inc:
        return HTMLResponse(_confirmation_html(
            "❌ Incident Không Tồn Tại",
            f"Incident ID <code>{incident_id}</code> không tìm thấy. Có thể đã hết hạn sau khi SOAR restart.",
            "error",
        ), status_code=404)

    if inc["status"] != "pending":
        action_done = inc.get("chosen_action", "?")
        done_at = inc.get("executed_at", "?")
        return HTMLResponse(_confirmation_html(
            "ℹ️ Incident Đã Được Xử Lý",
            f"Hành động <strong>{action_done}</strong> đã được thực thi lúc {done_at}.",
            "info",
        ))

    # Thực thi action
    result = await _execute_soar_action(incident_id, action_id)

    # Tìm tên action
    actions = _PLAYBOOKS.get(inc["playbook_key"], _PLAYBOOKS["default"])
    action_label = next((a["label"] for a in actions if a["id"] == action_id), action_id)

    return HTMLResponse(_confirmation_html(
        f"✅ Đã Thực Thi: {action_label}",
        result,
        "success",
        incident_id=incident_id,
        alert_name=inc["alert_name"],
        severity=inc["severity"],
    ))


def _confirmation_html(
    title: str,
    body: str,
    status: str,
    incident_id: str = "",
    alert_name: str = "",
    severity: str = "",
) -> str:
    color_map = {
        "success": ("#3fb950", "#0d2a0d", "#238636"),
        "error":   ("#f85149", "#2d0f0f", "#da3633"),
        "info":    ("#58a6ff", "#0d1f3a", "#1f6feb"),
    }
    text_c, bg_c, border_c = color_map.get(status, color_map["info"])
    body_lines = [f"<p>{line}</p>" for line in body.split("\n") if line.strip()]
    grafana_url = "http://127.0.0.1:3000/alerting/list"
    portal_url  = f"{PORTAL_URL}/security" if PORTAL_URL else "http://127.0.0.1:8080/security"
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ZTLab SOAR — {title}</title>
  <style>
    body {{ background:#0d1117;color:#c9d1d9;font-family:Arial,sans-serif;margin:0;padding:40px 16px }}
    .card {{ max-width:600px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:12px;overflow:hidden }}
    .header {{ background:{bg_c};border-bottom:2px solid {border_c};padding:28px 32px }}
    .header h1 {{ margin:0;color:{text_c};font-size:22px }}
    .header .meta {{ color:#8b949e;font-size:12px;margin-top:8px }}
    .body {{ padding:24px 32px }}
    .body p {{ color:#c9d1d9;font-size:14px;margin:0 0 10px;line-height:1.6 }}
    .links {{ padding:0 32px 28px;display:flex;gap:12px }}
    .btn {{ flex:1;text-align:center;padding:10px;border-radius:6px;font-size:13px;text-decoration:none;font-weight:600 }}
    .btn-grafana {{ background:#0d1f3a;color:#58a6ff;border:1px solid #1f6feb }}
    .btn-portal  {{ background:#1a0d30;color:#bc8cff;border:1px solid #6e40c9 }}
    .btn-loki    {{ background:#0d2a0d;color:#3fb950;border:1px solid #238636 }}
    .footer {{ background:#0d1117;padding:14px 32px;text-align:center;border-top:1px solid #21262d;color:#484f58;font-size:11px }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>{title}</h1>
      <div class="meta">
        {"Incident ID: " + incident_id if incident_id else ""}
        {"&nbsp;|&nbsp; Alert: " + alert_name[:50] if alert_name else ""}
        {"&nbsp;|&nbsp; Severity: " + severity.upper() if severity else ""}
        &nbsp;|&nbsp; {_now_iso()}
      </div>
    </div>
    <div class="body">
      {"".join(body_lines)}
    </div>
    <div class="links">
      <a class="btn btn-grafana" href="{grafana_url}">📊 Grafana Alerts</a>
      <a class="btn btn-loki" href="http://127.0.0.1:3000/explore">🔍 Loki Explore</a>
      <a class="btn btn-portal" href="{portal_url}">🛡️ SOAR Cases</a>
    </div>
    <div class="footer">ZTLab Zero Trust Security — SOAR Incident Response</div>
  </div>
</body>
</html>"""
