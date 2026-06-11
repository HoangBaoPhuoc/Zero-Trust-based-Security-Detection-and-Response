import asyncio
import hashlib
import json
import logging
import os
import random
import re
import time
import uuid
from datetime import datetime, timezone
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
# Webhook URL that receives pending alert notifications (Telegram bot, Slack, n8n, etc.)
ADMIN_WEBHOOK_URL = os.getenv("ADMIN_WEBHOOK_URL", "").strip()
PROVIDER_COOLDOWN_SECONDS = int(os.getenv("AI_PROVIDER_COOLDOWN_SECONDS", "900"))
_provider_backoff_until = 0.0

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MALICIOUS_PATTERNS = [
    (re.compile(r"\b(401|403|denied|deny|unauthorized|forbidden)\b", re.I), "access_denied"),
    (re.compile(r"fraud_gate_bypass", re.I), "fraud_gate_bypass"),
    (re.compile(r"lateral|invalid.*svid|spiffe.*den", re.I), "lateral_movement"),
    (re.compile(r"port scan|nmap|masscan|syn scan", re.I), "port_scan"),
    (re.compile(r"privilege escalation|setuid|cap_sys_admin", re.I), "privilege_escalation"),
    (re.compile(r"xmrig|cryptomin|stratum\+tcp", re.I), "cryptomining"),
    (re.compile(r"sqlmap|union select|/etc/passwd|cmd=|powershell|curl .*http", re.I), "exploit_probe"),
    (re.compile(r"bytes_sent[=: ]([1-9]\d{6,})", re.I), "large_response"),
]

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
        recommended_action=result.recommended_action or heuristic.recommended_action,
        recommended_playbook=result.recommended_playbook or heuristic.recommended_playbook,
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
    """Push pending alert notification to Loki (Grafana-visible) and optional webhook."""
    # Push to Loki with special label so Grafana can alert on it
    try:
        await push_alert_to_loki(alert, extra_labels={"pending_approval": "true", "alert_id": alert_id})
    except Exception as exc:
        logger.error(json.dumps({"event_type": "ai_admin_notify_loki_failed", "error": str(exc), "alert_id": alert_id}))

    if not ADMIN_WEBHOOK_URL:
        return

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
        "approve_hint": f"POST /pending/{alert_id}/approve",
        "dismiss_hint": f"POST /pending/{alert_id}/dismiss",
        "ts": alert.ts,
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(ADMIN_WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()


def should_alert(result: AnalyzeResult) -> bool:
    return result.verdict != "normal" and SEVERITY_RANK[result.severity] >= SEVERITY_RANK.get(MIN_ALERT_SEVERITY, 2)


def requires_admin_approval(result: AnalyzeResult) -> bool:
    return SEVERITY_RANK[result.severity] >= SEVERITY_RANK.get(ADMIN_APPROVAL_SEVERITY, 3)


async def handle_logs(logs: list[LogEntry], source: str) -> AnalyzeResult:
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
