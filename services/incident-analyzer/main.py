"""
ZTLab Incident Analyzer — detection-side evidence & notification service.

Replaces the former trio soar-engine + ai-analyzer + security-scorer (A4 of
KEHOACH-THAYDOI-HETHONG.md). The thesis stops at *detection + analysed evidence
+ prioritised notification*. This service therefore:

  * receives Grafana alert webhooks (POST /grafana-webhook) and generic alerts
    (POST /alerts),
  * maps the alert to a MITRE ATT&CK technique,
  * scores its priority (rule-based, 0-100),
  * pulls the surrounding logs from Loki (±5 min, jobs opa-decisions,
    envoy-access, bff-audit, waf-audit) into an **evidence bundle**,
  * emails the bundle to the operator via the in-cluster MailHog SMTP sink,
  * persists the evidence record and mirrors a summary line to Loki
    (job="incident-analyzer").

It has NO response capability: no Kubernetes client, no playbooks, no IP
blocking, no session revocation, no approve/deny endpoints. The ServiceAccount
it runs under is bound to no RBAC.

POST /evidence/{id}/risk-score is a reserved plug-in point for the Phase-C ML
model to attach a risk score to an existing evidence record.
"""
import json
import logging
import os
import re
import smtplib
import time
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Literal

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest
from pydantic import BaseModel, Field

APP_NAME = "incident-analyzer"
LOKI_URL = os.getenv("LOKI_URL", "http://loki.plg-stack.svc.cluster.local:3100").rstrip("/")
EVIDENCE_STORE_PATH = os.getenv("EVIDENCE_STORE_PATH", "/data/evidence.jsonl")

# In-cluster MailHog SMTP sink (no auth, no TLS). A real relay can be wired by
# setting SMTP_HOST/PORT/USER and providing SMTP_PASS via the Vault init
# container (see k8s/plg-stack/incident-analyzer.yaml); MailHog needs none.
SMTP_HOST = os.getenv("SMTP_HOST", "mailhog.plg-stack.svc.cluster.local")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "false").lower() == "true"
MAIL_FROM = os.getenv("MAIL_FROM", "incident-analyzer@ztlab.local")
MAIL_TO = os.getenv("MAIL_TO", "soc@ztlab.local")

EVIDENCE_WINDOW_S = int(os.getenv("EVIDENCE_WINDOW_SECONDS", "300"))  # ±5 min
EVIDENCE_JOBS = ["opa-decisions", "envoy-access", "bff-audit", "waf-audit"]
EVIDENCE_LIMIT_PER_JOB = int(os.getenv("EVIDENCE_LIMIT_PER_JOB", "25"))

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(APP_NAME)
app = FastAPI(title="ZTLab Incident Analyzer")

EVIDENCE_BUNDLES = Gauge("ztlab_evidence_bundles_total", "Evidence bundles produced since process start")
LAST_PRIORITY_SCORE = Gauge("ztlab_incident_priority_score", "Priority score (0-100) of the most recent evidence bundle")

# ── ATT&CK + display names ─────────────────────────────────────────────────────

ATTACK_MITRE: dict[str, str] = {
    "brute_force": "T1110.001",
    "credential_stuffing": "T1110.004",
    "jwt_replay": "T1550.001",
    "lateral_movement": "T1021.007",
    "account_manipulation": "T1098",
    "large_response": "T1041",
    "data_staging": "T1074",
    "cryptomining": "T1496",
    "container_escape": "T1611",
    "impair_defenses": "T1562",
    "privilege_escalation": "T1068",
    "port_scan": "T1046",
    "exploit_probe": "T1203",
    "access_denied": "T1078",
    "bfla": "T1078",
    "bola": "T1078",
}

ATTACK_DISPLAY: dict[str, str] = {
    "brute_force": "Brute Force Login (T1110.001)",
    "credential_stuffing": "Credential Stuffing (T1110.004)",
    "jwt_replay": "JWT Token Replay (T1550.001)",
    "lateral_movement": "Lateral Movement — Invalid SVID / ACL deny (T1021.007)",
    "account_manipulation": "Account Manipulation (T1098)",
    "large_response": "Data Exfiltration — Large Response (T1041)",
    "data_staging": "Data Staging — Bulk Export (T1074)",
    "cryptomining": "Cryptomining (T1496)",
    "container_escape": "Container Escape Attempt (T1611)",
    "impair_defenses": "Impair Defenses (T1562)",
    "privilege_escalation": "Privilege Escalation in Container (T1068)",
    "port_scan": "Port Scan (T1046)",
    "exploit_probe": "Exploit Probe / Injection (T1203)",
    "access_denied": "Access Denied Spike (T1078)",
}

# Rule weights for the priority score (adapted from the old security-scorer RULES)
_SCORE_WEIGHT: dict[str, int] = {
    "brute_force": 30,
    "credential_stuffing": 30,
    "jwt_replay": 25,
    "lateral_movement": 50,
    "account_manipulation": 40,
    "large_response": 35,
    "data_staging": 35,
    "cryptomining": 45,
    "container_escape": 50,
    "impair_defenses": 45,
    "privilege_escalation": 50,
    "port_scan": 25,
    "exploit_probe": 35,
    "access_denied": 10,
}

GRAFANA_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "warning": "medium",
    "medium": "medium", "info": "low", "low": "low",
}

GRAFANA_ATTACK_KEYWORDS = {
    "bfla": "access_denied", "bola": "access_denied", "brute": "brute_force",
    "anomaly": "access_denied", "lateral": "lateral_movement", "port_scan": "port_scan",
    "exploit": "exploit_probe", "jwt": "jwt_replay", "large": "large_response",
    "exfil": "large_response", "cred": "credential_stuffing",
}

# Loki queries whose result is the strongest single piece of evidence per attack.
# Mirrors the Grafana alert-rule LogQL so the bundle contains exactly what fired.
_EXACT_QUERY: dict[str, str] = {
    "brute_force": '{namespace="identity", app="keycloak"} |~ "(?i)login_error|invalid_user_credentials"',
    "access_denied": '{job="opa-decisions", opa_result="false"}',
    "lateral_movement": '{job="opa-decisions", opa_result="false", request_path=~"/(workshop|community)/api/.*"} != "/identity/api/auth/verify"',
    "large_response": '{job="envoy-access", namespace="crapi"} | json | bytes_sent > 1048576',
}


# ── Models ────────────────────────────────────────────────────────────────────

class GenericAlert(BaseModel):
    verdict: str = "malicious"
    severity: Literal["low", "medium", "high", "critical"] = "high"
    attack_type: str = "unknown"
    summary: str = ""
    mitre: str = ""
    source_ip: str | None = None
    affected_service: str | None = None
    evidence: list[str] = Field(default_factory=list)
    ts: str | None = None


class RiskScore(BaseModel):
    risk_score: float = Field(ge=0, le=1)
    model: str = "unknown"
    features: dict[str, Any] = Field(default_factory=dict)
    note: str | None = None


class EvidenceRecord(BaseModel):
    evidence_id: str
    ts: str
    alert_name: str
    attack_type: str
    mitre: str
    severity: str
    priority_score: int
    summary: str
    source_ip: str | None = None
    affected_service: str | None = None
    window_seconds: int
    loki_queries: dict[str, str] = Field(default_factory=dict)
    bundle: dict[str, list[str]] = Field(default_factory=dict)
    bundle_line_count: int = 0
    email_sent: bool = False
    # Reserved plug-in point for the Phase-C ML model (POST /evidence/{id}/risk-score)
    risk: RiskScore | None = None


EVIDENCE: dict[str, EvidenceRecord] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_evidence() -> None:
    path = os.path.abspath(EVIDENCE_STORE_PATH)
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = EvidenceRecord.model_validate_json(line)
                EVIDENCE[rec.evidence_id] = rec
            except Exception as exc:
                logger.error(json.dumps({"event_type": "evidence_load_failed", "error": str(exc)}))


def _persist_evidence(rec: EvidenceRecord) -> None:
    path = os.path.abspath(EVIDENCE_STORE_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(rec.model_dump_json() + "\n")


def _classify_attack(text: str, explicit: str = "") -> str:
    token = (explicit or "").strip().lower().replace("-", "_")
    if token and (token in ATTACK_MITRE or token in _SCORE_WEIGHT):
        return token
    lowered = text.lower()
    for keyword, mapped in GRAFANA_ATTACK_KEYWORDS.items():
        if keyword in lowered:
            return mapped
    return "access_denied"


def _extract_source_ip(text: str) -> str | None:
    m = re.search(r'source_ip[=:"\s]+(\d{1,3}(?:\.\d{1,3}){3})', text)
    if m:
        return m.group(1)
    m = re.search(r"\b((?!10\.|127\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)"
                  r"\d{1,3}(?:\.\d{1,3}){3})\b", text)
    return m.group(1) if m else None


def _priority_score(attack_type: str, severity: str, bundle_lines: int) -> int:
    base = _SCORE_WEIGHT.get(attack_type, 15)
    sev_bonus = {"low": 0, "medium": 10, "high": 25, "critical": 40}.get(severity, 10)
    # volume bonus with diminishing returns
    vol_bonus = min(20, bundle_lines * 2)
    return max(0, min(100, base + sev_bonus + vol_bonus))


def _grafana_to_alert(alert_data: dict) -> GenericAlert | None:
    if alert_data.get("status", "firing") != "firing":
        return None
    labels = alert_data.get("labels", {})
    annotations = alert_data.get("annotations", {})
    # Skip infra/health alerts — they fire on the analyzer's own logs
    if labels.get("category", "") in ("health", "ops", "infrastructure"):
        return None

    severity = GRAFANA_SEVERITY_MAP.get(labels.get("severity", "medium").lower(), "medium")
    summary = annotations.get("summary", labels.get("alertname", "unknown alert"))
    desc = annotations.get("description", "")
    attack_type = _classify_attack(f"{summary} {desc} {labels.get('alertname', '')}",
                                   labels.get("attack_type", ""))
    source_ip = labels.get("source_ip") or annotations.get("source_ip") or _extract_source_ip(desc)
    affected = "crapi-identity" if labels.get("gap") == "gap1" else labels.get("affected_service")
    evidence = [e for e in [desc, f"fingerprint={alert_data.get('fingerprint', '')}"] if e and e != "fingerprint="]
    return GenericAlert(
        severity=severity,  # type: ignore[arg-type]
        attack_type=attack_type,
        summary=summary,
        mitre=labels.get("mitre", ATTACK_MITRE.get(attack_type, "")),
        source_ip=source_ip,
        affected_service=affected,
        evidence=evidence,
        ts=_now_iso(),
    )


async def _loki_range(query: str, start_ns: int, end_ns: int, limit: int) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=10) as h:
            resp = await h.get(
                f"{LOKI_URL}/loki/api/v1/query_range",
                params={"query": query, "start": start_ns, "end": end_ns,
                        "limit": limit, "direction": "backward"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning(json.dumps({"event_type": "loki_query_failed", "query": query, "error": str(exc)}))
        return []
    lines: list[str] = []
    for stream in data.get("data", {}).get("result", []):
        for _, raw in stream.get("values", []):
            lines.append(raw if len(raw) <= 1200 else raw[:1200] + "…")
            if len(lines) >= limit:
                return lines
    return lines


async def _collect_bundle(alert: GenericAlert) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Query Loki ±EVIDENCE_WINDOW_S around now for each evidence job + the
    attack-specific exact query. Returns (bundle, queries_used)."""
    end_ns = time.time_ns()
    start_ns = end_ns - EVIDENCE_WINDOW_S * 10 ** 9
    end_ns += EVIDENCE_WINDOW_S * 10 ** 9  # ±window

    bundle: dict[str, list[str]] = {}
    queries: dict[str, str] = {}

    for job in EVIDENCE_JOBS:
        q = '{job="%s"}' % job
        if alert.source_ip:
            q = f'{q} |~ "{re.escape(alert.source_ip)}"'
        queries[job] = q
        bundle[job] = await _loki_range(q, start_ns, end_ns, EVIDENCE_LIMIT_PER_JOB)

    exact = _EXACT_QUERY.get(alert.attack_type)
    if exact:
        queries["exact"] = exact
        bundle["exact"] = await _loki_range(exact, start_ns, end_ns, EVIDENCE_LIMIT_PER_JOB)

    return bundle, queries


def _bundle_html(rec: EvidenceRecord) -> str:
    sev_color = {"low": "#4CAF50", "medium": "#FF9800", "high": "#F44336",
                 "critical": "#9C27B0"}.get(rec.severity, "#F44336")
    sections = ""
    for job, lines in rec.bundle.items():
        items = "".join(
            f"<li style='font:11px monospace;color:#a8d8a8;word-break:break-all;margin-bottom:3px'>{_esc(l)}</li>"
            for l in lines[:12]
        ) or "<li style='color:#999'>(no matching log lines in window)</li>"
        sections += (
            f"<h4 style='margin:14px 0 6px;color:#333'>{_esc(job)} "
            f"<span style='font-weight:normal;color:#888'>({len(lines)} lines)</span></h4>"
            f"<ul style='background:#1e1e1e;border-radius:4px;padding:10px 10px 10px 16px;margin:0;list-style:none;overflow-x:auto'>{items}</ul>"
        )
    return f"""<div style="font-family:Arial,sans-serif;max-width:720px;margin:0 auto;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden">
  <div style="background:#1a1a2e;padding:18px 22px">
    <h2 style="color:#fff;margin:0;font-size:17px">🧾 ZTLab Incident Evidence Bundle</h2>
    <p style="color:#b8b8c8;margin:4px 0 0;font-size:12px">Detection &amp; analysis only — no automated response was taken.</p>
  </div>
  <div style="padding:20px 22px">
    <table style="width:100%;border-collapse:collapse;margin-bottom:16px;font-size:13px">
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold;width:150px">Alert</td><td style="padding:5px 10px">{_esc(rec.alert_name)}</td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Attack type</td><td style="padding:5px 10px"><code>{_esc(rec.attack_type)}</code></td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">MITRE ATT&amp;CK</td><td style="padding:5px 10px">{_esc(rec.mitre or '—')}</td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Severity</td><td style="padding:5px 10px"><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{rec.severity.upper()}</span></td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Priority score</td><td style="padding:5px 10px"><strong>{rec.priority_score}</strong> / 100</td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Source IP</td><td style="padding:5px 10px"><code>{_esc(rec.source_ip or '—')}</code></td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Affected service</td><td style="padding:5px 10px">{_esc(rec.affected_service or '—')}</td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Evidence ID</td><td style="padding:5px 10px"><code style="font-size:11px">{_esc(rec.evidence_id)}</code></td></tr>
      <tr><td style="padding:5px 10px;background:#f5f5f5;font-weight:bold">Window</td><td style="padding:5px 10px">±{rec.window_seconds}s around {_esc(rec.ts)}</td></tr>
    </table>
    <p style="font-size:13px;color:#555;margin:0 0 4px"><strong>Summary:</strong> {_esc(rec.summary)}</p>
    {sections}
    <p style="font-size:11px;color:#aaa;margin-top:16px">ZTLab Incident Analyzer · evidence <code>{_esc(rec.evidence_id)}</code> · this system does not execute containment actions.</p>
  </div>
</div>"""


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _send_email(rec: EvidenceRecord) -> bool:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[ZTLab — {rec.severity.upper()} · P{rec.priority_score}] {rec.alert_name} — evidence bundle"
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO
    msg.attach(MIMEText(_bundle_html(rec), "html", "utf-8"))
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.ehlo()
            if SMTP_STARTTLS:
                s.starttls()
                s.ehlo()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(MAIL_FROM, [MAIL_TO], msg.as_string())
        logger.info(json.dumps({"event_type": "evidence_email_sent", "evidence_id": rec.evidence_id,
                                "to": MAIL_TO, "smtp": f"{SMTP_HOST}:{SMTP_PORT}"}))
        return True
    except Exception as exc:
        logger.error(json.dumps({"event_type": "evidence_email_failed", "evidence_id": rec.evidence_id,
                                 "error": str(exc)}))
        return False


async def _push_summary_to_loki(rec: EvidenceRecord) -> None:
    line = json.dumps({"event_type": "evidence_bundle", "service": APP_NAME, **rec.model_dump(exclude={"bundle"})},
                      ensure_ascii=True)
    payload = {"streams": [{
        "stream": {"job": APP_NAME, "service": APP_NAME, "attack_type": rec.attack_type[:80],
                   "severity": rec.severity},
        "values": [[str(time.time_ns()), line]],
    }]}
    try:
        async with httpx.AsyncClient(timeout=10) as h:
            resp = await h.post(f"{LOKI_URL}/loki/api/v1/push", json=payload)
            resp.raise_for_status()
    except Exception as exc:
        logger.error(json.dumps({"event_type": "evidence_loki_push_failed", "evidence_id": rec.evidence_id,
                                 "error": str(exc)}))


async def _build_evidence(alert: GenericAlert, alert_name: str) -> EvidenceRecord:
    bundle, queries = await _collect_bundle(alert)
    line_count = sum(len(v) for v in bundle.values())
    attack = alert.attack_type
    rec = EvidenceRecord(
        evidence_id=f"ev-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}",
        ts=_now_iso(),
        alert_name=alert_name,
        attack_type=attack,
        mitre=alert.mitre or ATTACK_MITRE.get(attack, ""),
        severity=alert.severity,
        priority_score=_priority_score(attack, alert.severity, line_count),
        summary=alert.summary or ATTACK_DISPLAY.get(attack, attack.replace("_", " ").title()),
        source_ip=alert.source_ip or _extract_source_ip(" ".join(sum(bundle.values(), []))[:5000]),
        affected_service=alert.affected_service,
        window_seconds=EVIDENCE_WINDOW_S,
        loki_queries=queries,
        bundle=bundle,
        bundle_line_count=line_count,
    )
    rec.email_sent = _send_email(rec)
    EVIDENCE[rec.evidence_id] = rec
    _persist_evidence(rec)
    await _push_summary_to_loki(rec)
    EVIDENCE_BUNDLES.inc()
    LAST_PRIORITY_SCORE.set(rec.priority_score)
    logger.warning(json.dumps({"event_type": "evidence_bundle", "evidence_id": rec.evidence_id,
                               "attack_type": attack, "severity": rec.severity,
                               "priority_score": rec.priority_score, "bundle_lines": line_count,
                               "email_sent": rec.email_sent}))
    return rec


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup() -> None:
    _load_evidence()
    logger.info(json.dumps({"event_type": "incident_analyzer_started", "loki_url": LOKI_URL,
                            "smtp": f"{SMTP_HOST}:{SMTP_PORT}", "evidence_count": len(EVIDENCE)}))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "loki_url": LOKI_URL,
        "smtp": f"{SMTP_HOST}:{SMTP_PORT}",
        "mail_to": MAIL_TO,
        "evidence_window_seconds": EVIDENCE_WINDOW_S,
        "evidence_jobs": EVIDENCE_JOBS,
        "evidence_count": len(EVIDENCE),
        "response_capability": False,
    }


@app.post("/grafana-webhook")
async def grafana_webhook(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")

    firing = [a for a in payload.get("alerts", []) if a.get("status") == "firing"]
    if not firing:
        return {"processed": 0, "message": "no firing alerts"}

    out: list[dict[str, Any]] = []
    for alert_data in firing:
        alert = _grafana_to_alert(alert_data)
        if alert is None:
            continue
        alert_name = alert_data.get("labels", {}).get("alertname", alert.attack_type)
        rec = await _build_evidence(alert, alert_name)
        out.append({"evidence_id": rec.evidence_id, "attack_type": rec.attack_type,
                    "priority_score": rec.priority_score, "email_sent": rec.email_sent})
    return {"processed": len(out), "evidence": out}


@app.post("/alerts")
async def alerts(alert: GenericAlert) -> dict[str, Any]:
    alert.attack_type = _classify_attack(f"{alert.summary} {alert.attack_type}", alert.attack_type)
    rec = await _build_evidence(alert, ATTACK_DISPLAY.get(alert.attack_type, alert.attack_type))
    return {"evidence_id": rec.evidence_id, "attack_type": rec.attack_type,
            "priority_score": rec.priority_score, "email_sent": rec.email_sent}


@app.get("/evidence")
async def list_evidence() -> list[dict[str, Any]]:
    return [r.model_dump(exclude={"bundle"}) for r in list(EVIDENCE.values())[-100:]]


@app.get("/evidence/{evidence_id}", response_model=EvidenceRecord)
async def get_evidence(evidence_id: str) -> EvidenceRecord:
    rec = EVIDENCE.get(evidence_id)
    if not rec:
        raise HTTPException(status_code=404, detail="evidence not found")
    return rec


@app.post("/evidence/{evidence_id}/risk-score", response_model=EvidenceRecord)
async def attach_risk_score(evidence_id: str, risk: RiskScore) -> EvidenceRecord:
    """Reserved plug-in point for the Phase-C ML model: attach a risk score to an
    existing evidence record. This does not trigger any action."""
    rec = EVIDENCE.get(evidence_id)
    if not rec:
        raise HTTPException(status_code=404, detail="evidence not found")
    updated = rec.model_copy(update={"risk": risk})
    EVIDENCE[evidence_id] = updated
    _persist_evidence(updated)
    await _push_summary_to_loki(updated)
    logger.warning(json.dumps({"event_type": "risk_score_attached", "evidence_id": evidence_id,
                               "risk_score": risk.risk_score, "model": risk.model}))
    return updated


@app.get("/metrics")
async def metrics() -> Any:
    from fastapi.responses import Response
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
