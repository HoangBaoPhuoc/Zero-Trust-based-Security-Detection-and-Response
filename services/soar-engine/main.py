import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Header, HTTPException
from kubernetes import client, config
from kubernetes.client import ApiException
from pydantic import BaseModel, Field


APP_NAME = "soar-engine"
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100").rstrip("/")
SOAR_DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"
SOAR_AUTO_EXECUTE = os.getenv("SOAR_AUTO_EXECUTE", "true").lower() == "true"
SOAR_MIN_SEVERITY = os.getenv("SOAR_MIN_SEVERITY", "high").lower()
SOAR_NAMESPACE = os.getenv("SOAR_NAMESPACE", "financial")
SOAR_ALLOWED_CONTEXTS = {item.strip() for item in os.getenv("SOAR_ALLOWED_CONTEXTS", "ctx-aws,ctx-openstack").split(",") if item.strip()}
SOAR_API_TOKEN = os.getenv("SOAR_API_TOKEN", "").strip()
CASE_STORE_PATH = os.getenv("SOAR_CASE_STORE_PATH", "/data/cases.jsonl")

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TARGETS_BY_ATTACK = {
    "fraud_gate_bypass": {"context": "ctx-aws", "workload": "payment-service"},
    "lateral_movement": {"context": "ctx-openstack", "workload": "core-banking"},
    "large_response": {"context": "ctx-openstack", "workload": "core-banking"},
    "cryptomining": {"context": "ctx-openstack", "workload": "transaction-service"},
    "port_scan": {"context": "ctx-aws", "workload": "api-gateway"},
    "exploit_probe": {"context": "ctx-aws", "workload": "api-gateway"},
}
PLAYBOOK_BY_ATTACK = {
    "fraud_gate_bypass": "isolate_workload",
    "lateral_movement": "isolate_workload",
    "large_response": "restrict_egress",
    "cryptomining": "quarantine_workload",
    "port_scan": "isolate_workload",
    "exploit_probe": "isolate_workload",
}
ALLOWED_PLAYBOOKS = {"isolate_workload", "restrict_egress", "quarantine_workload", "monitor_only"}

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


class SecurityAlert(BaseModel):
    event_type: str = "ai_security_alert"
    analyzer: str = "ai-analyzer"
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
    log_count: int = 0
    log_hash: str | None = None
    ts: str | None = None


class CaseRecord(BaseModel):
    case_id: str
    status: Literal["skipped", "dry_run", "executed", "failed", "rolled_back", "rollback_failed"]
    alert_hash: str
    attack_type: str
    severity: str
    confidence: float
    playbook: str
    target_context: str | None = None
    target_namespace: str = SOAR_NAMESPACE
    target_workload: str | None = None
    action: str
    reason: str
    error: str | None = None
    dry_run: bool
    ts: str


CASES: dict[str, CaseRecord] = {}


def require_soar_token(authorization: str | None) -> None:
    if not SOAR_API_TOKEN:
        return
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
    for token in _attack_tokens(alert.attack_type):
        if token in PLAYBOOK_BY_ATTACK:
            return token
    return "unknown"


def _infer_target(alert: SecurityAlert, attack: str) -> dict[str, str | None]:
    target = dict(TARGETS_BY_ATTACK.get(attack, {}))
    if alert.affected_service:
        target["workload"] = alert.affected_service
    if not target.get("context"):
        text = " ".join(alert.evidence + [alert.summary, alert.recommended_action]).lower()
        target["context"] = "ctx-openstack" if "openstack" in text or "/os/" in text else "ctx-aws"
    return {"context": target.get("context"), "workload": target.get("workload")}


def _select_playbook(alert: SecurityAlert, attack: str) -> str:
    # SOAR uses deterministic playbook mapping for known attacks.
    # AI recommendations enrich the alert, but they do not downgrade a known response to monitor_only.
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


def _load_core_api(context: str | None) -> client.CoreV1Api:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config(context=context)
    return client.CoreV1Api()


def _load_apps_api(context: str | None) -> client.AppsV1Api:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config(context=context)
    return client.AppsV1Api()



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
    return "patched Service selector to isolate workload traffic"


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
    return f"scaled deployment from {current_replicas} to 0 replicas"


def rollback_playbook(case: CaseRecord) -> str:
    context = case.target_context
    workload = case.target_workload
    if not context or context not in SOAR_ALLOWED_CONTEXTS:
        raise ValueError(f"context {context!r} is not allowed")
    if not workload:
        raise ValueError("target workload is required")

    if case.playbook == "isolate_workload":
        api = _load_core_api(context)
        service = api.read_namespaced_service(name=workload, namespace=SOAR_NAMESPACE)
        annotations = service.metadata.annotations or {}
        raw_selector = annotations.get("soar.ztlab.io/original-selector")
        if not raw_selector:
            raise ValueError("original service selector annotation is missing")
        selector = json.loads(raw_selector)
        api.patch_namespaced_service(
            name=workload,
            namespace=SOAR_NAMESPACE,
            body={
                "metadata": {"annotations": {"soar.ztlab.io/rolled-back-at": _now_iso()}},
                "spec": {"selector": selector},
            },
        )
        return "restored original Service selector"

    if case.playbook in {"restrict_egress", "quarantine_workload"}:
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
        return f"restored deployment replicas to {replicas}"

    raise ValueError(f"playbook {case.playbook!r} has no rollback action")


def execute_playbook(playbook: str, context: str | None, workload: str | None) -> str:
    if playbook == "monitor_only":
        return "monitor only"
    if not context or context not in SOAR_ALLOWED_CONTEXTS:
        raise ValueError(f"context {context!r} is not allowed")
    if not workload:
        raise ValueError("target workload is required")

    if playbook == "isolate_workload":
        return _isolate_service(context, workload)

    if playbook == "restrict_egress":
        return _scale_deployment(context, workload, "suspected exfiltration")

    if playbook == "quarantine_workload":
        return _scale_deployment(context, workload, "suspected cryptomining or compromise")

    raise ValueError(f"unsupported playbook {playbook!r}")


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


@app.on_event("startup")
async def startup() -> None:
    load_cases()


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
        "auth_required": bool(SOAR_API_TOKEN),
    }


@app.get("/playbooks")
async def playbooks(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    require_soar_token(authorization)
    return {
        "thresholds": {"min_severity": SOAR_MIN_SEVERITY, "min_confidence": SOAR_MIN_CONFIDENCE},
        "dry_run": SOAR_DRY_RUN,
        "playbook_by_attack": PLAYBOOK_BY_ATTACK,
        "targets_by_attack": TARGETS_BY_ATTACK,
        "allowed_contexts": sorted(SOAR_ALLOWED_CONTEXTS),
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
    if case.status not in {"executed", "rollback_failed"}:
        raise HTTPException(status_code=409, detail=f"case status {case.status} is not rollbackable")
    try:
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

    status: Literal["skipped", "dry_run", "executed", "failed", "rolled_back", "rollback_failed"]
    action = "no action"
    error: str | None = None

    if playbook == "monitor_only" or not eligible:
        status = "skipped"
        reason = reason if playbook != "monitor_only" else f"no automated playbook for attack_type={alert.attack_type}"
    elif SOAR_DRY_RUN:
        status = "dry_run"
        action = f"would run {playbook} on {target.get('context')}/{SOAR_NAMESPACE}/{target.get('workload')}"
    else:
        try:
            action = execute_playbook(playbook, target.get("context"), target.get("workload"))
            status = "executed"
        except Exception as exc:
            status = "failed"
            error = str(exc)

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
        action=action,
        reason=reason,
        error=error,
        dry_run=SOAR_DRY_RUN,
        ts=_now_iso(),
    )
    result = await record_case(case)
    if result.status == "failed":
        raise HTTPException(status_code=500, detail=result.model_dump())
    return result
