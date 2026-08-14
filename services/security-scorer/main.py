"""
ZTLab Security Scorer — thay thế AI Analyzer.

Nhận events từ các services, lưu vào Redis sorted-set với window 15 phút,
tính anomaly score 0-100 theo rule-based heuristics, expose Prometheus metrics.
"""
import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST

APP = "security-scorer"
REDIS_URL = os.getenv("REDIS_URL", "redis://redis.financial.svc.cluster.local:6379/1")
WINDOW_SECONDS = int(os.getenv("SCORER_WINDOW_SECONDS", "900"))   # 15 phút
SCORE_INTERVAL = int(os.getenv("SCORER_INTERVAL_SECONDS", "30"))  # tính lại mỗi 30s
REDIS_KEY = "scorer:events"
MAX_EVENTS_STORED = int(os.getenv("SCORER_MAX_EVENTS", "2000"))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger(APP)

redis_client: aioredis.Redis | None = None

# Prometheus metrics
ANOMALY_SCORE = Gauge("ztlab_anomaly_score", "Anomaly score 0-100 (15-minute window)")
EVENT_COUNTER = Counter("ztlab_security_events_total", "Total security events received", ["event_type"])
PATTERN_COUNTER = Counter("ztlab_anomaly_patterns_total", "Matched anomaly patterns", ["pattern"])

# Rule patterns — (regex, pattern_name, weight)
RULES: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(brute.?force|account.?lock|too.?many.?attempt)\b", re.I), "brute_force", 30),
    (re.compile(r"fraud.gate.bypass|fraud_block", re.I), "fraud_gate_bypass", 40),
    (re.compile(r"lateral.move|invalid.*svid|spiffe.*den", re.I), "lateral_movement", 50),
    (re.compile(r"port.scan|nmap|masscan|syn.scan", re.I), "port_scan", 25),
    (re.compile(r"sqlmap|union.select|/etc/passwd|cmd=|powershell", re.I), "exploit_probe", 35),
    (re.compile(r"xmrig|cryptomin|stratum\+tcp", re.I), "cryptomining", 45),
    (re.compile(r"credential.stuf|multiple.usernames|common.password", re.I), "cred_stuffing", 30),
    (re.compile(r"bytes_sent[=: ]([1-9]\d{6,})", re.I), "data_exfil", 35),
    (re.compile(r"\b(401|403|denied|deny|forbidden|unauthorized)\b", re.I), "access_denied", 5),
    (re.compile(r"jwt.*replay|stolen.token|suspicious.*reuse", re.I), "jwt_replay", 25),
    (re.compile(r"container.escape|host.filesys|169\.254\.169\.254", re.I), "container_escape", 50),
]

app = FastAPI(title="ZTLab Security Scorer")

# In-memory cache of last computed score
_last_score: dict[str, Any] = {"score": 0, "breakdown": {}, "event_count": 0, "ts": ""}


class SecurityEvent(BaseModel):
    message: str
    event_type: str = "generic"
    service: str = ""
    cloud: str = "aws"
    source_ip: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class BulkEvents(BaseModel):
    events: list[SecurityEvent]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _score_events(events: list[dict]) -> dict[str, Any]:
    """Tính anomaly score từ danh sách events trong 15 phút."""
    pattern_counts: dict[str, int] = {}
    for ev in events:
        text = f"{ev.get('message', '')} {ev.get('event_type', '')}".strip()
        for pattern, name, _ in RULES:
            if pattern.search(text):
                pattern_counts[name] = pattern_counts.get(name, 0) + 1

    # Score: mỗi pattern có weight, count nhiều → tăng score nhưng bị diminishing returns
    total_score = 0.0
    breakdown: dict[str, dict] = {}
    for pattern, name, weight in RULES:
        count = pattern_counts.get(name, 0)
        if count == 0:
            continue
        # diminishing returns: log2 scale
        import math
        contribution = min(weight, weight * (1 + math.log2(count)) / 4)
        total_score += contribution
        breakdown[name] = {"count": count, "contribution": round(contribution, 1)}

    score = min(100, round(total_score))
    return {
        "score": score,
        "breakdown": breakdown,
        "event_count": len(events),
        "window_seconds": WINDOW_SECONDS,
        "ts": _now_iso(),
    }


async def _store_event(event: SecurityEvent) -> None:
    if redis_client is None:
        return
    ts = time.time()
    payload = json.dumps({
        "message": event.message,
        "event_type": event.event_type,
        "service": event.service,
        "cloud": event.cloud,
        "source_ip": event.source_ip,
        "ts": ts,
    })
    pipe = redis_client.pipeline()
    pipe.zadd(REDIS_KEY, {payload: ts})
    # Giữ tối đa MAX_EVENTS_STORED entries để không tràn bộ nhớ
    pipe.zremrangebyscore(REDIS_KEY, 0, ts - WINDOW_SECONDS)
    pipe.zremrangebyrank(REDIS_KEY, 0, -(MAX_EVENTS_STORED + 1))
    await pipe.execute()


async def _fetch_recent_events() -> list[dict]:
    if redis_client is None:
        return []
    cutoff = time.time() - WINDOW_SECONDS
    raw = await redis_client.zrangebyscore(REDIS_KEY, cutoff, "+inf")
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            pass
    return events


async def _score_loop() -> None:
    global _last_score
    await asyncio.sleep(5)
    while True:
        try:
            events = await _fetch_recent_events()
            result = _score_events(events)
            _last_score = result
            ANOMALY_SCORE.set(result["score"])
            logger.info(json.dumps({
                "event_type": "anomaly_score_computed",
                "score": result["score"],
                "event_count": result["event_count"],
                "patterns": list(result["breakdown"].keys()),
            }))
        except Exception as exc:
            logger.error(json.dumps({"event_type": "scorer_error", "error": str(exc)}))
        await asyncio.sleep(SCORE_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    global redis_client
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis_client.ping()
        logger.info(json.dumps({"event_type": "redis_connected", "url": REDIS_URL}))
    except Exception as exc:
        logger.error(json.dumps({"event_type": "redis_connect_failed", "error": str(exc)}))
    asyncio.create_task(_score_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    if redis_client:
        await redis_client.aclose()


@app.get("/health")
async def health() -> dict:
    redis_ok = False
    try:
        if redis_client:
            await redis_client.ping()
            redis_ok = True
    except Exception:
        pass
    return {
        "status": "ok",
        "service": APP,
        "redis": "ok" if redis_ok else "error",
        "current_score": _last_score.get("score", 0),
        "window_seconds": WINDOW_SECONDS,
    }


@app.post("/events", status_code=204)
async def receive_event(event: SecurityEvent) -> None:
    EVENT_COUNTER.labels(event_type=event.event_type).inc()
    # Match patterns to increment counters immediately
    text = f"{event.message} {event.event_type}"
    for pattern, name, _ in RULES:
        if pattern.search(text):
            PATTERN_COUNTER.labels(pattern=name).inc()
    await _store_event(event)


@app.post("/events/bulk", status_code=204)
async def receive_bulk(body: BulkEvents) -> None:
    for event in body.events:
        EVENT_COUNTER.labels(event_type=event.event_type).inc()
        await _store_event(event)


@app.get("/score")
async def get_score() -> dict:
    """Trả về anomaly score hiện tại và breakdown theo từng pattern."""
    if not _last_score.get("ts"):
        events = await _fetch_recent_events()
        result = _score_events(events)
        ANOMALY_SCORE.set(result["score"])
        return result
    return _last_score


@app.get("/events/recent")
async def recent_events(limit: int = 50) -> dict:
    """Trả về các events gần đây trong 15 phút."""
    events = await _fetch_recent_events()
    events.sort(key=lambda e: e.get("ts", 0), reverse=True)
    return {"events": events[:limit], "total": len(events), "window_seconds": WINDOW_SECONDS}


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    return generate_latest().decode("utf-8")
