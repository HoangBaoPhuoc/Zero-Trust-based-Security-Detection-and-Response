# ZTLab - shared structured logging

import json
import logging
import sys
import time
import uuid
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware


logging.basicConfig(level=logging.INFO, format="%(message)s")


class ZTLabLogger:
    LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40, "AUDIT": 50}

    def __init__(self, service: str, cloud: str):
        self.service = service
        self.cloud = cloud

    def _emit(self, level: str, event: str, **kwargs: Any) -> None:
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "service": self.service,
            "cloud": self.cloud,
            "event": event,
            **kwargs,
        }
        stream = sys.stderr if level == "ERROR" else sys.stdout
        print(json.dumps(record, ensure_ascii=True, default=str), file=stream, flush=True)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._emit("DEBUG", event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._emit("INFO", event, **kwargs)

    def warn(self, event: str, **kwargs: Any) -> None:
        self._emit("WARN", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._emit("ERROR", event, **kwargs)

    def audit(self, event: str, **kwargs: Any) -> None:
        self._emit("AUDIT", event, **kwargs)


def trace_middleware(service: str, cloud: str) -> type[BaseHTTPMiddleware]:
    logger = ZTLabLogger(service, cloud)

    class TraceMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next: Callable):
            trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
            request.state.trace_id = trace_id
            start = time.time()
            try:
                response = await call_next(request)
            except Exception as exc:
                logger.error(
                    "request_failed",
                    trace_id=trace_id,
                    method=request.method,
                    path=request.url.path,
                    error=str(exc),
                )
                raise
            duration_ms = round((time.time() - start) * 1000, 2)
            bytes_sent = int(response.headers.get("content-length", 0))
            response.headers["X-Trace-ID"] = trace_id
            logger.info(
                "http_request",
                trace_id=trace_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
                bytes_sent=bytes_sent,
            )
            return response

    return TraceMiddleware
