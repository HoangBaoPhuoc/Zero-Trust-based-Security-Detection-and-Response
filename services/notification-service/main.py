# ZTLab - notification-service

from typing import Any
from fastapi import FastAPI
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP

SERVICE = "notification-service"
CLOUD = "aws"

app = FastAPI(title="ZTLab Notification Service")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)


class NotificationRequest(BaseModel):
    event: str
    trace_id: str = ""
    recipient: str | None = None
    transaction: dict[str, Any] = Field(default_factory=dict)


@app.post("/notify")
async def notify(body: NotificationRequest):
    logger.audit("notification_queued", event=body.event, trace_id=body.trace_id, recipient=body.recipient)
    return {"status": "queued", "service": SERVICE, "trace_id": body.trace_id}


@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE, "cloud": CLOUD}
