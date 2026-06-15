# ZTLab - notification-service

import asyncio
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from fastapi import FastAPI
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import SERVICE_UP

SERVICE = "notification-service"
CLOUD = "aws"

SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASS     = os.getenv("SMTP_PASS", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "noreply@ztlab.local")
SMTP_ENABLED  = bool(SMTP_HOST and SMTP_USER and SMTP_PASS)

app = FastAPI(title="ZTLab Notification Service")
app.add_middleware(trace_middleware(SERVICE, CLOUD))
app.mount("/metrics", make_asgi_app())
logger = ZTLabLogger(SERVICE, CLOUD)
SERVICE_UP.labels(service=SERVICE, cloud=CLOUD).set(1)


class NotificationRequest(BaseModel):
    event: str
    trace_id: str = ""
    recipient: str | None = None
    recipient_email: str | None = None
    sender_name: str | None = None
    transaction: dict[str, Any] = Field(default_factory=dict)


def _build_transfer_email(req: NotificationRequest) -> tuple[str, str]:
    txn = req.transaction
    txn_id   = txn.get("transaction_id") or req.trace_id or "N/A"
    amount   = txn.get("amount", 0)
    currency = txn.get("currency", "VND")
    from_acc = txn.get("from_account", "")
    to_acc   = txn.get("to_account", "")
    new_bal  = txn.get("from_balance", "")
    sender   = req.sender_name or from_acc or "người dùng"

    amount_fmt = f"{float(amount):,.0f}" if amount else "N/A"
    bal_fmt    = f"{float(new_bal):,.0f} {currency}" if new_bal != "" else "—"

    subject = f"[ZTLab] Chuyển tiền thành công — {amount_fmt} {currency}"
    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:32px 16px">
    <table width="560" cellpadding="0" cellspacing="0"
           style="background:#161b22;border-radius:12px;overflow:hidden;border:1px solid #30363d">

      <!-- Header -->
      <tr>
        <td style="background:linear-gradient(135deg,#1a3a5c,#0d2137);padding:28px 32px;text-align:center">
          <div style="font-size:28px;margin-bottom:8px">🏦</div>
          <div style="color:#58a6ff;font-size:20px;font-weight:700">ZTLab Banking</div>
          <div style="color:#8b949e;font-size:13px;margin-top:4px">Xác nhận giao dịch</div>
        </td>
      </tr>

      <!-- Success banner -->
      <tr>
        <td style="background:#0d2a0d;padding:16px 32px;text-align:center;border-bottom:1px solid #238636">
          <span style="color:#3fb950;font-size:16px;font-weight:600">✅ Chuyển tiền thành công</span>
        </td>
      </tr>

      <!-- Body -->
      <tr>
        <td style="padding:28px 32px">
          <p style="color:#c9d1d9;font-size:15px;margin:0 0 20px">
            Xin chào <strong style="color:#58a6ff">{sender}</strong>,
          </p>
          <p style="color:#8b949e;font-size:14px;margin:0 0 24px">
            Giao dịch của bạn đã được xử lý thành công qua hệ thống Zero Trust Security.
          </p>

          <!-- Transaction details box -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#0d1117;border:1px solid #30363d;border-radius:8px;margin-bottom:24px">
            <tr>
              <td style="padding:16px 20px;border-bottom:1px solid #21262d">
                <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Mã giao dịch</div>
                <div style="color:#f0f6fc;font-size:13px;font-family:monospace">{txn_id}</div>
              </td>
            </tr>
            <tr>
              <td style="padding:16px 20px;border-bottom:1px solid #21262d">
                <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Số tiền chuyển</div>
                <div style="color:#3fb950;font-size:22px;font-weight:700">{amount_fmt} {currency}</div>
              </td>
            </tr>
            <tr>
              <td style="padding:12px 20px;border-bottom:1px solid #21262d">
                <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Từ tài khoản</div>
                <div style="color:#c9d1d9;font-size:14px;font-family:monospace">{from_acc}</div>
              </td>
            </tr>
            <tr>
              <td style="padding:12px 20px;border-bottom:1px solid #21262d">
                <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Đến tài khoản</div>
                <div style="color:#c9d1d9;font-size:14px;font-family:monospace">{to_acc}</div>
              </td>
            </tr>
            <tr>
              <td style="padding:12px 20px">
                <div style="color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Số dư sau giao dịch</div>
                <div style="color:#c9d1d9;font-size:14px">{bal_fmt}</div>
              </td>
            </tr>
          </table>

          <!-- Security badge -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#0d1f3a;border:1px solid #1f6feb;border-radius:8px;margin-bottom:24px">
            <tr>
              <td style="padding:14px 20px">
                <div style="color:#58a6ff;font-size:13px">
                  🔐 <strong>Được xác thực bởi Zero Trust Security</strong><br>
                  <span style="color:#8b949e;font-size:12px;margin-top:4px;display:block">
                    OPA Policy ✓ &nbsp;|&nbsp; SPIRE mTLS ✓ &nbsp;|&nbsp; Fraud Detection ✓ &nbsp;|&nbsp; JWT (Keycloak) ✓
                  </span>
                </div>
              </td>
            </tr>
          </table>

          <p style="color:#8b949e;font-size:12px;margin:0">
            Nếu bạn không thực hiện giao dịch này, vui lòng liên hệ hỗ trợ ngay lập tức.
          </p>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#0d1117;padding:16px 32px;text-align:center;border-top:1px solid #21262d">
          <div style="color:#484f58;font-size:11px">ZTLab Banking — Hệ thống Zero Trust Security</div>
          <div style="color:#484f58;font-size:11px;margin-top:4px">Email tự động — Không trả lời email này</div>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>
"""
    return subject, html


def _smtp_send(to: str, subject: str, html: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = to
    msg.attach(MIMEText(html, "html", "utf-8"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(SMTP_FROM, [to], msg.as_string())


async def _send_email_async(to: str, subject: str, html: str) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _smtp_send, to, subject, html)


@app.post("/notify")
async def notify(body: NotificationRequest):
    logger.audit(
        "notification_queued",
        notification_event=body.event,
        trace_id=body.trace_id,
        recipient=body.recipient,
        smtp_enabled=SMTP_ENABLED,
    )

    if body.event == "payment_completed":
        email_to = body.recipient_email or body.recipient
        if SMTP_ENABLED and email_to and "@" in email_to:
            subject, html = _build_transfer_email(body)
            try:
                await _send_email_async(email_to, subject, html)
                logger.audit(
                    "email_sent",
                    notification_event=body.event,
                    trace_id=body.trace_id,
                    recipient_email=email_to,
                )
            except Exception as exc:
                logger.warn(
                    "email_send_failed",
                    notification_event=body.event,
                    trace_id=body.trace_id,
                    recipient_email=email_to,
                    error=str(exc),
                )
        else:
            logger.info(
                "email_skipped",
                reason="smtp_not_configured" if not SMTP_ENABLED else "no_email_address",
                trace_id=body.trace_id,
            )

    return {"status": "queued", "service": SERVICE, "trace_id": body.trace_id}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": SERVICE,
        "cloud": CLOUD,
        "smtp_enabled": SMTP_ENABLED,
        "smtp_host": SMTP_HOST if SMTP_ENABLED else None,
    }
