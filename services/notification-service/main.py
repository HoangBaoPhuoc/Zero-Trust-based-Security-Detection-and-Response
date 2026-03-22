# ZTLab - notification-service
# Source: IMPLEMENTATION.md §6
# See MAP.md §10 for context and edit guidance

from fastapi import FastAPI
app = FastAPI(title="ZTLab Notification Service")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "notification-service", "cloud": "aws"}
