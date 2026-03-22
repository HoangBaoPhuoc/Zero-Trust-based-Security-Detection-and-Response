# ZTLab - fraud-detection
# Source: IMPLEMENTATION.md §6.5
# See MAP.md §10 for context and edit guidance

from fastapi import FastAPI
app = FastAPI(title="ZTLab Fraud Detection")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "fraud-detection", "cloud": "aws"}

# TODO: populate scorer logic from IMPLEMENTATION.md §6.5
