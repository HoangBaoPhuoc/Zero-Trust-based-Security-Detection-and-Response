# ZTLab - api-gateway
# Source: IMPLEMENTATION.md §6.3
# See MAP.md §10 for context and edit guidance

from fastapi import FastAPI
app = FastAPI(title="ZTLab API Gateway")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "api-gateway", "cloud": "aws"}

# TODO: populate JWT verify + rate limit + routing from IMPLEMENTATION.md §6.3
