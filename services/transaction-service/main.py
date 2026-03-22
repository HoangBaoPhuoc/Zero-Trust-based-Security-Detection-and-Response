# ZTLab - transaction-service
# Source: IMPLEMENTATION.md §6.8
# See MAP.md §10 for context and edit guidance

from fastapi import FastAPI
app = FastAPI(title="ZTLab Transaction Service")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "transaction-service", "cloud": "openstack"}

# TODO: populate ledger and stats logic from IMPLEMENTATION.md §6.8
