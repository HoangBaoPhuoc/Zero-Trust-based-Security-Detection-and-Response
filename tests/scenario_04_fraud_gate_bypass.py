# ZTLab - scenario_04_fraud_gate_bypass
# Source: IMPLEMENTATION.md §15.3
# See MAP.md §17 for context and edit guidance

import requests

URL = "http://localhost:8080/transactions/execute"
PAYLOAD = {
    "from_account": "A001",
    "to_account": "A002",
    "amount": 100000,
    "currency": "VND"
}

# Missing X-Fraud-Gate on purpose
r = requests.post(URL, json=PAYLOAD, timeout=10)
print("status:", r.status_code)
print("body:", r.text)

# TODO: adapt endpoint and auth for deployed environment
