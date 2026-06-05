# ZTLab - shared Prometheus metrics

from prometheus_client import Counter, Gauge, Histogram

TXN_TOTAL = Counter(
    "ztlab_transactions_total",
    "Transaction counter",
    ["service", "cloud", "type", "status"],
)
FRAUD_SCORE = Histogram(
    "ztlab_fraud_score",
    "Fraud score distribution",
    ["service", "cloud", "verdict"],
    buckets=(0, 20, 40, 60, 75, 90, 100),
)
CROSS_CLOUD_LATENCY = Histogram(
    "ztlab_cross_cloud_latency_seconds",
    "Cross-cloud request latency",
    ["source", "target", "status"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
AUTH_FAILURES = Counter(
    "ztlab_auth_failures_total",
    "Authentication or authorization failures",
    ["service", "cloud", "reason"],
)
SERVICE_UP = Gauge(
    "ztlab_service_up",
    "Service health indicator",
    ["service", "cloud"],
)
