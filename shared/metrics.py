# ZTLab - shared metrics
# Source: IMPLEMENTATION.md §6.1
# See MAP.md §9 for context and edit guidance

from prometheus_client import Counter

TXN_TOTAL = Counter('ztlab_transactions_total', 'Transaction counter', ['service', 'cloud', 'type', 'status'])

# TODO: populate full metrics set from IMPLEMENTATION.md §6.1
