# services/bola-detector/dev/log_schema.py
from dataclasses import dataclass
from typing import Literal, Optional

@dataclass
class ZTLogEvent:
    timestamp: str              # ISO8601 UTC
    trace_id: str
    session_id: str
    caller_identity: str        # spiffe://... của workload gọi
    caller_jwt_subject: Optional[str]   # None nếu là workload-to-workload
    callee_identity: str        # spiffe://... của workload nhận
    method: str
    path: str                   # path thật, đã có ID cụ thể, không phải template
    object_id: Optional[str]    # trích từ path, None nếu endpoint không thao tác 1 object cụ thể
    response_code: int
    response_time_ms: float
    bytes_sent: int
    opa_decision: Literal["allow", "deny"]
    opa_policy_matched: Optional[str]
