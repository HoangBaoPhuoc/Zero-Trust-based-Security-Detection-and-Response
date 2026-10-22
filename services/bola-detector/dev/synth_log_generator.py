# services/bola-detector/dev/synth_log_generator.py
"""Sinh log ZTLogEvent giả lập để phát triển/test feature extraction
trước khi có log thật từ Envoy+OPA. KHÔNG dùng file này để tạo dữ liệu
train cuối cùng — chỉ để kiểm thử logic code."""
import random
import uuid
from datetime import datetime, timedelta, timezone

IDENTITIES = [
    "spiffe://ztlab.local/crapi/web-frontend",
    "spiffe://ztlab.local/crapi/identity",
    "spiffe://ztlab.local/crapi/workshop",
    "spiffe://ztlab.local/crapi/community",
]
USERS = [f"user{i}@test.local" for i in range(20)]
VEHICLES = {u: f"veh-{i:05d}" for i, u in enumerate(USERS)}  # mỗi user sở hữu 1 xe


def _base_event(ts, session_id, user, path, object_id, decision="allow"):
    return dict(
        timestamp=ts.isoformat(),
        trace_id=str(uuid.uuid4())[:8],
        session_id=session_id,
        caller_identity="spiffe://ztlab.local/crapi/web-frontend",
        caller_jwt_subject=user,
        callee_identity="spiffe://ztlab.local/crapi/workshop",
        method="GET",
        path=path,
        object_id=object_id,
        response_code=200 if decision == "allow" else 403,
        response_time_ms=round(random.uniform(5, 40), 1),
        bytes_sent=random.randint(200, 2000),
        opa_decision=decision,
        opa_policy_matched="workshop-read-own-vehicle",
    )


def gen_benign_session(user, start_ts, n_calls=5):
    """User xem đúng xe của chính mình vài lần — hành vi bình thường."""
    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    ts = start_ts
    events = []
    for _ in range(n_calls):
        ts += timedelta(seconds=random.uniform(5, 60))
        events.append(_base_event(ts, session_id, user,
                                   f"/workshop/api/vehicle/{VEHICLES[user]}",
                                   VEHICLES[user]))
    return events


def gen_bola_attack_run(attacker, start_ts, n_distinct_victims=5):
    """Mô phỏng Challenge 1 của crAPI: attacker duyệt vehicle_id của
    NHIỀU user khác nhau liên tiếp, cách đều nhau (giống script tự động)."""
    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    ts = start_ts
    events = []
    victims = random.sample([u for u in USERS if u != attacker], n_distinct_victims)
    for v in victims:
        ts += timedelta(seconds=2)  # đều đặn — dấu hiệu script, khác hành vi người
        events.append(_base_event(ts, session_id, attacker,
                                   f"/workshop/api/vehicle/{VEHICLES[v]}",
                                   VEHICLES[v]))
    return events, {"attack_run_id": str(uuid.uuid4()), "attack_class": "BOLA",
                     "start": events[0]["timestamp"], "end": events[-1]["timestamp"]}


if __name__ == "__main__":
    import json
    now = datetime.now(timezone.utc)
    all_events = []
    for u in USERS:
        all_events += gen_benign_session(u, now)
    # +10 phút để chắc chắn session benign của USERS[0] (5 call x tối đa 60s = <=5 phút)
    # đã kết thúc hẳn trước khi attack run bắt đầu — tránh 2 session của CÙNG entity
    # chồng lấn trong 1 cửa sổ 5 phút, khiến quy tắc "loại cửa sổ vắt session" xoá mất
    # đúng cửa sổ cần quan sát (phát hiện khi chạy dev/sanity_check.py).
    atk_events, atk_meta = gen_bola_attack_run(USERS[0], now + timedelta(minutes=10))
    all_events += atk_events
    all_events.sort(key=lambda e: e["timestamp"])

    with open("services/bola-detector/dev/synth_events.jsonl", "w") as f:
        for e in all_events:
            f.write(json.dumps(e) + "\n")
    with open("services/bola-detector/dev/synth_attack_runs.jsonl", "w") as f:
        f.write(json.dumps(atk_meta) + "\n")
    print(f"Sinh {len(all_events)} events, 1 attack run → dev/synth_events.jsonl")
