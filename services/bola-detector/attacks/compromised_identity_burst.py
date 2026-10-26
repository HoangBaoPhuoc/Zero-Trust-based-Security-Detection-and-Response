# services/bola-detector/attacks/compromised_identity_burst.py
"""Attack run: hành vi DANH TÍNH BỊ CHIẾM DỤNG (compromised identity) — lớp
tấn công ML thứ 2 theo đề cương KLTN ("chỉ BOLA + hành vi danh tính bị chiếm
dụng"), CHƯA có script nào đại diện trước file này. Khác hẳn bola_vehicle_scan.py
(đối tượng truy cập KHÔNG thuộc quyền sở hữu của attacker): kịch bản này giả
lập 1 JWT hợp lệ của victim (giả định đã bị lộ qua kênh ngoài — log, XSS, thiết
bị công cộng... cơ chế lộ không phải trọng tâm mô phỏng ở đây) bị dùng lại với
hành vi lệch hẳn baseline của CHÍNH chủ tài khoản: burst request tốc độ máy chỉ
nhắm vào tài nguyên CỦA CHÍNH victim (vehicle/location, danh sách xe, bài đăng
cộng đồng) — KHÔNG đụng object_id của ai khác, nên không thể/không nên gán nhãn
BOLA (không vi phạm object-level authorization nào).

Tín hiệu phân biệt nằm ở Nhóm A (req_rate_per_min tăng đột biến so với baseline
thưa thớt của cùng entity_id — xem traffic/benign_new_user_sparse_history.py),
KHÔNG nằm ở object lạ (Nhóm B) như BOLA. Vì bản chất khác nhau, PHẢI gán
attack_class="COMPROMISED_IDENTITY" riêng, không gộp vào "BOLA" — nếu gộp
chung, ablation study (Bước 4, so sánh nhóm A/A+B) sẽ không tách được đóng góp
thật của từng nhóm đặc trưng cho từng lớp tấn công.

Không có endpoint riêng nào cho "compromised identity" vì bản chất đây là lệch
HÀNH VI trên chính API hợp lệ, không phải một lỗ hổng cụ thể — dùng lại nguyên
vẹn 3 endpoint đã xác nhận thật ở docs/crapi_api_map.md (Luồng 1 bước 1, 4;
Luồng 3 bước 2).
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
    victim_token: str,
    own_vehicle_id: str,
    out_meta_path: str,
    n_calls: int = 60,
    delay_seconds: float = 0.05,
) -> tuple[str, list[dict]]:
    """`n_calls` lần gọi gần như liên tục (`delay_seconds` mặc định 50ms — tốc
    độ script, không phải người dùng thật) xoay vòng qua 3 endpoint CHÍNH CHỦ
    được phép gọi. Không object_id nào ngoài phạm vi sở hữu của victim -> không
    phải BOLA. Bất thường duy nhất là TẦN SUẤT/BREADTH của cùng 1 danh tính so
    với baseline sparse của chính nó (đối lập trực tiếp với
    benign_new_user_sparse_history.py — cùng 1 entity, 2 chế độ hành vi khác
    hẳn nhau theo thời gian)."""
    attack_run_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {victim_token}",
        "X-Attack-Run-Id": attack_run_id,
    }
    endpoints = [
        ("GET", f"{BASE}/identity/api/v2/vehicle/{own_vehicle_id}/location"),
        ("GET", f"{BASE}/identity/api/v2/vehicle/vehicles"),
        ("GET", f"{BASE}/community/api/v2/community/posts/recent"),
    ]
    start = time.time()
    results = []
    for i in range(n_calls):
        method, url = endpoints[i % len(endpoints)]
        resp = requests.request(method, url, headers=headers)
        results.append({"path": url, "status": resp.status_code})
        time.sleep(delay_seconds)
    end = time.time()

    with open(out_meta_path, "a") as f:
        f.write(
            json.dumps(
                {
                    "attack_run_id": attack_run_id,
                    "attack_class": "COMPROMISED_IDENTITY",
                    "start_ts": start,
                    "end_ts": end,
                    "is_test_only_variant": False,
                }
            )
            + "\n"
        )
    return attack_run_id, results


if __name__ == "__main__":
    import sys

    victim_token = login("victim@test.local", "Victim123@")
    own_vehicle_id = sys.argv[1] if len(sys.argv) > 1 else None
    if not own_vehicle_id:
        print("Truyền vehicle uuid CỦA CHÍNH victim làm tham số, ví dụ:")
        print("  python3 attacks/compromised_identity_burst.py <own_vehicle_uuid>")
        sys.exit(1)

    attack_run_id, results = run_attack(
        victim_token, own_vehicle_id, "attacks/attack_runs_meta.jsonl"
    )
    print(f"attack_run_id={attack_run_id}, {len(results)} requests trong burst")
