# services/bola-detector/traffic/benign_new_user_sparse_history.py
"""Hard negative #1: user MỚI đăng ký, hầu như không có lịch sử gọi API trước
đó -> nhiều 'cặp gọi chưa từng thấy' (unseen_identity_pair_count cao) dù hành
vi hoàn toàn hợp lệ (chỉ add xe của chính mình rồi xem vị trí 1 lần). Model
không được học nhầm 'ít lịch sử = tấn công'."""
import sys
import time
import uuid

sys.path.insert(0, ".")
from traffic.common import BASE, signup, login, get_vin_pincode_from_mailhog, add_vehicle
import requests


def run(email: str, name: str, number: str, password: str = "Newuser123@"):
    signup(name, email, number, password)
    time.sleep(1)  # chờ mail tới Mailhog
    vin, pincode = get_vin_pincode_from_mailhog(email)
    token = login(email, password)
    add_vehicle(token, vin, pincode)

    vehicles = requests.get(
        f"{BASE}/identity/api/v2/vehicle/vehicles",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    car_id = vehicles[0]["uuid"]
    requests.get(
        f"{BASE}/identity/api/v2/vehicle/{car_id}/location",
        headers={"Authorization": f"Bearer {token}"},
    )
    print(f"[benign/new_user] {email} xem đúng xe của mình ({car_id}) — 1 lần, entity gần như không có lịch sử")


if __name__ == "__main__":
    suffix = uuid.uuid4().hex[:6]
    run(f"sv2_newuser_{suffix}@test.local", f"New User {suffix}", f"09{suffix[:8].rjust(8,'0')}")
