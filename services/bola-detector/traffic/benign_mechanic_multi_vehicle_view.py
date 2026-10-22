# services/bola-detector/traffic/benign_mechanic_multi_vehicle_view.py
"""Hard negative #3 (thay cho 'admin xem nhiều vehicle' trong hướng dẫn gốc —
crAPI không có endpoint admin xem toàn bộ vehicle, nhưng MECHANIC xem
service_requests của nhiều khách hàng khác nhau là kịch bản tương đương hợp
lệ nhất có thật trong hệ thống): 1 mechanic nhận nhiều yêu cầu sửa xe từ
NHIỀU khách hàng khác nhau -> callee/entity mechanic có distinct_callee/
distinct_objects rất cao, nhưng hoàn toàn hợp lệ vì đó là vai trò của họ.
"""
import sys
import time
import uuid

sys.path.insert(0, ".")
from traffic.common import BASE, signup, login, get_vin_pincode_from_mailhog, add_vehicle
import requests


def contact_mechanic(user_token: str, mechanic_code: str, vin: str, problem: str):
    return requests.post(
        f"{BASE}/workshop/api/merchant/contact_mechanic",
        headers={"Authorization": f"Bearer {user_token}", "Content-Type": "application/json"},
        json={
            "mechanic_code": mechanic_code,
            "problem_details": problem,
            "vin": vin,
            "mechanic_api": f"https://crapi-workshop:8000/workshop/api/mechanic/receive_report",
            "repeat_request_if_failed": False,
            "number_of_repeats": 1,
        },
    )


def run(n_customers: int = 4):
    suffix = uuid.uuid4().hex[:6]
    mechanic_code = f"SV2M{suffix[:4].upper()}"
    mech_email = f"sv2_mech_{suffix}@test.local"

    requests.post(
        f"{BASE}/workshop/api/mechanic/signup",
        json={
            "name": "SV2 Mechanic",
            "email": mech_email,
            "number": f"0966{suffix[:4]}",
            "password": "Mechanic123@",
            "mechanic_code": mechanic_code,
        },
    )

    vins = []
    for i in range(n_customers):
        email = f"sv2_customer_{suffix}_{i}@test.local"
        signup(f"Customer {i}", email, f"0944{suffix[:4]}{i:02d}", "Customer123@")
        time.sleep(1)
        vin, pincode = get_vin_pincode_from_mailhog(email)
        token = login(email, "Customer123@")
        add_vehicle(token, vin, pincode)
        contact_mechanic(token, mechanic_code, vin, f"Kiem tra dinh ky lan {i}")
        vins.append(vin)

    mech_token = login(mech_email, "Mechanic123@")
    resp = requests.get(
        f"{BASE}/workshop/api/mechanic/service_requests",
        headers={"Authorization": f"Bearer {mech_token}"},
    ).json()
    seen_vins = {sr["vehicle"]["vin"] for sr in resp.get("service_requests", [])}
    print(f"[benign/mechanic_multi_vehicle] mechanic {mechanic_code} xem hợp lệ "
          f"{len(seen_vins)} xe khác nhau trong 1 lần gọi: {seen_vins}")


if __name__ == "__main__":
    run()
