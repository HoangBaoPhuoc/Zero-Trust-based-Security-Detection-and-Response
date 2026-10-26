# services/bola-detector/traffic/benign_multi_vehicle_owner.py
"""Hard negative #2: 1 user sở hữu THẬT nhiều xe (ví dụ gia đình đứng tên
nhiều xe dưới 1 tài khoản), truy cập nhiều object_id (vehicle_id) hợp lệ
trong CÙNG 1 session. Bề ngoài giống hệt attacker ở đặc trưng
'distinct_objects_per_session' cao — nhưng hoàn toàn hợp lệ vì user thực sự
sở hữu (biết đúng vin+pincode) từng xe. Đây là ca khó nhất cho Nhóm B."""
import sys
import time
import uuid

sys.path.insert(0, ".")
from traffic.common import BASE, signup, login, get_vin_pincode_from_mailhog, add_vehicle
import requests


def run(n_vehicles: int = 3):
    suffix = uuid.uuid4().hex[:6]

    # 1. Tạo n_vehicles tài khoản "nguồn" chỉ để lấy vin+pincode hợp lệ
    #    (mô phỏng việc user thật đã mua n xe riêng lẻ và biết đủ giấy tờ từng xe).
    vin_pincodes = []
    for i in range(n_vehicles):
        email = f"sv2_carsource_{suffix}_{i}@test.local"
        signup(f"Car Source {i}", email, f"0977{suffix[:4]}{i:02d}", "Source123@")
        time.sleep(1)
        vin_pincodes.append(get_vin_pincode_from_mailhog(email))

    # 2. Tài khoản chủ sở hữu thật, add_vehicle từng chiếc trong 1 session.
    owner_email = f"sv2_multiowner_{suffix}@test.local"
    signup("Multi Vehicle Owner", owner_email, f"0988{suffix[:4]}", "Owner123@")
    token = login(owner_email, "Owner123@")

    added_ids = []
    for vin, pincode in vin_pincodes:
        add_vehicle(token, vin, pincode)
    vehicles = requests.get(
        f"{BASE}/identity/api/v2/vehicle/vehicles",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    for v in vehicles:
        added_ids.append(v["uuid"])
        requests.get(
            f"{BASE}/identity/api/v2/vehicle/{v['uuid']}/location",
            headers={"Authorization": f"Bearer {token}"},
        )

    print(f"[benign/multi_vehicle_owner] {owner_email} sở hữu hợp lệ {len(added_ids)} xe, "
          f"xem vị trí cả {len(added_ids)} xe trong 1 session: {added_ids}")


if __name__ == "__main__":
    run()
