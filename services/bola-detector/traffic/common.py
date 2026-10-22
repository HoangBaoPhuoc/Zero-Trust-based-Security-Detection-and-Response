# services/bola-detector/traffic/common.py
"""Tiện ích dùng chung cho các kịch bản traffic nền (Bước 2.3)."""
import json
import quopri
import re
import time
import urllib.request

import requests

BASE = "http://localhost:8888"
MAILHOG_API = "http://localhost:8025/api/v2/messages?limit=100"


def signup(name: str, email: str, number: str, password: str, retries: int = 3) -> dict:
    """crAPI tính user id kế tiếp bằng MAX(id)+1 không atomic (thấy trong cả
    identity lẫn workshop) -> đụng độ khoá chính khi 2 request signup gần
    nhau (race condition có THẬT của hệ thống, không phải lỗi script). Retry
    nhẹ để traffic-gen không bị chặn bởi lỗi hạ tầng ngoài ý muốn."""
    last_text = None
    for attempt in range(retries):
        r = requests.post(
            f"{BASE}/identity/api/auth/signup",
            json={"name": name, "email": email, "number": number, "password": password},
        )
        if r.status_code == 200:
            return r.json()
        last_text = r.text
        time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"signup thất bại sau {retries} lần cho {email}: {last_text}")


def login(email: str, password: str) -> str:
    r = requests.post(
        f"{BASE}/identity/api/auth/login",
        json={"email": email, "password": password},
    )
    r.raise_for_status()
    return r.json()["token"]


def get_vin_pincode_from_mailhog(email: str) -> tuple[str, str]:
    """Đọc email 'Welcome to crAPI' gửi lúc signup để lấy vin+pincode của xe
    được sinh sẵn cho tài khoản đó. Content-Transfer-Encoding: quoted-printable
    nên phải decode bằng quopri trước khi regex."""
    with urllib.request.urlopen(MAILHOG_API) as resp:
        data = json.load(resp)
    for item in data.get("items", []):
        to = item["Content"]["Headers"].get("To", [""])[0]
        if to != email:
            continue
        decoded = quopri.decodestring(item["Content"]["Body"].encode()).decode(errors="ignore")
        m_vin = re.search(r"VIN:\s*</font><font[^>]*>([A-Z0-9]{10,20})", decoded)
        m_pin = re.search(r"Pincode:\s*<font[^>]*>(\d{4,8})", decoded)
        if m_vin and m_pin:
            return m_vin.group(1), m_pin.group(1)
    raise RuntimeError(f"Không tìm thấy vin/pincode cho {email} trong Mailhog")


def add_vehicle(token: str, vin: str, pincode: str) -> dict:
    r = requests.post(
        f"{BASE}/identity/api/v2/vehicle/add_vehicle",
        headers={"Authorization": f"Bearer {token}"},
        json={"vin": vin, "pincode": pincode},
    )
    return r.json()


def get_vehicles(token: str) -> list[dict]:
    r = requests.get(
        f"{BASE}/identity/api/v2/vehicle/vehicles",
        headers={"Authorization": f"Bearer {token}"},
    )
    r.raise_for_status()
    return r.json()
