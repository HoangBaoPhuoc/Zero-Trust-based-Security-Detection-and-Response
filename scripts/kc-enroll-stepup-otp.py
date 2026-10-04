"""Enroll OTP cho user `stepup-demo` — chạy TRONG pod kc-stepup-flow-setup (ns identity).

Mục 6 vòng 2026-09-29. Keycloak 24 không có Admin API "tạo OTP credential" cho
user. Thay vì bịa credential qua import, script này đi ĐÚNG luồng enroll của
Keycloak như người dùng thật trên trình duyệt:

  1. /protocol/openid-connect/auth (client crapi-bff-stepup, acr_values=high)
  2. POST username/password → Keycloak trả trang required action CONFIGURE_TOTP
     (user có requiredActions=[CONFIGURE_TOTP] từ realm-config.json)
  3. Đọc `totpSecret` (input ẩn của chính form đó — cùng bí mật mã hoá trong QR)
  4. Tính mã TOTP (RFC 6238, HmacSHA1, 6 số, 30 s — chính sách OTP mặc định realm)
     và POST form → Keycloak tự lưu credential OTP (userLabel = "deploy-enrolled")
  5. Dừng ở redirect về redirect_uri (không cần đổi code lấy token).

Idempotent:
  - user đã có credential otp VÀ biết secret (env OTP_SECRET khác rỗng) → bỏ qua.
  - user đã có otp nhưng không biết secret (Secret k8s bị mất) → xoá credential
    otp, gắn lại CONFIGURE_TOTP, enroll lại.

Env: KC_ADMIN_PASSWORD, OTP_SECRET (có thể rỗng), REDIRECT_URI.
Stdout: dòng cuối `OTP_SECRET=<secret>` (deploy script cất vào Secret k8s
identity/stepup-demo-otp; không in ra log deploy).
"""
import base64
import hashlib
import hmac
import html
import http.cookiejar
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC = "http://keycloak.identity.svc.cluster.local:8080"
REALM = "ztlab"
USER, PASSWORD = "stepup-demo", "StepupDemo123!"
CLIENT = "crapi-bff-stepup"
REDIRECT_URI = os.environ.get("REDIRECT_URI", "https://crapi.ztlab.local:18444/auth/callback")


def admin_headers() -> dict:
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli", "username": "admin",
                                   "password": os.environ["KC_ADMIN_PASSWORD"]}).encode()
    tok = json.load(urllib.request.urlopen(urllib.request.Request(
        KC + "/realms/master/protocol/openid-connect/token", data=data)))["access_token"]
    return {"Authorization": "Bearer " + tok}


def admin(method: str, path: str, body=None):
    req = urllib.request.Request(KC + f"/admin/realms/{REALM}" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={**admin_headers(), "Content-Type": "application/json"})
    raw = urllib.request.urlopen(req).read()
    return json.loads(raw) if raw else None


def totp(secret: str, t: float | None = None) -> str:
    # Keycloak dùng byte UTF-8 của chuỗi secret làm khoá HMAC (QR = base32 của chính các byte này)
    counter = int((t or time.time()) // 30)
    mac = hmac.new(secret.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def internal(url: str) -> str:
    # Keycloak dựng URL tuyệt đối theo KC_HOSTNAME (keycloak.ztlab.local:8180,
    # tên chỉ có nghĩa ở máy người dùng) — đổi về Service nội cụm, giữ path+query.
    u = urllib.parse.urlsplit(html.unescape(url))
    return KC + urllib.parse.urlunsplit(("", "", u.path, u.query, ""))


def fetch(op, url: str, data: bytes | None = None) -> tuple[str, str]:
    """Tự theo redirect nội bộ Keycloak; dừng khi Location trỏ về REDIRECT_URI.
    Trả ("page", html) hoặc ("redirect", location)."""
    for _ in range(10):
        try:
            return "page", op.open(url, data=data).read().decode()
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location") or ""
            if e.code not in (301, 302, 303) or not loc:
                raise RuntimeError(f"{url} -> HTTP {e.code}: {e.read().decode()[:300]}")
            if loc.startswith(REDIRECT_URI):
                return "redirect", loc
            url, data = internal(loc), None
    raise RuntimeError("quá nhiều redirect")


def form_action(page: str) -> str:
    m = re.search(r'<form[^>]+action="([^"]+)"', page)
    if not m:
        raise RuntimeError("không thấy <form action> trên trang Keycloak")
    return internal(m.group(1))


def main() -> int:
    uid = admin("GET", f"/users?username={USER}&exact=true")[0]["id"]
    creds = admin("GET", f"/users/{uid}/credentials")
    otp_creds = [c for c in creds if c["type"] == "otp"]
    known = os.environ.get("OTP_SECRET", "")
    if otp_creds and known:
        print("stepup-demo đã có OTP và secret đã lưu — bỏ qua")
        print(f"OTP_SECRET={known}")
        return 0
    for c in otp_creds:  # có credential nhưng mất secret → enroll lại
        admin("DELETE", f"/users/{uid}/credentials/{c['id']}")
    user = admin("GET", f"/users/{uid}")
    if "CONFIGURE_TOTP" not in user.get("requiredActions", []):
        user["requiredActions"] = user.get("requiredActions", []) + ["CONFIGURE_TOTP"]
        admin("PUT", f"/users/{uid}", user)

    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = urllib.parse.urlencode({"client_id": CLIENT, "response_type": "code", "scope": "openid",
                                "redirect_uri": REDIRECT_URI, "state": "enroll", "acr_values": "high",
                                "code_challenge": challenge, "code_challenge_method": "S256"})
    kind, page = fetch(op, f"{KC}/realms/{REALM}/protocol/openid-connect/auth?{q}")
    kind, page = fetch(op, form_action(page), urllib.parse.urlencode(
        {"username": USER, "password": PASSWORD, "credentialId": ""}).encode())
    m = re.search(r'name="totpSecret"\s+value="([^"]+)"', page) or re.search(r'id="totpSecret"[^>]*value="([^"]+)"', page)
    if kind != "page" or not m:
        raise RuntimeError("không thấy trang CONFIGURE_TOTP (totpSecret) sau khi đăng nhập stepup-demo: "
                           + re.sub(r"\s+", " ", page)[:300])
    secret = html.unescape(m.group(1))
    body = urllib.parse.urlencode({"totp": totp(secret), "totpSecret": secret, "mode": "",
                                   "userLabel": "deploy-enrolled"}).encode()
    kind, res = fetch(op, form_action(page), body)
    if kind != "redirect" or "code=" not in res:
        raise RuntimeError("Keycloak không redirect về redirect_uri sau khi nộp mã OTP (mã sai / hết hạn?): "
                           + re.sub(r"\s+", " ", res)[:300])
    creds = admin("GET", f"/users/{uid}/credentials")
    if not any(c["type"] == "otp" for c in creds):
        raise RuntimeError("Keycloak redirect nhưng user không có credential otp")
    print("stepup-demo: OTP enrolled qua luồng CONFIGURE_TOTP thật (credential otp 'deploy-enrolled')")
    print(f"OTP_SECRET={secret}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
