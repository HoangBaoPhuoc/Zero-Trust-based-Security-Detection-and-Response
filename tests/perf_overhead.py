#!/usr/bin/env python3
"""ZTLab Performance Overhead Benchmark v2 — crAPI (Phần 2.1, remediation
2026-09-19, xem BAOCAO-VONG-2026-09-19.md mục 2.1 cho toàn bộ diễn giải).

Bản Phần 1.4 (2026-09-18, đã XOÁ) đo SAI: cặp `crapi-community -> crapi-
workshop` KHÔNG có entry trong `service_acl` (chỉ có `crapi-community ->
crapi-identity` và `crapi-workshop -> crapi-identity`, không có entry nào
giữa community/workshop với nhau) — verify sống 2026-09-19 xác nhận: request
`via_mesh` của bản cũ nhận **403**, decision log OPA ghi
`"result":false` cho đúng path `/workshop/api/shop/products`. Nghĩa là toàn
bộ số "overhead" 1.04ms trước đây là latency của MỘT REQUEST BỊ TỪ CHỐI
(Envoy cắt sớm ở ext_authz), không phải request thật đi hết đường xử lý.
Hai sai sót thêm (cùng phát hiện, sửa luôn): (1) `bypass_mesh` gọi `localhost`
(loopback) — không phải "cùng đường mạng, chỉ khác mesh"; (2) hop cũ hoàn
toàn bỏ qua `keycloak_gate` (theo `opa/crapi-policies/zta_crapi.rego`, chỉ
kích hoạt khi nguồn là `bff` VÀ có JWT thật — `io.jwt.decode_verify` RS256 —
phần tính toán đắt nhất của cả policy).

Bản v2 đo cặp ĐƯỢC PHÉP theo `service_acl`: `bff -> crapi-workshop`
(`GET /workshop/api/shop/products`, có trong service_acl), dùng JWT Keycloak
THẬT (testuser01, header `X-Access-Token` — đúng header OPA đọc), 3 cấu hình
trên CÙNG một cặp, CÙNG đường mạng thật (không loopback):

  (1) full     : mТLS STRICT + OPA ext_authz (crapi-workshop-opa-authz) — y
                 nguyên cấu hình sống.
  (2) mtls_only: xoá TẠM AuthorizationPolicy `crapi-workshop-opa-authz` (áp
                 lại ngay sau khi đo xong) — giữ nguyên sidecar/PeerAuthentication
                 STRICT, chỉ bỏ vòng gọi ext_authz.
  (A0) app_only  : client chạy TRONG pod crapi-workshop gọi 127.0.0.1:8000 — loopback
                 bị iptables Istio bỏ qua, không Envoy, không mạng: thời gian xử lý của app.
                 KHÔNG đo được "không mesh" trên cùng cặp: crapi-workshop CrashLoopBackOff
                 nếu thiếu sidecar (cần mТLS tới identity; đo 2026-09-26 với cả tắt
                 injection lẫn excludeInboundPorts). => báo CẬN TRÊN overhead = (1) − (A0),
                 gồm cả độ trễ mạng pod-to-pod; nếu cận trên ≤ 20ms p99 thì ngưỡng đề cương
                 chắc chắn đạt. (1)−(2) xấp xỉ chi phí OPA ext_authz.
Client đo chạy trong container ứng dụng `bff` (python), KHÔNG phải curl trong `istio-proxy`
(uid 1337 bị iptables RETURN khỏi Envoy => plaintext vào STRICT mTLS => reset; xem
BAOCAO-CUOI-2026-09-26.md mục 2.3).

MỌI thay đổi cấu hình để đo (client Keycloak, AuthorizationPolicy, sidecar
injection) đều được HOÀN NGUYÊN trong khối `finally` + xác nhận lại bằng
`kubectl diff`/`kubectl get` khớp lại cấu hình nguồn ngay sau khi đo xong,
kể cả khi script bị ngắt giữa chừng (Ctrl-C) — restore chạy trong finally.

Usage:
  python3 tests/perf_overhead.py [--n 60] [--warmup 10] [--output results/perf_overhead.json]
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AWS_CTX = "ctx-aws"
NS = "crapi"
LOKI_URL = "http://localhost:13100"
TARGET_PATH = "/workshop/api/shop/products"
WORKSHOP_SVC_URL = f"http://crapi-workshop.{NS}.svc.cluster.local:8000{TARGET_PATH}"
TEST_USER = "testuser01"
TEST_USER_EMAIL = f"{TEST_USER}@ztlab.local"
# LƯU Ý (bug thật gặp khi chạy lần đầu 2026-09-19): "CrapiSeed123!" (Secret
# crapi-seed) là mật khẩu của user trong DB identity NỘI BỘ của crAPI (seed-job.yaml,
# KHÔNG liên quan Keycloak). Mật khẩu THẬT của testuser01 trong Keycloak nằm ở
# k8s/keycloak/realm-config.json ("Test1234!") — 2 kho danh tính khác nhau,
# nhầm cái này gây token endpoint trả 401 dù grant đã bật đúng.
TEST_USER_PASS = "Test1234!"  # k8s/keycloak/realm-config.json — user Keycloak testuser01
KC_ADMIN_SETUP_OVERRIDES = (
    '{"metadata":{"labels":{"app":"kc-admin-setup"},'
    '"annotations":{"sidecar.istio.io/userVolume":'
    '"[{\\"name\\":\\"spire-workload-socket\\",\\"hostPath\\":{\\"path\\":\\"/run/spire/sockets/agent.sock\\",\\"type\\":\\"Socket\\"}}]",'
    '"sidecar.istio.io/userVolumeMount":'
    '"[{\\"name\\":\\"spire-workload-socket\\",\\"mountPath\\":\\"/var/run/secrets/workload-spiffe-uds/socket\\"}]"}},'
    '"spec":{"serviceAccountName":"kc-admin-setup"}}'
)
OS_CTX = "ctx-openstack"


def _run(cmd: list[str], timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and out.returncode != 0:
        raise RuntimeError(f"lệnh thất bại: {' '.join(shlex.quote(c) for c in cmd)}\n{out.stderr}")
    return out


def _pod(app: str, ctx: str = AWS_CTX) -> str:
    out = _run(["kubectl", "--context", ctx, "-n", NS, "get", "pod", "-l", f"app={app}",
                "-o", "jsonpath={.items[0].metadata.name}"])
    pod = out.stdout.strip()
    if not pod:
        raise RuntimeError(f"không tìm được pod app={app} trên {ctx}")
    return pod


# Client đo chạy BẰNG PYTHON TRONG CONTAINER (không dùng curl trong `istio-proxy`).
# Vòng cuối 2026-09-26 — SỬA LỖI CÔNG CỤ ĐO gây "connection reset by peer" ở v2:
# container `istio-proxy` chạy uid 1337 và iptables Istio có
# `-A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN`, tức traffic của nó KHÔNG đi
# qua Envoy client -> plaintext vào đích STRICT mTLS -> bị reset. Client phải là
# container ứng dụng (uid != 1337) để request đi qua sidecar (mTLS + SPIFFE thật).
# DNS được resolve MỘT LẦN ngoài vòng đo (không cộng độ trễ DNS vào từng request);
# mỗi request mở kết nối mới và đo bằng perf_counter quanh request+đọc hết body.
_PY_CLIENT = (
    "import sys,socket,http.client,time,json\n"
    "host,port,path,n,hdrs=sys.argv[1],int(sys.argv[2]),sys.argv[3],int(sys.argv[4]),json.loads(sys.argv[5])\n"
    "ip=socket.gethostbyname(host)\n"
    "for _ in range(n):\n"
    "    t=time.perf_counter()\n"
    "    try:\n"
    "        c=http.client.HTTPConnection(ip,port,timeout=10)\n"
    "        h=dict(hdrs); h['Host']=host+':'+str(port)\n"
    "        c.request('GET',path,headers=h); r=c.getresponse(); r.read(); code=str(r.status); c.close()\n"
    "    except Exception as e:\n"
    "        code=type(e).__name__\n"
    "    print(code, (time.perf_counter()-t)*1000)\n"
)


def _run_in_pod(pod: str, container: str, url: str, n: int, ctx: str = AWS_CTX,
                 headers: dict[str, str] | None = None) -> tuple[list[float], list[str]]:
    u = urllib.parse.urlparse(url)
    port = u.port or 80
    out = subprocess.run(
        ["kubectl", "--context", ctx, "-n", NS, "exec", pod, "-c", container, "--",
         "python", "-c", _PY_CLIENT, u.hostname, str(port), u.path or "/", str(n), json.dumps(headers or {})],
        capture_output=True, text=True, timeout=120 + n,
    )
    if out.returncode != 0:
        raise RuntimeError(f"kubectl exec thất bại (pod={pod}): {out.stderr.strip()[:400]}")
    times, codes = [], []
    for line in out.stdout.strip().splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        codes.append(parts[0])
        try:
            times.append(float(parts[1]))
        except ValueError:
            continue
    return times, codes


# Đóng sổ 2026-10-04 — JWT Keycloak (TTL 300 s) HẾT HẠN GIỮA LƯỢT là lý do lượt 2 ngày 2026-09-30 có
# 320 × 200 rồi 1730 × 403 (cùng lớp lỗi H16, lần này trong công cụ đo). Chạy theo LÔ, mỗi lô ngắn hơn
# TTL; trước mỗi lô xin JWT mới nếu token đã quá BATCH_TOKEN_MAX_AGE_S. Khoảng nghỉ giữa các lô (kubectl
# exec, xin token) nằm NGOÀI vòng đo nên không cộng vào độ trễ.
BATCH_SIZE = int(os.environ.get("PERF_BATCH_SIZE", "150"))
BATCH_TOKEN_MAX_AGE_S = 150


def _run_batched(pod: str, container: str, url: str, total: int, header_fn, ctx: str = AWS_CTX
                 ) -> tuple[list[float], list[str]]:
    times, codes = [], []
    left = total
    while left > 0:
        k = min(BATCH_SIZE, left)
        t, c = _run_in_pod(pod, container, url, k, ctx=ctx, headers=header_fn())
        times += t; codes += c; left -= k
    return times, codes


# ── Vòng 2026-09-29 (mục 9): CFS throttling của các container trên đường đo ──
# OPA (limit 200m) bị throttle ngay cả lúc nhàn rỗi, mỗi lần ~90 ms (cpu.stat
# của cgroup, đọc qua SSH node). Client đo chạy trong `bff` (limit 300m) — nếu
# chính client bị throttle thì (1)/(2) bị thổi phồng mà (A0) thì không. Mỗi cấu
# hình ghi delta nr_throttled/throttled_usec trước/sau để tách nhiễu này.
SSH_KEY = str(Path.home() / ".ssh" / "ztlab-key")
THROTTLE_TARGETS = (("opa", "opa"), ("bff", "bff"), ("crapi-workshop", "crapi-workshop"))


def _aws_bastion() -> str:
    import re
    txt = (REPO_ROOT / "ansible" / "inventory" / "hosts.yml").read_text()
    m = re.search(r"aws_bastion:\s*\n\s*ansible_host:\s*([0-9.]+)", txt)
    return m.group(1) if m else ""


def _cfs_snapshot() -> dict:
    """{"<pod>/<container>": {"nr_throttled": int, "throttled_usec": int}} — rỗng nếu SSH lỗi."""
    bastion = _aws_bastion()
    snap: dict = {}
    for app, cname in THROTTLE_TARGETS:
        out = _run(["kubectl", "--context", AWS_CTX, "-n", NS, "get", "pod", "-l", f"app={app}", "-o", "json"],
                   check=False)
        if out.returncode != 0:
            continue
        for pod in json.loads(out.stdout)["items"]:
            cid = next((c["containerID"].split("//")[1] for c in pod["status"].get("containerStatuses", [])
                        if c["name"] == cname and c.get("containerID")), None)
            if not cid:
                continue
            cmd = (f"f=$(sudo find /sys/fs/cgroup -maxdepth 6 -type d -name '*{cid}*' | head -1); "
                   f"sudo grep -E 'nr_throttled|throttled_usec' $f/cpu.stat")
            r = subprocess.run(["ssh", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no",
                                "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-i", SSH_KEY,
                                "-J", f"ubuntu@{bastion}", f"ubuntu@{pod['status']['hostIP']}", cmd],
                               capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            vals = dict(ln.split() for ln in r.stdout.strip().splitlines() if len(ln.split()) == 2)
            if vals:
                snap[f"{pod['metadata']['name']}/{cname}"] = {k: int(v) for k, v in vals.items()}
    return snap


def _cfs_delta(before: dict, after: dict) -> dict:
    out = {}
    for k, a in after.items():
        b = before.get(k)
        if b:
            out[k] = {"nr_throttled": a["nr_throttled"] - b["nr_throttled"],
                      "throttled_ms": round((a["throttled_usec"] - b["throttled_usec"]) / 1000, 1)}
    return out


def histogram(latencies_ms: list[float], bin_ms: float = 0.5, cap_ms: float = 200.0) -> dict:
    """Histogram thô (bin 0,5 ms tới 200 ms + tràn) để vẽ phân phối trong luận văn."""
    bins: dict[str, int] = {}
    over = 0
    for v in latencies_ms:
        if v >= cap_ms:
            over += 1
            continue
        k = f"{int(v // bin_ms) * bin_ms:.1f}"
        bins[k] = bins.get(k, 0) + 1
    return {"bin_ms": bin_ms, "cap_ms": cap_ms, "counts": dict(sorted(bins.items(), key=lambda kv: float(kv[0]))),
            "overflow": over}


def percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def stats_of(latencies_ms: list[float]) -> dict:
    if not latencies_ms:
        return {"error": "no samples"}
    return {
        "n": len(latencies_ms),
        "p50_ms": round(percentile(latencies_ms, 50), 2),
        "p95_ms": round(percentile(latencies_ms, 95), 2),
        "p99_ms": round(percentile(latencies_ms, 99), 2),
        "mean_ms": round(statistics.mean(latencies_ms), 2),
        "min_ms": round(min(latencies_ms), 2),
        "max_ms": round(max(latencies_ms), 2),
        "stdev_ms": round(statistics.stdev(latencies_ms), 2) if len(latencies_ms) > 1 else 0.0,
        # số mẫu nằm TRÊN p99 (tạo nên đuôi) — n=300 cũ chỉ có ~3 mẫu này.
        "samples_above_p99": sum(1 for v in latencies_ms if v > percentile(latencies_ms, 99)),
        "samples_above_20ms": sum(1 for v in latencies_ms if v > 20.0),
    }


def _dominant_code(codes: list[str]) -> str:
    if not codes:
        return "?"
    return max(set(codes), key=codes.count)


# ── Lấy JWT thật cho testuser01 (bật tạm direct-access-grants ở client
#    crapi-bff, xin token, TẮT LẠI ngay — xem module docstring) ─────────────

def _kc_admin_password() -> str:
    out = _run(["kubectl", "--context", OS_CTX, "get", "secret", "keycloak-secret", "-n", "identity",
                "-o", "jsonpath={.data.admin-password}"])
    import base64
    return base64.b64decode(out.stdout.strip()).decode()


def _kc_admin_pod_ensure() -> None:
    _run(["kubectl", "--context", OS_CTX, "delete", "pod", "kc-admin-setup-perf", "-n", "identity",
          "--ignore-not-found", "--wait=true"], check=False)
    _run(["kubectl", "--context", OS_CTX, "run", "kc-admin-setup-perf", "--image=python:3.12-alpine",
          "-n", "identity", "--restart=Never", "--overrides", KC_ADMIN_SETUP_OVERRIDES,
          "--command", "--", "sh", "-c", "sleep 90"], check=False)
    for _ in range(12):
        r = _run(["kubectl", "--context", OS_CTX, "wait", "--for=condition=Ready",
                   "pod/kc-admin-setup-perf", "-n", "identity", "--timeout=15s"], check=False)
        if r.returncode == 0:
            return
    raise RuntimeError("kc-admin-setup-perf không Ready — không lấy được token thật cho phép đo")


def _kc_admin_pod_cleanup() -> None:
    _run(["kubectl", "--context", OS_CTX, "delete", "pod", "kc-admin-setup-perf", "-n", "identity",
          "--ignore-not-found", "--wait=false"], check=False)


def _set_bff_direct_access_grants(enabled: bool, admin_pass: str) -> None:
    script = f"""
import urllib.request, json, urllib.parse
KC='http://keycloak.identity.svc.cluster.local:8080'; REALM='ztlab'
tok=urllib.parse.urlencode({{'grant_type':'password','client_id':'admin-cli','username':'admin','password':{admin_pass!r}}}).encode()
H={{'Authorization':'Bearer '+json.load(urllib.request.urlopen(urllib.request.Request(KC+'/realms/master/protocol/openid-connect/token',data=tok)))['access_token']}}
req=urllib.request.Request(KC+'/admin/realms/%s/clients?clientId=crapi-bff'%REALM, headers=H)
cur=json.load(urllib.request.urlopen(req))[0]
cur['directAccessGrantsEnabled']={enabled}
req2=urllib.request.Request(KC+'/admin/realms/%s/clients/%s'%(REALM,cur['id']), data=json.dumps(cur).encode(), headers={{**H,'Content-Type':'application/json'}}, method='PUT')
urllib.request.urlopen(req2)
print('directAccessGrantsEnabled ->', {enabled})
"""
    out = _run(["kubectl", "--context", OS_CTX, "exec", "-n", "identity", "kc-admin-setup-perf",
                "--", "python3", "-c", script])
    print("   ", out.stdout.strip())


def _get_test_user_token(admin_pass: str) -> str:
    script = f"""
import urllib.request, json, urllib.parse
KC='http://keycloak.identity.svc.cluster.local:8080'; REALM='ztlab'
tok=urllib.parse.urlencode({{'grant_type':'password','client_id':'crapi-bff','username':{TEST_USER!r},'password':{TEST_USER_PASS!r}}}).encode()
r=json.load(urllib.request.urlopen(urllib.request.Request(KC+'/realms/%s/protocol/openid-connect/token'%REALM,data=tok)))
print(r['access_token'])
"""
    out = _run(["kubectl", "--context", OS_CTX, "exec", "-n", "identity", "kc-admin-setup-perf",
                "--", "python3", "-c", script])
    token = out.stdout.strip()
    if not token or " " in token:
        raise RuntimeError(f"không lấy được access_token thật cho {TEST_USER_EMAIL}: {out.stdout[:200]} {out.stderr[:200]}")
    return token


def _get_crapi_token(bff_pod: str) -> str:
    """Vòng 2026-09-30 — token crAPI THẬT (Authorization: Bearer) cho testuser01.

    Mọi bản trước chỉ gửi X-Access-Token (JWT Keycloak cho OPA) mà KHÔNG có token
    crAPI → OPA cho qua rồi chính crapi-workshop trả 401 ("Unauthorized"). Kiểm lại
    results/round3/perf_overhead*.json: http_codes = 401 ở CẢ 3 cấu hình, cả 3 lượt —
    toàn bộ số độ trễ vòng 3 là latency của request bị APP từ chối, không phải request
    đi trọn. Lấy token bằng chính endpoint login của crAPI (mật khẩu seed, Secret
    crapi-seed ns crapi OpenStack), gọi từ container bff (hop bff→identity có trong
    service_acl)."""
    import base64
    pw = base64.b64decode(_run(["kubectl", "--context", OS_CTX, "-n", NS, "get", "secret", "crapi-seed",
                                "-o", "jsonpath={.data.password}"]).stdout.strip()).decode()
    script = (
        "import json,sys,http.client\n"
        "c=http.client.HTTPConnection('crapi-identity-openstack.crapi.svc.cluster.local',30090,timeout=20)\n"
        "c.request('POST','/identity/api/auth/login',body=json.dumps({'email':sys.argv[1],'password':sys.argv[2]}),"
        "headers={'Content-Type':'application/json'})\n"
        "r=c.getresponse(); b=r.read().decode(); print(r.status); print(b)\n"
    )
    out = _run(["kubectl", "--context", AWS_CTX, "-n", NS, "exec", bff_pod, "-c", "bff", "--",
                "python", "-c", script, TEST_USER_EMAIL, pw])
    status, _, body = out.stdout.strip().partition("\n")
    try:
        tok = json.loads(body).get("token", "")
    except Exception:
        tok = ""
    if status != "200" or not tok:
        raise RuntimeError(f"không lấy được token crAPI cho {TEST_USER_EMAIL}: {status} {body[:200]}")
    return tok


def _verify_bff_direct_access_grants_reverted(admin_pass: str) -> bool:
    script = f"""
import urllib.request, json, urllib.parse
KC='http://keycloak.identity.svc.cluster.local:8080'; REALM='ztlab'
tok=urllib.parse.urlencode({{'grant_type':'password','client_id':'admin-cli','username':'admin','password':{admin_pass!r}}}).encode()
H={{'Authorization':'Bearer '+json.load(urllib.request.urlopen(urllib.request.Request(KC+'/realms/master/protocol/openid-connect/token',data=tok)))['access_token']}}
req=urllib.request.Request(KC+'/admin/realms/%s/clients?clientId=crapi-bff'%REALM, headers=H)
cur=json.load(urllib.request.urlopen(req))[0]
print(cur['directAccessGrantsEnabled'])
"""
    out = _run(["kubectl", "--context", OS_CTX, "exec", "-n", "identity", "kc-admin-setup-perf",
                "--", "python3", "-c", script])
    return out.stdout.strip() == "False"


# ── Toggle AuthorizationPolicy (config 2: mtls_only) ────────────────────────

def _authz_policy_exists() -> bool:
    r = _run(["kubectl", "--context", AWS_CTX, "-n", NS, "get", "authorizationpolicy",
              "crapi-workshop-opa-authz"], check=False)
    return r.returncode == 0


def _delete_authz_policy() -> None:
    _run(["kubectl", "--context", AWS_CTX, "-n", NS, "delete", "authorizationpolicy",
          "crapi-workshop-opa-authz", "--ignore-not-found"])


def _restore_authz_policy() -> None:
    _run(["kubectl", "--context", AWS_CTX, "apply", "-f",
          str(REPO_ROOT / "k8s" / "crapi" / "istio-policies.yaml")])



def measure_mtls_opa_overhead(n: int, warmup: int) -> dict:
    total = n + warmup
    admin_pass = _kc_admin_password()
    _kc_admin_pod_ensure()
    token = None
    authz_removed = False
    result: dict = {}
    try:
        print("  [setup] Bật tạm directAccessGrantsEnabled cho client crapi-bff, xin JWT thật testuser01...")
        _set_bff_direct_access_grants(True, admin_pass)
        token = _get_test_user_token(admin_pass)
        print(f"  [setup] Có JWT thật ({len(token)} ký tự) cho {TEST_USER_EMAIL}")

        bff_pod = _pod("bff")
        # Client chạy từ container ỨNG DỤNG `bff` (uid 1000) bằng python (ảnh bff không có
        # curl) — request đi qua sidecar của bff: mТLS + danh tính spiffe://.../aws/bff thật.
        # KHÔNG chạy trong `istio-proxy` (uid 1337 bị iptables RETURN khỏi Envoy -> plaintext).
        crapi_bearer = "Bearer " + _get_crapi_token(bff_pod)
        print("  [setup] Có token crAPI thật (Authorization: Bearer) — request phải đi TRỌN tới 200")
        tok = {"jwt": token, "at": time.time(), "refreshes": 0}

        def header_fn() -> dict[str, str]:
            if time.time() - tok["at"] > BATCH_TOKEN_MAX_AGE_S:
                tok["jwt"], tok["at"] = _get_test_user_token(admin_pass), time.time()
                tok["refreshes"] += 1
            return {"X-Access-Token": tok["jwt"], "Authorization": crapi_bearer}

        print(f"  [(1) full] {total} req từ {bff_pod} (bff) -> crapi-workshop.svc, "
              f"mТLS STRICT + OPA ext_authz + keycloak_gate(JWT RS256) thật")
        cfs0 = _cfs_snapshot()
        full_all, full_codes = _run_batched(bff_pod, "bff", WORKSHOP_SVC_URL, total, header_fn)
        cfs1 = _cfs_snapshot()

        print("  [(2) mtls_only] Xoá tạm AuthorizationPolicy crapi-workshop-opa-authz...")
        _delete_authz_policy()
        authz_removed = True
        time.sleep(3)  # để Envoy nhận config mới qua xDS
        print(f"  [(2) mtls_only] {total} req từ {bff_pod} -> crapi-workshop.svc, "
              f"chỉ mТLS STRICT (không ext_authz)")
        cfs2 = _cfs_snapshot()
        mtls_all, mtls_codes = _run_batched(bff_pod, "bff", WORKSHOP_SVC_URL, total, header_fn)
        cfs3 = _cfs_snapshot()
        _restore_authz_policy()
        authz_removed = False
        time.sleep(3)

        # (A0) app_only: client chạy TRONG pod crapi-workshop (container ứng dụng, python) gọi
        # 127.0.0.1:8000 — loopback bị iptables Istio bỏ qua (`-d 127.0.0.1 -j RETURN`) nên
        # không qua Envoy, không mТLS, không OPA, không mạng pod-to-pod: thời gian xử lý của
        # chính ứng dụng. Không đo được "không mesh" đúng nghĩa trên cùng cặp vì
        # crapi-workshop KHÔNG chạy được nếu thiếu sidecar (cần mТLS tới identity — đo
        # 2026-09-26: tắt injection hoặc excludeInboundPorts đều cho pod 0/1 crash "Identity
        # Server is down"). Do đó (1)-(A0) là CẬN TRÊN của overhead (gồm cả mạng + Envoy 2 đầu).
        workshop_pod = _pod("crapi-workshop")
        print(f"  [(A0) app_only] {total} req TRONG {workshop_pod} -> 127.0.0.1:8000 (không Envoy, không mạng)")
        cfs4 = _cfs_snapshot()
        app_all, app_codes = _run_batched(workshop_pod, "crapi-workshop",
                                           f"http://127.0.0.1:8000{TARGET_PATH}", total, header_fn)
        cfs5 = _cfs_snapshot()

        # Cổng kiểm hợp lệ: nếu request bị OPA từ chối (403) hoặc lỗi kết nối thì số đo là
        # latency của request BỊ TỪ CHỐI (đúng sai sót đã làm hỏng bản Phần 1.4) — dừng,
        # không báo số.
        # Vòng 2026-09-29: yêu cầu 200 (không chỉ "không phải 403") cho ≥ 99% request
        # và CHỈ tính percentile trên request 200 — request lỗi/bị từ chối có đường xử
        # lý khác, trộn vào sẽ làm sai phân phối.
        code_counts = {}
        for name, codes in (("full", full_codes), ("mtls_only", mtls_codes), ("app_only", app_codes)):
            cc = {c: codes.count(c) for c in set(codes)}
            code_counts[name] = cc
            ok200 = cc.get("200", 0)
            if not codes or ok200 < 0.99 * len(codes):
                raise RuntimeError(f"phép đo cấu hình '{name}' KHÔNG hợp lệ: mã HTTP {cc} "
                                   f"(cần ≥ 99% là 200; 403 = bị OPA từ chối). Không báo số.")

        def _ok(times: list[float], codes: list[str]) -> list[float]:
            return [t for t, c in zip(times[warmup:], codes[warmup:]) if c == "200"]

        full = _ok(full_all, full_codes)
        mtls = _ok(mtls_all, mtls_codes)
        app = _ok(app_all, app_codes)
        full_stats, mtls_stats, app_stats = stats_of(full), stats_of(mtls), stats_of(app)
        delta_full_vs_pure = {}
        if "p50_ms" in full_stats and "p50_ms" in app_stats:
            delta_full_vs_pure = {
                "p50_ms": round(full_stats["p50_ms"] - app_stats["p50_ms"], 2),
                "p95_ms": round(full_stats["p95_ms"] - app_stats["p95_ms"], 2),
                "p99_ms": round(full_stats["p99_ms"] - app_stats["p99_ms"], 2),
                "mean_ms": round(full_stats["mean_ms"] - app_stats["mean_ms"], 2),
                "meets_20ms_p99_budget": (full_stats["p99_ms"] - app_stats["p99_ms"]) <= 20.0,
                "note": "CẬN TRÊN overhead Zero-Trust: cấu hình đầy đủ (Envoy 2 đầu + mТLS STRICT + OPA "
                        "ext_authz + JWT RS256 + mạng pod-to-pod) trừ thời gian xử lý app-only (loopback "
                        "trong pod đích). Bao gồm cả độ trễ mạng nên KHÔNG thuần là chi phí mesh; nếu cận "
                        "trên đã <= 20ms p99 thì ngưỡng đề cương chắc chắn đạt.",
            }
        no_mesh_stats = app_stats
        delta_mtls_component = {}
        if "p50_ms" in mtls_stats and "p50_ms" in no_mesh_stats:
            delta_mtls_component = {
                "p99_ms": round(mtls_stats["p99_ms"] - no_mesh_stats["p99_ms"], 2),
                "note": "xấp xỉ chi phí mТLS+Envoy L7 (không có ext_authz) — vẫn còn 2 chặng proxy, không phải mТLS thuần tuý đơn lẻ",
            }
        delta_opa_component = {}
        if "p50_ms" in full_stats and "p50_ms" in mtls_stats:
            delta_opa_component = {
                "p99_ms": round(full_stats["p99_ms"] - mtls_stats["p99_ms"], 2),
                "note": "xấp xỉ chi phí riêng vòng OPA ext_authz (full trừ mtls_only, cùng bff->workshop)",
            }

        result = {
            "methodology": (
                "Cặp ĐƯỢC PHÉP theo service_acl: bff -> crapi-workshop, "
                f"GET {TARGET_PATH}, header X-Access-Token = JWT Keycloak THẬT "
                f"({TEST_USER_EMAIL}, kích hoạt keycloak_gate/io.jwt.decode_verify RS256 "
                "thật — phần tính toán đắt nhất của policy, KHÔNG bỏ qua như bản cũ). "
                "3 cấu hình trên CÙNG cặp, CÙNG đường mạng thật (config (3) gọi thẳng "
                "pod IP thật của crapi-workshop, KHÔNG phải localhost/loopback): "
                "(1) full = mТLS STRICT + OPA ext_authz; (2) mtls_only = xoá tạm "
                "AuthorizationPolicy crapi-workshop-opa-authz, giữ sidecar/mТLS; "
                "(A0) app_only = client chạy TRONG pod crapi-workshop gọi 127.0.0.1:8000 (loopback bỏ "
                "qua Envoy; không mạng). KHÔNG đo được 'không mesh' đúng nghĩa trên cùng cặp vì "
                "crapi-workshop crash nếu thiếu sidecar (cần mТLS tới identity) — nên báo CẬN TRÊN "
                "overhead = (1) - (A0), gồm cả độ trễ mạng. Client đo là python trong container "
                "ứng dụng (KHÔNG phải curl trong istio-proxy uid 1337: bị iptables RETURN khỏi Envoy "
                "=> plaintext vào STRICT mTLS => reset). "
                "So với ngưỡng 20ms p99 bằng cận trên (1) - (A0). "
                "(2)-(3) và (1)-(2) là XẤP XỈ tách mТLS/OPA (không hoàn toàn sạch vì "
                "(2) vẫn còn 2 chặng Envoy L7 proxy). Mọi thay đổi cấu hình đã HOÀN "
                "NGUYÊN + xác nhận lại ngay sau khi đo (xem trường 'reverted_ok')."
            ),
            "warmup_requests_discarded": warmup,
            "batch_size": BATCH_SIZE,
            "jwt_refreshes": tok["refreshes"],
            "http_codes": {"full": _dominant_code(full_codes), "mtls_only": _dominant_code(mtls_codes),
                            "app_only": _dominant_code(app_codes)},
            "http_code_counts": code_counts,
            "full_mtls_opa": full_stats,
            "mtls_only": mtls_stats,
            "app_only_loopback": app_stats,
            "cfs_throttling_delta": {"full": _cfs_delta(cfs0, cfs1), "mtls_only": _cfs_delta(cfs2, cfs3),
                                     "app_only": _cfs_delta(cfs4, cfs5)},
            "histogram": {"full": histogram(full), "mtls_only": histogram(mtls), "app_only": histogram(app)},
            "raw_ms": {"full": [round(v, 3) for v in full], "mtls_only": [round(v, 3) for v in mtls],
                       "app_only": [round(v, 3) for v in app]},
            "overhead_upper_bound_full_minus_app_only": delta_full_vs_pure,
            "approx_mtls_l7_component_mtls_minus_app_only": delta_mtls_component,
            "approx_opa_component_full_minus_mtls": delta_opa_component,
        }
        return result
    finally:
        print("  [teardown] Hoàn nguyên toàn bộ thay đổi cấu hình tạm...")
        if authz_removed:
            _restore_authz_policy()
        try:
            _set_bff_direct_access_grants(False, admin_pass)
            reverted_ok = _verify_bff_direct_access_grants_reverted(admin_pass)
        except Exception as e:
            print(f"  [teardown] LỖI khi tắt lại directAccessGrantsEnabled: {e}", file=sys.stderr)
            reverted_ok = False
        _kc_admin_pod_cleanup()
        # Xác nhận cấu hình sống khớp source sau khi hoàn nguyên
        authz_ok = _authz_policy_exists()
        if result:
            result["reverted_ok"] = {
                "keycloak_direct_access_grants_disabled_again": reverted_ok,
                "authorization_policy_restored": authz_ok,
            }
            if not (reverted_ok and authz_ok):
                print("  [teardown] CẢNH BÁO: có mục hoàn nguyên KHÔNG xác nhận được — kiểm tay ngay!",
                      file=sys.stderr)


def _loki_query_range(query: str, start_s: int, end_s: int, limit: int = 500) -> list[dict]:
    qs = urllib.parse.urlencode({
        "query": query, "start": f"{start_s}000000000", "end": f"{end_s}000000000", "limit": limit,
    })
    try:
        with urllib.request.urlopen(f"{LOKI_URL}/loki/api/v1/query_range?{qs}", timeout=10) as r:
            data = json.load(r)
    except Exception as e:
        return [{"_error": str(e)}]
    lines = []
    for stream in data.get("data", {}).get("result", []):
        for _, line in stream.get("values", []):
            lines.append(line)
    return lines


def _extract_response_times(lines: list[str]) -> list[float]:
    out = []
    for ln in lines:
        try:
            d = json.loads(ln)
            rt = d.get("response_time")
            if rt is not None:
                out.append(float(rt))
        except Exception:
            continue
    return out


def measure_cross_cloud_latency(generate_samples: int) -> dict:
    """Độ trễ cross-cloud THẬT từ Envoy access log (Loki). Sinh traffic thật qua Gateway
    (tests/perf_generate_crosscloud.sh) rồi đọc `response_time` của CẢ 2 phía hop
    community/workshop(AWS) -> identity(OpenStack) /verify: phía client (AWS, gồm cả
    WireGuard) và phía server (OpenStack, chỉ xử lý). Hiệu 2 phía ~ chi phí đường truyền
    cross-cloud. KHÔNG áp ngưỡng 20ms (đặc tính kiến trúc hybrid)."""
    t0 = int(time.time())
    gen = REPO_ROOT / "tests" / "perf_generate_crosscloud.sh"
    print(f"  Sinh traffic thật qua Gateway ({generate_samples} vòng, 2 request/vòng) bằng {gen.name}")
    try:
        r = subprocess.run(["bash", str(gen), str(generate_samples)], capture_output=True, text=True,
                           timeout=600, cwd=REPO_ROOT)
        print("   ", (r.stdout.strip().splitlines() or [r.stderr.strip()[:200]])[-1])
    except Exception as e:  # noqa: BLE001
        print(f"    (không sinh được traffic mẫu: {e} — vẫn thử đọc log sẵn có)")
    time.sleep(10)  # chờ Promtail -> Loki
    t1 = int(time.time()) + 5

    hops = {
        "verify_client_side_aws_incl_wireguard": (
            '{job="envoy-access", cloud="aws", pod=~"crapi-(community|workshop).*"} |= "/identity/api/auth/verify"'
        ),
        "verify_server_side_openstack_identity": (
            '{job="envoy-access", cloud="openstack", pod=~"crapi-identity.*"} |= "/identity/api/auth/verify"'
        ),
        "opa_aws_to_keycloak_openstack_jwks": (
            '{job="envoy-access", cloud="aws", pod=~"opa-server.*"} |~ "192.168.101"'
        ),
    }
    result = {}
    for label, query in hops.items():
        lines = _loki_query_range(query, t0 - 900, t1)
        rts = _extract_response_times(lines)
        result[label] = stats_of(rts) if rts else {"n": 0, "note": "không có mẫu trong log"}
    c, sv = result.get("verify_client_side_aws_incl_wireguard", {}), result.get("verify_server_side_openstack_identity", {})
    if "p50_ms" in c and "p50_ms" in sv:
        result["approx_wireguard_transport_p50_ms"] = round(c["p50_ms"] - sv["p50_ms"], 2)
    result["methodology"] = (
        "Đọc field response_time (ms) THẬT từ Envoy access log (job=envoy-access, Loki) "
        "trong cửa sổ vừa sinh traffic (+ 15 phút trước) — không phải benchmark tự tạo, không "
        "trộn với phần mТLS+OPA nội cụm. Phía client (AWS) gồm cả WireGuard; phía server "
        "(OpenStack) chỉ xử lý. Đặc tính kiến trúc hybrid, KHÔNG áp ngưỡng 20ms."
    )
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="ZTLab perf overhead v2 — cặp ĐƯỢC PHÉP bff->crapi-workshop (Phần 2.1)")
    ap.add_argument("--n", type=int, default=2000, help="số request tính percentile (sau warmup); vòng 2026-09-29: ≥ 2000")
    ap.add_argument("--warmup", type=int, default=50, help="số request warm-up bỏ qua")
    ap.add_argument("--skip-crosscloud", action="store_true", help="bỏ phần [b] cross-cloud (lặp nhiều lượt [a])")
    ap.add_argument("--output", default="results/perf_overhead.json")
    args = ap.parse_args()

    print("ZTLab Performance Overhead v2 — bff->crapi-workshop, 3 cấu hình (Phần 2.1)")
    print(f"  N={args.n}  warmup={args.warmup}\n")

    results: dict = {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n": args.n,
        "warmup": args.warmup,
    }

    print("[a] Overhead mТLS+OPA (áp ngưỡng 20ms p99) — bff -> crapi-workshop, JWT thật")
    results["a_mtls_opa_overhead"] = measure_mtls_opa_overhead(args.n, args.warmup)

    if not args.skip_crosscloud:
        print("\n[b] Độ trễ cross-cloud (đặc tính kiến trúc, KHÔNG áp ngưỡng 20ms)")
        results["b_cross_cloud_latency"] = measure_cross_cloud_latency(30)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"\nGhi kết quả vào {out}")

    print("\n=== TÓM TẮT ===")
    a_ = results["a_mtls_opa_overhead"]
    def line(name, st):
        if "p50_ms" in st:
            print(f"  {name:<34} P50={st['p50_ms']:.2f}ms P95={st['p95_ms']:.2f}ms P99={st['p99_ms']:.2f}ms (n={st.get('n', '?')})")
    line("(1) full: mТLS+OPA+JWT", a_.get("full_mtls_opa", {}))
    line("(2) mtls_only (bỏ ext_authz)", a_.get("mtls_only", {}))
    line("(A0) app_only (loopback trong pod)", a_.get("app_only_loopback", {}))
    print(f"  mã HTTP chủ đạo: {a_.get('http_codes')}")
    d = a_.get("overhead_upper_bound_full_minus_app_only", {})
    if d:
        print(f"  CẬN TRÊN overhead (1)-(A0)  P50=+{d['p50_ms']:.2f}ms P99=+{d['p99_ms']:.2f}ms"
              f"  (ngưỡng đề cương: 20ms p99 — {'ĐẠT' if d.get('meets_20ms_p99_budget') else 'KHÔNG ĐẠT'})")
    print(f"  Hoàn nguyên cấu hình: {a_.get('reverted_ok')}")
    for cfg, dd in a_.get("cfs_throttling_delta", {}).items():
        thr = {k: v for k, v in dd.items() if v["nr_throttled"]}
        print(f"  CFS throttle trong lúc đo {cfg}: {thr or 'không'}")
    b = results.get("b_cross_cloud_latency", {})
    for k, v in b.items():
        if isinstance(v, dict) and "p50_ms" in v:
            print(f"  cross-cloud[{k}] P50={v['p50_ms']:.2f}ms P95={v['p95_ms']:.2f}ms P99={v['p99_ms']:.2f}ms (n={v['n']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
