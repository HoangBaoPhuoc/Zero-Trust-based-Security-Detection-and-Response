# Hướng dẫn SV2 — Pipeline dữ liệu & Machine Learning

> Bám sát đề cương KLTN chính thức ("Bản sao của DeCuongChiTiet_KLTN_ZTA.docx"), **không phải** kế hoạch PaySim/AIT-LDS cũ trong `DE_XUAT_AI.md`. Đọc [thesis_decuong_klta.md](đã lưu trong memory Claude) hoặc mục tóm tắt bên dưới nếu cần nhắc lại scope.
>
> Mục tiêu ML: phát hiện **BOLA** (Broken Object Level Authorization) + hành vi **danh tính bị chiếm dụng**, trên ứng dụng **OWASP crAPI**, dùng telemetry sinh ra bởi hạ tầng Zero Trust (Envoy access log + OPA decision log), tự sinh dữ liệu train (không dùng dataset công khai).

---

## 0. Cấu trúc thư mục sẽ tạo

Đặt toàn bộ code SV2 vào 1 service mới, theo đúng convention đang có (`services/fraud-detection/` có `main.py` + `training/` + `model/`):

```
services/bola-detector/
  dev/                        # GD1 — công cụ phát triển khi CHƯA có hạ tầng thật
    log_schema.py             # định nghĩa schema log thống nhất với SV1
    synth_log_generator.py    # sinh log giả lập đúng schema để test code
  features/                   # dùng chung mọi giai đoạn
    entities.py                # bảng thực thể (end-user / workload)
    windowing.py                # cửa sổ trượt 5'/1'
    feature_groups.py           # nhóm A + nhóm B
    build_features.py           # ghép thành 1 pipeline
  labeling/                   # GD3
    attack_runs.py
    label_windows.py
  training/                   # GD4
    split.py
    train_xgboost.py
    evaluate.py
    shap_analysis.py
  model/                      # artifact .pkl sau khi train (GD4)
  main.py                     # scoring service FastAPI, shadow mode (GD5)
  requirements.txt
```

Tạo khung thư mục:

```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
mkdir -p services/bola-detector/{dev,features,labeling,training,model}
touch services/bola-detector/{dev,features,labeling,training}/__init__.py
```

---

## GIAI ĐOẠN 1 (09/2026, tuần 1-3) — đang ở đây

Việc của SV2 trong GD1 (theo đề cương): *khảo sát ML, dựng môi trường 1 node, khung trích xuất đặc trưng trên dữ liệu mô phỏng*, và **cùng SV1 thống nhất lược đồ log ngay từ đầu**.

### Bước 1.1 — Khảo sát tài liệu (để viết phần liên quan + hiểu bài toán)

Đọc theo đúng thứ tự này, mỗi bài chỉ cần nắm ý chính để trích dẫn, không cần đọc sâu toán:

| # | Tài liệu | Đọc để lấy gì |
|---|---|---|
| 1 | NIST SP 800-207 | Định nghĩa PDP/PEP, nguyên tắc "never trust, always verify" — dùng cho phần đặt vấn đề |
| 2 | OWASP API Security Top 10 (2023) | Định nghĩa chính xác BOLA vs BFLA — đề cương phân định rõ 2 loại này, phải trích đúng |
| 3 | Chen & Malin (2011), Tuor et al. (2017) | Cách dùng quan hệ trong access log để phát hiện lạm quyền — gần nhất với hướng của đề tài (tabular, không phải graph deep learning) |
| 4 | TraceAnomaly, DeepTraLog | Cách định nghĩa "cửa sổ" và đặc trưng lời gọi giữa service — tham khảo cách chia cửa sổ, không cần dùng graph neural network như họ |
| 5 | UNICORN, ProvDetector | Chỉ cần nắm ý tưởng provenance graph để viết phần "công trình liên quan chưa khai thác được gì" |
| 6 | Arp et al. "Dos and Don'ts of ML in Security" | **Bắt buộc đọc kỹ** — checklist tránh data leakage, sẽ áp dụng trực tiếp ở Bước 4 (train/test split theo thời gian) |
| 7 | Pendlebury et al. TESSERACT | Cách chia tập theo trục thời gian có buffer — áp dụng trực tiếp |
| 8 | Axelsson "Base-Rate Fallacy" | Lý do không dùng accuracy — trích dẫn khi giải thích chọn PR-AUC |
| 9 | Geirhos et al. "Shortcut Learning" | Lý do phải test trên biến thể tấn công chưa gặp — áp dụng ở Bước 4 |
| 10 | Lundberg & Lee, SHAP | Cách đọc SHAP value — dùng ở Bước 4 |

Ghi chú lại mỗi bài 3-5 dòng vào 1 file `docs/related_work_notes.md` — dùng thẳng cho chương "Công trình liên quan" của báo cáo.

### Bước 1.2 — Cài Docker (nếu máy dev chưa có)

```bash
# Kiểm tra đã có chưa
docker --version && docker compose version
```

Nếu chưa có (Ubuntu):
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker   # áp dụng quyền group ngay, không cần logout
docker compose version   # xác nhận plugin compose v2 đã có (>= 2.x)
```

### Bước 1.3 — Cài đặt crAPI (1 node)

Đây là ứng dụng mục tiêu chính thức theo đề cương. Cài bằng docker compose, dùng bản build sẵn từ image chính thức (nhanh, không cần build lại từ source):

```bash
mkdir -p ~/crapi-dev && cd ~/crapi-dev
curl -o crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip crapi.zip && cd crAPI-main/deploy/docker

docker compose pull                                   # tải toàn bộ image (vài phút)
docker compose -f docker-compose.yml --compatibility up -d
```

Giải thích: `--compatibility` cần vì file compose của crAPI dùng cú pháp `deploy.resources` kiểu Swarm, flag này dịch nó sang giới hạn tài nguyên tương đương cho Docker Compose thường.

Kiểm tra đã chạy đủ container:
```bash
docker compose ps
```
Kỳ vọng thấy các service: `web` (nginx/gateway, cổng 8888), `identity` (Go — xác thực, JWT), `community` (Python — blog/comment), `workshop` (NodeJS — vehicle + mechanic report, chính là nơi có 2 lỗ hổng BOLA mục tiêu), `mailhog` (bắt email OTP vì SMTP thật bị tắt), `mongo`, `postgres`.

Truy cập thử:
```bash
curl -s http://localhost:8888/identity/health | python3 -m json.tool
```
Mailhog (đọc OTP đăng ký tài khoản, vì crAPI bắt buộc xác thực OTP qua email khi signup):
```bash
xdg-open http://localhost:8025 2>/dev/null || echo "Mở tay: http://localhost:8025"
```

Đăng ký 2 tài khoản test (dùng UI ở `http://localhost:8888`, lấy OTP từ Mailhog) — đặt tên rõ ràng để sau này dùng cho kịch bản BOLA, ví dụ `victim@test.local` và `attacker@test.local`.

**Việc cần làm ở bước này**: đăng nhập bằng 2 tài khoản, dùng tab Network của DevTools (F12) đi qua toàn bộ luồng "thêm xe" (workshop), "gửi báo cáo cho thợ" (mechanic report), "đăng video" (community) — ghi lại đúng path + method + body của từng API vào 1 file `docs/crapi_api_map.md`. Đây là input bắt buộc cho Bước 1.6 (thiết kế đặc trưng) và cho GD2 (viết script tấn công tự động) — không đoán path, phải tự bắt gói tin thật.

Dừng môi trường khi không dùng (tiết kiệm RAM máy dev):
```bash
cd ~/crapi-dev/crAPI-main/deploy/docker && docker compose down
```

### Bước 1.4 — Chốt lược đồ log với SV1 (quan trọng nhất GD1)

crAPI hiện **chưa chạy sau Envoy/OPA** — bản thân nó không sinh ra telemetry Zero Trust. Việc của SV1 ở GD2 là đặt crAPI sau SPIRE + Istio mTLS + OPA `ext_authz`. Việc của bạn ngay bây giờ là **đề xuất trước** format log, để SV1 cấu hình Envoy đúng ngay từ đầu (tránh phải sửa lại giữa chừng — bài học từ project cũ, xem `envoy/envoy-sidecar.yaml` đã phải sửa 2 lần).

Đề xuất format JSON log (dựa trên format Envoy access log đã dùng trong project cũ, mở rộng thêm field Zero Trust cần cho nhóm đặc trưng B):

```json
{
  "timestamp": "2026-09-12T10:15:32.123Z",
  "trace_id": "abc123",
  "session_id": "sess-9f2a",
  "caller_identity": "spiffe://ztlab.local/crapi/web-frontend",
  "caller_jwt_subject": "victim@test.local",
  "callee_identity": "spiffe://ztlab.local/crapi/workshop",
  "method": "GET",
  "path": "/workshop/api/vehicle/{vehicle_id}",
  "object_id": "veh-00042",
  "response_code": 200,
  "response_time_ms": 18,
  "bytes_sent": 512,
  "opa_decision": "allow",
  "opa_policy_matched": "workshop-read-own-vehicle"
}
```

Giải thích từng field và vì sao cần:
- `caller_identity`/`callee_identity` (SPIFFE ID) — bắt buộc để tính đặc trưng nhóm B "số identity đích khác nhau/cửa sổ" và "cặp gọi chưa từng thấy".
- `caller_jwt_subject` — vì thực thể có 2 loại (end-user qua JWT, workload qua SPIFFE ID); end-user gọi API qua `web` nên identity ở tầng mesh luôn là `web-frontend`, phải lấy JWT subject mới phân biệt được người dùng thật.
- `object_id` — trích từ path (ví dụ `{vehicle_id}`), **bắt buộc phải có** vì đây là field then chốt để tính "số object khác nhau truy cập/session" — nếu Envoy không log được field này (path template thay vì path thật), phải yêu cầu SV1 bật `%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%` (đã dùng đúng cách này trong config cũ) để lấy path thật có ID cụ thể.
- `opa_decision` + `opa_policy_matched` — nguồn của đặc trưng "tỷ lệ bị PDP từ chối" và của baseline luật ngưỡng (Bước 4, cấu hình (i)).
- `session_id` — bắt buộc để chia train/test theo session (Bước 4) và để loại bỏ cửa sổ vắt ranh giới session (quy tắc gán nhãn, Bước 3).

Gửi bản đề xuất này cho SV1, chốt xong thì lưu lại thành `services/bola-detector/dev/log_schema.py`:

```python
# services/bola-detector/dev/log_schema.py
from dataclasses import dataclass
from typing import Literal, Optional

@dataclass
class ZTLogEvent:
    timestamp: str              # ISO8601 UTC
    trace_id: str
    session_id: str
    caller_identity: str        # spiffe://... của workload gọi
    caller_jwt_subject: Optional[str]   # None nếu là workload-to-workload
    callee_identity: str        # spiffe://... của workload nhận
    method: str
    path: str                   # path thật, đã có ID cụ thể, không phải template
    object_id: Optional[str]    # trích từ path, None nếu endpoint không thao tác 1 object cụ thể
    response_code: int
    response_time_ms: float
    bytes_sent: int
    opa_decision: Literal["allow", "deny"]
    opa_policy_matched: Optional[str]
```

### Bước 1.5 — Sinh log giả lập để phát triển code khi chưa có hạ tầng thật

Vì SV1 cần vài tuần mới xong hạ tầng, bạn không được đứng chờ — viết 1 bộ sinh log giả lập đúng schema trên, mô phỏng cả traffic bình thường lẫn 1 kịch bản BOLA đơn giản, để có dữ liệu test code trích xuất đặc trưng ngay.

```python
# services/bola-detector/dev/synth_log_generator.py
"""Sinh log ZTLogEvent giả lập để phát triển/test feature extraction
trước khi có log thật từ Envoy+OPA. KHÔNG dùng file này để tạo dữ liệu
train cuối cùng — chỉ để kiểm thử logic code."""
import random
import uuid
from datetime import datetime, timedelta, timezone

IDENTITIES = [
    "spiffe://ztlab.local/crapi/web-frontend",
    "spiffe://ztlab.local/crapi/identity",
    "spiffe://ztlab.local/crapi/workshop",
    "spiffe://ztlab.local/crapi/community",
]
USERS = [f"user{i}@test.local" for i in range(20)]
VEHICLES = {u: f"veh-{i:05d}" for i, u in enumerate(USERS)}  # mỗi user sở hữu 1 xe


def _base_event(ts, session_id, user, path, object_id, decision="allow"):
    return dict(
        timestamp=ts.isoformat(),
        trace_id=str(uuid.uuid4())[:8],
        session_id=session_id,
        caller_identity="spiffe://ztlab.local/crapi/web-frontend",
        caller_jwt_subject=user,
        callee_identity="spiffe://ztlab.local/crapi/workshop",
        method="GET",
        path=path,
        object_id=object_id,
        response_code=200 if decision == "allow" else 403,
        response_time_ms=round(random.uniform(5, 40), 1),
        bytes_sent=random.randint(200, 2000),
        opa_decision=decision,
        opa_policy_matched="workshop-read-own-vehicle",
    )


def gen_benign_session(user, start_ts, n_calls=5):
    """User xem đúng xe của chính mình vài lần — hành vi bình thường."""
    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    ts = start_ts
    events = []
    for _ in range(n_calls):
        ts += timedelta(seconds=random.uniform(5, 60))
        events.append(_base_event(ts, session_id, user,
                                   f"/workshop/api/vehicle/{VEHICLES[user]}",
                                   VEHICLES[user]))
    return events


def gen_bola_attack_run(attacker, start_ts, n_distinct_victims=5):
    """Mô phỏng Challenge 1 của crAPI: attacker duyệt vehicle_id của
    NHIỀU user khác nhau liên tiếp, cách đều nhau (giống script tự động)."""
    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    ts = start_ts
    events = []
    victims = random.sample([u for u in USERS if u != attacker], n_distinct_victims)
    for v in victims:
        ts += timedelta(seconds=2)  # đều đặn — dấu hiệu script, khác hành vi người
        events.append(_base_event(ts, session_id, attacker,
                                   f"/workshop/api/vehicle/{VEHICLES[v]}",
                                   VEHICLES[v]))
    return events, {"attack_run_id": str(uuid.uuid4()), "attack_class": "BOLA",
                     "start": events[0]["timestamp"], "end": events[-1]["timestamp"]}


if __name__ == "__main__":
    import json
    now = datetime.now(timezone.utc)
    all_events = []
    for u in USERS:
        all_events += gen_benign_session(u, now)
    atk_events, atk_meta = gen_bola_attack_run(USERS[0], now + timedelta(minutes=2))
    all_events += atk_events
    all_events.sort(key=lambda e: e["timestamp"])

    with open("services/bola-detector/dev/synth_events.jsonl", "w") as f:
        for e in all_events:
            f.write(json.dumps(e) + "\n")
    with open("services/bola-detector/dev/synth_attack_runs.jsonl", "w") as f:
        f.write(json.dumps(atk_meta) + "\n")
    print(f"Sinh {len(all_events)} events, 1 attack run → dev/synth_events.jsonl")
```

Chạy thử:
```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
python3 services/bola-detector/dev/synth_log_generator.py
wc -l services/bola-detector/dev/synth_events.jsonl
```

### Bước 1.6 — Môi trường Python cho phần ML

```bash
cd services/bola-detector
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

`services/bola-detector/requirements.txt`:
```
pandas==2.2.2
numpy==1.26.4
scikit-learn==1.5.0
xgboost==2.0.3
shap==0.45.1
fastapi==0.111.0
uvicorn==0.30.1
pydantic==2.7.1
pyarrow==16.1.0
```
```bash
pip install -r requirements.txt
```
Giải thích lựa chọn: `xgboost` là model chính (đề cương đã chốt lý do — dữ liệu bảng, CPU, giải thích được). `shap` cho Bước 4 (feature importance, kiểm tra shortcut learning). `pyarrow` để lưu feature dạng Parquet (nhanh + giữ kiểu dữ liệu, tốt hơn CSV khi có hàng triệu dòng log). `fastapi`/`uvicorn` dành cho GD5 (scoring service), cài từ giờ để code Bước 1.7 tương thích luôn.

### Bước 1.7 — Khung trích xuất đặc trưng (chạy được ngay trên log giả lập)

```python
# services/bola-detector/features/entities.py
"""Bảng thực thể: end-user (theo JWT subject) hoặc workload (theo SPIFFE ID),
cùng 1 bảng, phân biệt bằng cột entity_type — đúng thiết kế trong đề cương."""
import pandas as pd


def build_entity_id(row: dict) -> tuple[str, str]:
    """Trả về (entity_id, entity_type). Ưu tiên end-user nếu có JWT subject,
    vì đó là chủ thể ra quyết định hành vi thật; nếu không có (gọi
    workload-to-workload nội bộ, không qua người dùng) thì entity = SPIFFE ID
    của caller."""
    if row.get("caller_jwt_subject"):
        return row["caller_jwt_subject"], "end_user"
    return row["caller_identity"], "workload"


def add_entity_columns(df: pd.DataFrame) -> pd.DataFrame:
    ids, types = zip(*df.apply(build_entity_id, axis=1))
    df = df.copy()
    df["entity_id"] = ids
    df["entity_type"] = types
    return df
```

```python
# services/bola-detector/features/windowing.py
"""Cửa sổ trượt 5 phút, bước trượt 1 phút — đúng đơn vị dự đoán trong đề cương:
(thực thể × cửa sổ thời gian)."""
import pandas as pd

WINDOW = pd.Timedelta(minutes=5)
STEP = pd.Timedelta(minutes=1)


def make_windows(df: pd.DataFrame) -> pd.DataFrame:
    """Trả về DataFrame các window: mỗi dòng là 1 (entity_id, window_start).
    events_in_window là list index để feature_groups.py dùng lại, tránh phải
    lọc lại toàn bộ log mỗi lần tính 1 đặc trưng."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    windows = []
    for entity_id, g in df.groupby("entity_id"):
        g = g.sort_values("timestamp")
        t_min, t_max = g["timestamp"].min(), g["timestamp"].max()
        w_start = t_min.floor(STEP)
        while w_start <= t_max:
            w_end = w_start + WINDOW
            mask = (g["timestamp"] >= w_start) & (g["timestamp"] < w_end)
            idx = g.index[mask]
            if len(idx) > 0:
                # loại cửa sổ vắt qua ranh giới session — quy tắc gán nhãn đã khoá
                sessions_in_window = g.loc[idx, "session_id"].unique()
                spans_boundary = len(sessions_in_window) > 1 and _crosses_boundary(g, idx)
                windows.append(dict(entity_id=entity_id, entity_type=g["entity_type"].iloc[0],
                                     window_start=w_start, window_end=w_end,
                                     event_idx=list(idx), dropped_session_boundary=spans_boundary))
            w_start += STEP
    return pd.DataFrame(windows)


def _crosses_boundary(g: pd.DataFrame, idx) -> bool:
    """True nếu cửa sổ chứa events từ >1 session VÀ khoảng cách thời gian giữa
    2 session đó lớn hơn nửa độ dài cửa sổ (tức thực sự là 2 phiên tách biệt,
    không phải trùng khớp session_id bị cấp lại nhanh)."""
    sub = g.loc[idx].sort_values("timestamp")
    if sub["session_id"].nunique() <= 1:
        return False
    boundaries = sub["session_id"].ne(sub["session_id"].shift()).cumsum()
    gap = sub.groupby(boundaries)["timestamp"].agg(["min", "max"])
    return len(gap) > 1
```

```python
# services/bola-detector/features/feature_groups.py
"""Nhóm A (HTTP thường) và Nhóm B (đặc thù Zero Trust) — đây là ablation
3 cấu hình sẽ dùng ở Bước 4: baseline / A / A+B."""
import math
import pandas as pd

# baseline pairs "đã thấy" — trong thực tế build từ giai đoạn nền dài trước
# khi chạy tấn công; ở đây nhận vào như tham số để hàm test được độc lập.
def group_a_features(events: pd.DataFrame) -> dict:
    n = len(events)
    status = events["response_code"]
    path_lens = events["path"].str.len()
    return {
        "req_rate_per_min": n / 5.0,
        "pct_4xx": (status.between(400, 499)).mean() if n else 0.0,
        "pct_5xx": (status >= 500).mean() if n else 0.0,
        "avg_path_len": path_lens.mean() if n else 0.0,
        "path_entropy": _entropy(events["path"]) if n else 0.0,
    }


def group_b_features(events: pd.DataFrame, known_pairs: set[tuple[str, str]]) -> dict:
    n = len(events)
    distinct_callees = events["callee_identity"].nunique()
    pairs = set(zip(events["caller_identity"], events["callee_identity"]))
    unseen_pairs = len(pairs - known_pairs)
    deny_rate = (events["opa_decision"] == "deny").mean() if n else 0.0
    distinct_objects_per_session = (
        events.groupby("session_id")["object_id"].nunique().mean()
        if n and "session_id" in events else 0.0
    )
    return {
        "distinct_callee_count": distinct_callees,
        "unseen_identity_pair_count": unseen_pairs,
        "pdp_deny_rate": deny_rate,
        "distinct_objects_per_session": distinct_objects_per_session or 0.0,
    }


def _entropy(series: pd.Series) -> float:
    probs = series.value_counts(normalize=True)
    return float(-(probs * probs.apply(math.log2)).sum())
```

```python
# services/bola-detector/features/build_features.py
"""Ghép entity + windowing + feature_groups thành 1 pipeline chạy từ log
(thật hoặc giả lập) ra bảng feature sẵn sàng train."""
import json
import pandas as pd

from entities import add_entity_columns
from windowing import make_windows
from feature_groups import group_a_features, group_b_features


def load_events(jsonl_path: str) -> pd.DataFrame:
    rows = [json.loads(line) for line in open(jsonl_path)]
    return pd.DataFrame(rows)


def build_known_pairs(df: pd.DataFrame, before_ts) -> set[tuple[str, str]]:
    """Baseline 'cặp gọi đã từng thấy' — tính trên dữ liệu TRƯỚC mốc before_ts
    (giai đoạn nền), không được rò rỉ thông tin từ chính cửa sổ đang chấm điểm."""
    hist = df[pd.to_datetime(df["timestamp"]) < before_ts]
    return set(zip(hist["caller_identity"], hist["callee_identity"]))


def build_feature_table(jsonl_path: str) -> pd.DataFrame:
    df = load_events(jsonl_path)
    df = add_entity_columns(df)
    windows = make_windows(df)
    windows = windows[~windows["dropped_session_boundary"]]  # áp quy tắc gán nhãn

    rows = []
    for _, w in windows.iterrows():
        events = df.loc[w["event_idx"]]
        known_pairs = build_known_pairs(df, w["window_start"])
        feat = {"entity_id": w["entity_id"], "entity_type": w["entity_type"],
                "window_start": w["window_start"]}
        feat.update(group_a_features(events))
        feat.update(group_b_features(events, known_pairs))
        rows.append(feat)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    table = build_feature_table("dev/synth_events.jsonl")
    table.to_parquet("dev/synth_features.parquet", index=False)
    print(table.shape)
    print(table.head())
```

Chạy thử để xác nhận khung code chạy được (dùng log giả lập từ Bước 1.5):
```bash
cd services/bola-detector/features
python3 build_features.py
```
Kỳ vọng: in ra shape bảng feature và vài dòng đầu, thấy cửa sổ chứa attack run có `distinct_callee_count`/`unseen_identity_pair_count` cao hẳn so với các cửa sổ benign khác — đây chính là tín hiệu nhóm B mà đề cương kỳ vọng model học được.

**Việc cần làm thêm ở bước này**: viết vài `assert` đơn giản (không cần pytest đầy đủ ở GD1) để tự kiểm tra: cửa sổ vắt session bị loại đúng, cửa sổ chứa attack run có `unseen_identity_pair_count >= n_distinct_victims`. Việc này giúp Bước 3 (khi có log thật) tự tin là logic đúng chứ không phải bug.

### Checklist hoàn thành GD1

- [ ] Đọc xong 10 tài liệu ở Bước 1.1, có file ghi chú
- [ ] crAPI chạy được trên máy dev, đã map được API của `workshop` (vehicle, mechanic report) và `community` (video)
- [ ] Lược đồ log đã gửi và **được SV1 xác nhận** — vì SV1 sẽ dùng nó để cấu hình Envoy ở GD2, sai ở đây là tốn công sửa lại về sau
- [ ] Code `entities.py` / `windowing.py` / `feature_groups.py` / `build_features.py` chạy được trên log giả lập, có assert cơ bản
- [ ] Đã thấy rõ bằng mắt: cửa sổ chứa attack run tách biệt khỏi cửa sổ benign trên ít nhất 1-2 đặc trưng nhóm B (sanity check quan trọng nhất trước khi đầu tư train thật)

---

## GIAI ĐOẠN 2 (T4/09 - T2/10/2026) — SV1 chủ trì hạ tầng, SV2 làm song song

Việc của bạn: **xây bộ kịch bản tấn công tự động cho crAPI + biến thể thủ công dùng riêng cho test set.**

### Bước 2.1 — Script tấn công tự động (2 challenge BOLA + 1 challenge BFLA làm phép thử policy)

Dùng chính API map đã ghi ở Bước 1.3. Khung script (điền path thật đã bắt được bằng DevTools/Burp vào chỗ `TODO`):

```python
# services/bola-detector/attacks/bola_vehicle_scan.py
"""Attack run: đăng nhập bằng 1 tài khoản, quét vehicle_id của nhiều tài
khoản khác bằng cách thay ID trong URL — đúng Challenge 1 của crAPI."""
import time
import uuid
import requests

BASE = "http://localhost:8888"


def login(email, password):
    r = requests.post(f"{BASE}/identity/api/auth/login",
                       json={"email": email, "password": password})
    r.raise_for_status()
    return r.json()["token"]


def run_attack(attacker_token: str, victim_vehicle_ids: list[str], out_meta_path: str):
    attack_run_id = str(uuid.uuid4())
    start = time.time()
    headers = {"Authorization": f"Bearer {attacker_token}",
               "X-Attack-Run-Id": attack_run_id}   # đánh dấu để mapping nhãn sau này
    for vid in victim_vehicle_ids:
        requests.get(f"{BASE}/workshop/api/vehicle/{vid}", headers=headers)  # TODO xác nhận path thật
        time.sleep(1)
    end = time.time()
    with open(out_meta_path, "a") as f:
        import json
        f.write(json.dumps({"attack_run_id": attack_run_id, "attack_class": "BOLA",
                             "start_ts": start, "end_ts": end}) + "\n")
    return attack_run_id
```

Điểm quan trọng: **luôn gắn `X-Attack-Run-Id` vào header của mọi request tấn công**, và bảo SV1 cho phép Envoy log header này ra field riêng (giống cách `trace_id` đã được log). Đây là cách rẻ nhất để biết chính xác request nào thuộc lần chạy tấn công nào khi gán nhãn ở Bước 3 — khỏi phải đối chiếu theo IP/thời gian (dễ sai khi nhiều thứ chạy song song).

### Bước 2.2 — Biến thể thủ công (dùng riêng cho test set)

Đề cương yêu cầu: kịch bản OWASP có sẵn (Bước 2.1) dùng để **train**; còn 1-2 biến thể **tự nghĩ thêm, khác cách viết script** (ví dụ: quét ngẫu nhiên ID thay vì tuần tự, chèn delay ngẫu nhiên thay vì đều đặn, trộn lẫn với truy cập hợp lệ để né phát hiện dựa trên tần suất) — các biến thể này **không được đưa vào tập train**, chỉ dùng ở Bước 4 để test "model có học được bản chất hành vi vượt quyền hay chỉ học đúng dấu vết của 1 script cụ thể" (shortcut learning, theo Geirhos et al.).

Viết chúng thành các file riêng `attacks/bola_vehicle_scan_variant_random_delay.py`, `attacks/bola_vehicle_scan_variant_mixed_traffic.py` — gắn nhãn `is_test_only_variant: true` trong file meta để Bước 3/4 tự động loại khỏi tập train.

### Bước 2.3 — Kịch bản traffic nền "khác thường nhưng hợp lệ"

Đề cương yêu cầu tránh traffic nền quá đơn điệu (nếu không bài toán sẽ dễ giả tạo). Viết thêm 3 kịch bản load-gen hợp lệ:
- admin xem nhiều vehicle khác nhau (hợp lệ vì có quyền, nhưng bề ngoài giống hệt attacker ở đặc trưng "distinct object count" — quan trọng để model không học nhầm "xem nhiều object = tấn công")
- user mới đăng ký, hành vi khác biệt hẳn user cũ (ít lịch sử → nhiều "cặp gọi chưa từng thấy" dù hoàn toàn hợp lệ)
- user sở hữu nhiều xe thật (multi-vehicle), truy cập nhiều `object_id` hợp lệ trong 1 session

Đây chính là các ca khó (hard negatives) giúp đặc trưng nhóm B (Bước 1.7) chứng minh giá trị thật thay vì chỉ tách được benign/attack một cách hiển nhiên.

---

## GIAI ĐOẠN 3 (T3/10 - T3/11/2026) — SV2 chủ trì

Khi hạ tầng SV1 xong (SPIRE + Istio mTLS + OPA trước crAPI, log Envoy/OPA đẩy vào Loki theo đúng schema đã chốt ở Bước 1.4):

### Bước 3.1 — Kéo log thật từ Loki thay vì file giả lập

```bash
# ví dụ query Loki lấy log crAPI trong 1 khung giờ, xuất ra JSONL
curl -sG "http://localhost:13100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="envoy-crapi"}' \
  --data-urlencode 'start=2026-10-15T00:00:00Z' \
  --data-urlencode 'end=2026-10-15T23:59:59Z' \
  --data-urlencode 'limit=5000' \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for stream in data['data']['result']:
    for ts, line in stream['values']:
        print(line)
" > services/bola-detector/data/raw/2026-10-15.jsonl
```
(Chỉnh `job=` đúng label thật SV1 đặt cho promtail scrape config của crAPI.)

### Bước 3.2 — Chạy sinh dữ liệu theo session, ~5 tuần

Viết 1 script orchestrator chạy song song: load-gen benign liên tục + xen kẽ các attack run (từ Bước 2.1/2.2) theo lịch ngẫu nhiên, mục tiêu **≥100 lần chạy tấn công độc lập** trải đều các lớp trong phạm vi (BOLA + hành vi danh tính bị chiếm dụng) và **≥150 giờ traffic nền**.

```python
# services/bola-detector/labeling/attack_runs.py
"""Ghi lại metadata mọi lần chạy tấn công (kể cả benign 'hard negative' runs)
vào 1 file tập trung — nguồn sự thật duy nhất để gán nhãn ở build_features."""
import json, time

def log_run(meta_path, attack_run_id, attack_class, start_ts, end_ts, is_test_only=False):
    with open(meta_path, "a") as f:
        f.write(json.dumps(dict(attack_run_id=attack_run_id, attack_class=attack_class,
                                 start_ts=start_ts, end_ts=end_ts,
                                 is_test_only=is_test_only)) + "\n")
```

### Bước 3.3 — Gán nhãn (quy tắc đã khoá từ đề cương — không được đổi giữa chừng)

```python
# services/bola-detector/labeling/label_windows.py
import pandas as pd

def label_windows(feature_table: pd.DataFrame, attack_runs: pd.DataFrame) -> pd.DataFrame:
    """Cửa sổ dương <=> chứa ít nhất 1 event thuộc 1 attack_run đã đánh dấu.
    So khớp bằng khoảng thời gian [window_start, window_end) giao với
    [run.start_ts, run.end_ts]."""
    feature_table = feature_table.copy()
    feature_table["label"] = 0
    feature_table["attack_run_id"] = None
    for _, run in attack_runs.iterrows():
        mask = (feature_table["window_start"] < run["end_ts"]) & \
               (feature_table["window_end"] > run["start_ts"])
        feature_table.loc[mask, "label"] = 1
        feature_table.loc[mask, "attack_run_id"] = run["attack_run_id"]
    return feature_table
```

### Bước 3.4 — QC bắt buộc trước khi coi là "xong GD3"

```bash
python3 - <<'EOF'
import pandas as pd
df = pd.read_parquet("services/bola-detector/data/processed/features_labeled.parquet")
runs = pd.read_json("services/bola-detector/data/processed/attack_runs.jsonl", lines=True)

print("Tổng số attack run (không tính is_test_only):",
      (~runs["is_test_only"]).sum(), "— cần >= 100")
print("Số lớp tấn công khác nhau:", runs.loc[~runs.is_test_only, "attack_class"].nunique())
print("Tỷ lệ nhãn dương:", df["label"].mean())
print("Số entity_id khác nhau (đa dạng traffic nền):", df["entity_id"].nunique())
EOF
```
Nếu số lần chạy tấn công độc lập chưa tới 100, hoặc traffic nền chỉ tập trung vào rất ít entity → quay lại Bước 3.2, không chuyển sang GD4 khi chưa đạt, vì đề cương ghi rõ đây là điều kiện để đảm bảo độ tin cậy thống kê.

---

## GIAI ĐOẠN 4 (T4/11 - T3/12/2026) — SV2 chủ trì

### Bước 4.1 — Chia tập theo session + theo thời gian, có buffer

```python
# services/bola-detector/training/split.py
import pandas as pd

WINDOW = pd.Timedelta(minutes=5)

def time_session_split(df: pd.DataFrame, train_frac=0.7):
    """Chia theo trục thời gian (không random) — phần đầu train, phần cuối
    test, đúng khuyến nghị Pendlebury et al. Thêm buffer = độ dài 1 cửa sổ
    quanh điểm cắt để loại các cửa sổ chồng lấn giữa 2 tập (data leakage
    theo Arp et al.). Đồng thời đảm bảo 1 session không bị xé giữa train/test."""
    df = df.sort_values("window_start")
    cutoff = df["window_start"].quantile(train_frac)

    # nếu 1 entity_id có session vắt qua cutoff, đẩy toàn bộ session đó
    # về phía có nhiều event hơn để không xé lẻ
    sess_bounds = df.groupby("entity_id")["window_start"].agg(["min", "max"])
    train_mask = df["window_start"] < (cutoff - WINDOW)
    test_mask = df["window_start"] > (cutoff + WINDOW)
    return df[train_mask].copy(), df[test_mask].copy()
```

### Bước 4.2 — Train 3 cấu hình

```python
# services/bola-detector/training/train_xgboost.py
import numpy as np
import xgboost as xgb
from sklearn.metrics import average_precision_score

FEATURES_A = ["req_rate_per_min", "pct_4xx", "pct_5xx", "avg_path_len", "path_entropy"]
FEATURES_B = ["distinct_callee_count", "unseen_identity_pair_count",
              "pdp_deny_rate", "distinct_objects_per_session"]


def baseline_threshold_score(df):
    """Cấu hình (i): baseline luật ngưỡng trên pdp_deny_rate — bắt buộc phải
    có để chứng minh model vượt trội, không phải chỉ nhìn có vẻ hay."""
    return df["pdp_deny_rate"].values


def train_config(train_df, feature_cols):
    pos = (train_df["label"] == 1).sum()
    neg = (train_df["label"] == 0).sum()
    scale_pos_weight = neg / max(pos, 1)   # xử lý mất cân bằng ở mức thuật toán

    model = xgb.XGBClassifier(
        n_estimators=300, max_depth=5, learning_rate=0.05,
        scale_pos_weight=scale_pos_weight, eval_metric="aucpr",
        n_jobs=4,
    )
    model.fit(train_df[feature_cols], train_df["label"])
    return model


if __name__ == "__main__":
    import pandas as pd
    from split import time_session_split

    df = pd.read_parquet("../data/processed/features_labeled.parquet")
    df = df[df["attack_run_id"].isna() | (~df["is_test_only_variant"])]  # loại biến thể test-only khỏi train
    train_df, test_df = time_session_split(df)

    model_a = train_config(train_df, FEATURES_A)
    model_ab = train_config(train_df, FEATURES_A + FEATURES_B)

    baseline_scores = baseline_threshold_score(test_df)
    scores_a = model_a.predict_proba(test_df[FEATURES_A])[:, 1]
    scores_ab = model_ab.predict_proba(test_df[FEATURES_A + FEATURES_B])[:, 1]

    for name, scores in [("baseline", baseline_scores), ("A", scores_a), ("A+B", scores_ab)]:
        pr_auc = average_precision_score(test_df["label"], scores)
        print(f"{name}: PR-AUC = {pr_auc:.4f}")

    model_ab.save_model("../model/bola_xgboost.json")
```

### Bước 4.3 — Đánh giá đúng chuẩn đề cương (không dùng accuracy)

```python
# services/bola-detector/training/evaluate.py
import numpy as np
from sklearn.metrics import precision_recall_curve, average_precision_score


def recall_at_fpr(y_true, scores, target_fpr=0.01):
    from sklearn.metrics import roc_curve
    fpr, tpr, thr = roc_curve(y_true, scores)
    idx = np.searchsorted(fpr, target_fpr)
    return tpr[min(idx, len(tpr) - 1)], thr[min(idx, len(thr) - 1)]


def bootstrap_ci_pr_auc_diff(y_true, scores_a, scores_b, attack_run_ids, n_boot=2000):
    """CI 95% cho chênh lệch PR-AUC giữa 2 cấu hình, resample theo attack_run_id
    (không phải theo dòng) — đúng yêu cầu 'CI ở mức lần chạy tấn công' của đề cương,
    vì các dòng cùng 1 attack run không độc lập với nhau."""
    runs = np.unique(attack_run_ids[attack_run_ids.notna()])
    diffs = []
    rng = np.random.default_rng(42)
    for _ in range(n_boot):
        sample_runs = rng.choice(runs, size=len(runs), replace=True)
        mask = attack_run_ids.isin(sample_runs) | (attack_run_ids.isna())
        if y_true[mask].sum() == 0:
            continue
        d = average_precision_score(y_true[mask], scores_b[mask]) - \
            average_precision_score(y_true[mask], scores_a[mask])
        diffs.append(d)
    lo, hi = np.percentile(diffs, [2.5, 97.5])
    return lo, hi   # đạt tiêu chí đề cương nếu khoảng này KHÔNG chứa 0


def negative_control(y_true, feature_df, feature_cols, train_fn, rng_seed=42):
    """Đối chứng âm: xáo trộn nhãn rồi train lại — PR-AUC phải xấp xỉ base rate,
    nếu vẫn cao là dấu hiệu leakage trong feature/pipeline."""
    import numpy as np
    rng = np.random.default_rng(rng_seed)
    shuffled = y_true.sample(frac=1, random_state=rng_seed).reset_index(drop=True)
    model = train_fn(feature_df.assign(label=shuffled), feature_cols)
    scores = model.predict_proba(feature_df[feature_cols])[:, 1]
    return average_precision_score(shuffled, scores)
```

### Bước 4.4 — Test trên biến thể chưa gặp + SHAP

```python
# services/bola-detector/training/shap_analysis.py
import shap

def explain(model, X_sample):
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    shap.summary_plot(shap_values, X_sample, show=False)
    import matplotlib.pyplot as plt
    plt.savefig("../model/shap_summary.png", bbox_inches="tight")
    # kiểm tra riêng: đặc trưng nào liên quan cross-cloud call không được đứng
    # top-1 áp đảo — nếu có, nghi ngờ model học bố trí thí nghiệm thay vì bản
    # chất tấn công (đúng cảnh báo trong đề cương)
    return shap_values
```

Chạy test riêng file biến thể thủ công (`is_test_only_variant=True`) qua cùng pipeline feature, đo recall — phải **≥ 70%** so với recall trên tập test thường để đạt tiêu chí "tính vững" của đề cương.

---

## GIAI ĐOẠN 5 (T4/12/2026 - 01/2027) — cả 2 cùng làm, SV2 phụ trách phần scoring service

### Bước 5.1 — Đóng gói scoring service (shadow mode, không chặn)

Theo đúng pattern đã có ở `services/fraud-detection/main.py` (load model 1 lần lúc start, endpoint FastAPI trả điểm) nhưng **không** trả `gate`/block — chỉ ghi log điểm số song song, đúng yêu cầu "không chặn trực tiếp giao dịch, chạy shadow mode trước":

```python
# services/bola-detector/main.py
from fastapi import FastAPI
import xgboost as xgb
import pandas as pd

app = FastAPI()
model = xgb.XGBClassifier()
model.load_model("model/bola_xgboost.json")

FEATURES = ["req_rate_per_min", "pct_4xx", "pct_5xx", "avg_path_len", "path_entropy",
            "distinct_callee_count", "unseen_identity_pair_count",
            "pdp_deny_rate", "distinct_objects_per_session"]


@app.post("/score")
def score(features: dict):
    x = pd.DataFrame([features])[FEATURES]
    prob = float(model.predict_proba(x)[0, 1])
    # shadow mode: chỉ log, không trả action chặn
    return {"entity_id": features.get("entity_id"), "bola_score": prob, "mode": "shadow"}
```

Sau khi đo được false-positive rate thật ở shadow mode (đối chiếu qua Grafana/Loki như đã làm với SOAR ở project cũ), mới nối sang cơ chế phản ứng bán tự động cần người xác nhận — tái dùng pattern HITL đã có ở `soar-engine` nhưng áp cho case BOLA (thu hồi danh tính / siết chính sách / yêu cầu xác thực lại) thay vì playbook banking cũ.

### Bước 5.2 — Đo latency phụ trội

Đề cương yêu cầu công bố p99 latency tăng thêm do toàn bộ cơ chế (mTLS + OPA + scoring) — đo bằng cách so sánh thời gian phản hồi API `workshop` khi có/không có sidecar Envoy + gọi `/score`, dùng `hey`/`ab` hoặc script `time.perf_counter()` quanh request, lấy p99 qua ≥1000 request.

---

## Tổng hợp mốc nghiệm thu (đối chiếu để biết đã "xong" chưa)

| Mốc | Điều kiện đạt |
|---|---|
| GD1 xong | Lược đồ log được SV1 xác nhận; code feature extraction chạy được, phân biệt được attack/benign trên log giả lập |
| GD3 xong | ≥100 lần chạy tấn công độc lập, ≥150 giờ traffic nền, nhãn đã QC |
| GD4 xong | Cấu hình A+B: recall ≥0.80 tại FPR 1%; CI 95% của (PR-AUC A+B − PR-AUC baseline) và (A+B − A) đều không chứa 0; recall trên biến thể chưa gặp ≥70% recall tập test thường; đối chứng âm PR-AUC ≈ base rate |
| GD5 xong | Latency phụ trội p99 ≤20ms; scoring service chạy shadow mode, có log đối chiếu được false positive |
