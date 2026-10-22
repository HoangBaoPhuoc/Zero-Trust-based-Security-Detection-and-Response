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
