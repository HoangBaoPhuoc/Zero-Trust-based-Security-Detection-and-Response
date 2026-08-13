#!/usr/bin/env python3
"""
ZTLab seed_db.py — Reset account balances to NT114 test baseline.

Postgres (postgres-accounts, postgres-txn) only runs on the OpenStack
cluster (see deploy-all.sh) — AWS financial namespace only has Redis.

Usage:
    python3 tests/seed_db.py

Baseline per NT114.Q21.ANTT report §5.1.2:
  ACC-1001 (testuser01) : 1,000,000,000 VND
  ACC-2001 (testuser02) :   250,000,000 VND
  ACC-3001 (internal)   :   100,000,000 VND
  ACC-4001 (merchant01) :    26,750,000 VND
  ACC-5001 (analyst01)  :    10,000,000 VND
"""
import argparse
import subprocess
import sys

SEED_SQL = """
UPDATE accounts SET balance = 1000000000.0 WHERE account_id = 'ACC-1001';
UPDATE accounts SET balance =  250000000.0 WHERE account_id = 'ACC-2001';
UPDATE accounts SET balance =  100000000.0 WHERE account_id = 'ACC-3001';
UPDATE accounts SET balance =   26750000.0 WHERE account_id = 'ACC-4001';
UPDATE accounts SET balance =   10000000.0 WHERE account_id = 'ACC-5001';
SELECT account_id, owner, balance FROM accounts ORDER BY account_id;
"""

CLUSTERS = {
    "openstack": ("ctx-openstack", "financial", "deploy/postgres-accounts"),
}

TXN_SQL_CLEAR = "DELETE FROM ledger;"


def run_sql(context: str, namespace: str, deploy: str, sql: str, label: str) -> bool:
    cmd = [
        "kubectl", "--context", context,
        "exec", "-n", namespace, deploy, "--",
        "psql", "-U", "accounts_user", "-d", "accounts_db", "-c", sql,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[{label}] ERROR: {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"[{label}] OK\n{result.stdout.strip()}")
    return True


def clear_txn_ledger(context: str, namespace: str, label: str) -> bool:
    cmd = [
        "kubectl", "--context", context,
        "exec", "-n", namespace, "deploy/postgres-txn", "--",
        "psql", "-U", "txn_user", "-d", "transactions_db", "-c", TXN_SQL_CLEAR,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[{label}:txn] WARN: {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"[{label}:txn] ledger cleared")
    return True


def seed_cloud(cloud: str) -> bool:
    context, namespace, deploy = CLUSTERS[cloud]
    label = cloud.upper()
    ok = run_sql(context, namespace, deploy, SEED_SQL, label)
    clear_txn_ledger(context, namespace, label)
    return ok


def main():
    parser = argparse.ArgumentParser(description="Reset ZTLab test DB to NT114 baseline")
    parser.parse_args()

    if seed_cloud("openstack"):
        print("\n[seed_db] Seeded successfully.")
    else:
        print("\n[seed_db] Seeding failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
