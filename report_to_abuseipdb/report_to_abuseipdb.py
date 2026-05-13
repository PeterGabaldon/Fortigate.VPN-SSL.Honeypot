#!/usr/bin/env python3
"""
report_to_abuseipdb.py – Report malicious IPs from SQLite honeypot DB to AbuseIPDB
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import requests
import yaml

API_ENDPOINT = "https://api.abuseipdb.com/api/v2/report"
BASE_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR.parent / "db" / "honeypot.db").resolve()

def abuseipdb_report(api_key: str, ip: str, categories: str, comment: str):
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    data = {
        'ip': ip,
        'categories': categories,
        'comment': comment
    }
    resp = requests.post(API_ENDPOINT, headers=headers, data=data)
    if not resp.ok:
        raise RuntimeError(f"AbuseIPDB {resp.status_code}: {resp.text[:200]}")
    return resp.json()

def sanitize(tag: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", tag).strip("_")

def state_path(tag: str) -> pathlib.Path:
    return BASE_DIR / "abuseipdb_config" / f"state_{sanitize(tag)}.txt"

def load_last_dt(path: pathlib.Path) -> datetime:
    if path.exists():
        try:
            return datetime.fromisoformat(path.read_text().strip())
        except ValueError:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)

def save_last_dt(path: pathlib.Path, dt: datetime):
    path.write_text(dt.isoformat(), encoding="utf-8")

def fetch_new_ips(db: pathlib.Path, since: datetime, hours: int | None):
    if not db.exists():
        print(f"❌ DB not found: {db}", file=sys.stderr)
        sys.exit(1)

    window_start = since
    if hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        if cutoff > window_start:
            window_start = cutoff

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT ip, MIN(ts) AS first_seen
              FROM honeypot_creds
             WHERE ts > ?
          GROUP BY ip
            """,
            (window_start.isoformat(),),
        )
        rows = cur.fetchall()
    except sqlite3.OperationalError as e:
        print(f"❌ DB schema issue: {e}", file=sys.stderr)
        rows = []
    conn.close()

    return [(row["ip"], datetime.fromisoformat(row["first_seen"])) for row in rows]

def main():
    parser = argparse.ArgumentParser(description="Report new malicious IPs to AbuseIPDB")
    parser.add_argument("-c", "--config", type=pathlib.Path, required=True, help="abuseipdb config path")
    parser.add_argument("--db", type=pathlib.Path, default=DEFAULT_DB, help="SQLite DB path")
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    api_key = cfg["abuseipdb_api_key"]
    tag = cfg.get("tag", "FortiGate VPN-SSL Honeypot")
    categories = str(cfg.get("categories", "18,21"))
    comment_tpl = cfg.get("comment", "IP {ip} was seen bruteforcing FortiGate VPN-SSL at {seen} 🛡️")
    hours_window = cfg.get("hours", 24)

    last_dt = load_last_dt(state_path(tag))
    entries = fetch_new_ips(args.db, last_dt, hours_window)
    if not entries:
        print("No new IPs to report.")
        return

    newest_dt = max(seen for _, seen in entries)

    for ip, seen in entries:
        try:
            abuseipdb_report(api_key, ip, categories, comment_tpl.format(ip=ip, seen=seen.isoformat()))
            print(f"✅ {ip}")
        except Exception as e:
            print(f"⚠️  {ip}: {e}", file=sys.stderr)

    save_last_dt(state_path(tag), newest_dt)
    print(f"🗒️  State updated → {newest_dt.isoformat()}")

if __name__ == "__main__":
    main()
