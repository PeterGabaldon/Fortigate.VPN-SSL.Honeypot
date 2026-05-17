#!/usr/bin/env python3
"""
report_to_vt.py – Report malicious IPs from SQLite honeypot DB to VirusTotal
============================================================================
* Schema (raw tables):
    • honeypot_creds(id, user, password, ip, ts)
* We pull DISTINCT IPs whose earliest `ts` is newer than the per‑tag state‑file
  timestamp (and within the optional `hours` window; default 24).
* For each IP we:
    1. Down‑vote (verdict=malicious)
    2. Comment with a template containing {ip} and {seen}
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import vt
import yaml

BASE_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR.parent / "db" / "honeypot.db").resolve()

# ──────────────────────────── VT wrappers ───────────────────────────────────

def vt_downvote(client: vt.Client, ip: str):
    client.post(f"/ip_addresses/{ip}/votes", json_data={"data": {"type": "vote", "attributes": {"verdict": "malicious"}}})


def vt_comment(client: vt.Client, ip: str, text: str):
    client.post(f"/ip_addresses/{ip}/comments", json_data={"data": {"type": "comment", "attributes": {"text": text}}})


def vt_add_to_collection(client: vt.Client, collection_id: str, ip: str):
    client.post(f"/collections/{collection_id}/items", json_data={"data": [{"type": "ip_address", "id": ip}]})

# ──────────────────────────── State file ────────────────────────────────────

def sanitize(tag: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", tag).strip("_")


def state_path(tag: str) -> pathlib.Path:
    return BASE_DIR / "vt_config" / f"state_{sanitize(tag)}.txt"


def load_last_dt(path: pathlib.Path) -> datetime:
    if path.exists():
        try:
            return datetime.fromisoformat(path.read_text().strip())
        except ValueError:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def save_last_dt(path: pathlib.Path, dt: datetime):
    path.write_text(dt.isoformat(), encoding="utf-8")

# ─────────────────────── Fetch IPs from honeypot_creds ──────────────────────

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

# ─────────────────────────────── Main ───────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Report new malicious IPs to VirusTotal")
    parser.add_argument("-c", "--config", type=pathlib.Path, required=True, help="vt_config.yaml path")
    parser.add_argument("--db", type=pathlib.Path, default=DEFAULT_DB, help="SQLite DB path")
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    api_key = cfg["vt_api_key"]
    tag = cfg.get("tag", "FortiGate VPN-SSL Honeypot")
    comment_tpl = cfg.get("comment", "IP {ip} seen at {seen}")
    hours_window = cfg.get("hours", 24)
    collection_id = cfg.get("collection_id")

    last_dt = load_last_dt(state_path(tag))
    entries = fetch_new_ips(args.db, last_dt, hours_window)
    if not entries:
        print("No new IPs to report.")
        return

    newest_dt = max(seen for _, seen in entries)

    client = vt.Client(api_key)
    try:
        for ip, seen in entries:
            try:
                vt_downvote(client, ip)
                vt_comment(client, ip, comment_tpl.format(ip=ip, seen=seen.isoformat()))
                if collection_id:
                    try:
                        vt_add_to_collection(client, collection_id, ip)
                    except Exception as e:
                        print(f"⚠️  {ip} (collection): {e}", file=sys.stderr)
                print(f"✅ {ip}")
            except Exception as e:
                print(f"⚠️  {ip}: {e}", file=sys.stderr)
    finally:
        client.close()

    save_last_dt(state_path(tag), newest_dt)
    print(f"🗒️  State updated → {newest_dt.isoformat()}")


if __name__ == "__main__":
    main()
