#!/usr/bin/env python3
"""
send_report.py (v2) – Render honeypot statistics from **SQLite** and send an HTML
report via e‑mail.

Changes vs v1
-------------
• Pulls data from `data/db/honeypot.db` instead of `report.json`.
• Time‑window filtering: default **last 24h** (override with `--hours N`).
• Same config YAML structure (subject / smtp creds). No change needed.
• Keeps Jinja2 template logic – but data now comes from SQL aggregates.
"""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import sqlite3
import ssl
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import unquote_plus

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

# ---------------------------------------------------------------------------
# Paths / template
BASE_DIR = pathlib.Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "db" / "honeypot.db"
EXFIL_FILE = BASE_DIR.parent / "exfiltrated_passwords.txt"
DEFAULT_TEMPLATE = BASE_DIR / "email_template.html.jinja"

# ---------------------------------------------------------------------------
# Helpers

def ensure_template(path: pathlib.Path):
    if path.exists():
        return
    path.write_text("""<!DOCTYPE html><html><head><meta charset='utf-8'><style>body{font-family:Segoe UI,system-ui,sans-serif;background:#f9fafb;color:#111827;margin:0;padding:1rem}h1{text-align:center}h2{color:#2563eb}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{padding:.4rem .6rem;border-bottom:1px solid #e5e7eb;text-align:left}th{background:#f3f4f6}</style></head><body><h1>{{ subject }}</h1>{% for title,key in sections %}<h2>{{ title }}</h2><table><thead><tr>{% for col in headers[key] %}<th>{{ col }}</th>{% endfor %}</tr></thead><tbody>{% for row in data[key] %}<tr>{% for col in headers[key] %}<td>{{ row[col_map[key][loop.index0]] }}</td>{% endfor %}</tr>{% endfor %}</tbody></table>{% endfor %}</body></html>""", encoding="utf-8")


def load_yaml(path: pathlib.Path):
    return yaml.safe_load(path.read_text())


def load_exfil() -> set[str]:
    if EXFIL_FILE.exists():
        return {line.strip() for line in EXFIL_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}
    return set()

###############################################################################
# DB query – now derived from RAW tables                                      #
###############################################################################
def query_db(start_iso: str, exfil_set: set[str]):
    """
    Return the six sections the e-mail expects, but computed on-the-fly
    from *honeypot_creds* and *symlink_exploits*.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    sections: dict[str, list] = {}

    # ── 1. Attempts by IP ────────────────────────────────────────────────────
    cur.execute(
        """
        SELECT ip, ts, COUNT(*) AS count
          FROM honeypot_creds
         WHERE ts >= ?
      GROUP BY ip
      ORDER BY count DESC
        """,
        (start_iso,),
    )
    sections["tests_by_ip"] = [dict(r) for r in cur.fetchall()]

    # ── 2. Attempts by user / pass / IP ──────────────────────────────────────
    cur.execute(
        """
        SELECT user, password AS pass, ip, COUNT(*) AS count
          FROM honeypot_creds
         WHERE ts >= ?
      GROUP BY user, password, ip
      ORDER BY count DESC
        """,
        (start_iso,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        r["user"] = unquote_plus(r["user"])
        r["pass"] = unquote_plus(r["pass"])
    sections["tests_by_user_pass_ip"] = rows

    # ── 3. Attempts by user ──────────────────────────────────────────────────
    cur.execute(
        """
        SELECT user, COUNT(*) AS count
          FROM honeypot_creds
         WHERE ts >= ?
      GROUP BY user
      ORDER BY count DESC
        """,
        (start_iso,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        r["user"] = unquote_plus(r["user"])
    sections["tests_by_user"] = rows

    # ── 4. Attempts by password ──────────────────────────────────────────────
    cur.execute(
        """
        SELECT password, COUNT(*) AS count
          FROM honeypot_creds
         WHERE ts >= ?
      GROUP BY password
      ORDER BY count DESC
        """,
        (start_iso,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        r["password"] = unquote_plus(r["password"])
    sections["tests_by_password"] = rows

    # ── 5. Symlink exploit attempts (IP · PATH · COUNT) ─────────────────────────
    cur.execute(
        """
        SELECT ip, path, ts, COUNT(*) AS count
          FROM symlink_exploits
         WHERE ts >= ?
      GROUP BY ip, path
      ORDER BY count DESC
        """,
        (start_iso,),
    )
    sections["symlink_exploits"] = [dict(r) for r in cur.fetchall()]

    # ── 6. “Bad IPs” list (unique IPs in the window) ────────────────────────
    cur.execute(
        """
        SELECT DISTINCT ip
          FROM honeypot_creds
         WHERE ts >= ?
        """,
        (start_iso,),
    )
    sections["bad_ips"] = [dict(r) for r in cur.fetchall()]

    # 7) Exfiltrated creds section
    if exfil_set:
        cur.execute(
            """SELECT user, password AS pass, ip, ts FROM honeypot_creds WHERE ts >= ? AND password IN ({})""".format(
                ",".join(["?"] * len(exfil_set))
            ),
            (start_iso, *exfil_set),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r["user"] = unquote_plus(r["user"])
            r["pass"] = unquote_plus(r["pass"])
        sections["exfil_creds"] = rows
    else:
        sections["exfil_creds"] = []

    conn.close()
    return sections


def render_html(template_path: pathlib.Path, ctx: dict[str, object]) -> str:
    env = Environment(loader=FileSystemLoader(str(template_path.parent)), autoescape=select_autoescape(["html", "xml"]))
    return env.get_template(template_path.name).render(**ctx)


def send_email(cfg: dict, html_body: str):
    smtp_cfg = cfg["smtp"]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = cfg["subject"]
    msg["From"] = cfg.get("from", smtp_cfg["username"])
    msg["To"] = ", ".join(cfg["to"]) if isinstance(cfg["to"], list) else cfg["to"]

    msg.attach(MIMEText("This report is best viewed in HTML.", "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    context = ssl.create_default_context()
    if smtp_cfg.get("use_ssl", True):
        with smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg["port"], context=context) as s:
            s.login(smtp_cfg["username"], smtp_cfg["password"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"]) as s:
            s.starttls(context=context)
            s.login(smtp_cfg["username"], smtp_cfg["password"])
            s.send_message(msg)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Send honeypot e‑mail report from SQLite data")
    p.add_argument("--config", type=pathlib.Path, default=BASE_DIR / "email_config.yaml")
    p.add_argument("--hours", type=int, default=24, help="Time window (h) – default last 24h")
    p.add_argument("--template", type=pathlib.Path, default=DEFAULT_TEMPLATE)
    return p.parse_args()


def main():
    args = parse_args()

    ensure_template(args.template)

    cfg = load_yaml(args.config)

    start_dt = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=args.hours)
    exfil_pwds = load_exfil()
    sections = query_db(start_dt.isoformat(), exfil_pwds)

    # Context for Jinja2 template rendering
    ctx = {
        "subject": cfg["subject"],
        "data": sections,
        # Map table headings for convenience in default template
        "headers": {
            "tests_by_ip": ["IP", "count", "Timestamp"],
            "tests_by_user_pass_ip": ["user", "pass", "ip", "count"],
            "tests_by_user": ["user", "count"],
            "tests_by_password": ["pass", "count"],
            "symlink_exploits": ["IP", "path", "count", "Timestamp"],
            "bad_ips": ["IP"],
            "exfil_creds": ["user", "password", "IP", "timestamp"]
        },
        "sections": [
            ("🌐 Attempts by IP", "tests_by_ip"),
            ("🧑‍💻 Attempts by User / Pass / IP", "tests_by_user_pass_ip"),
            ("👤 Attempts by User", "tests_by_user"),
            ("🔑 Attempts by Password", "tests_by_password"),
            ("⚠️ Symlink Exploit Attempts", "symlink_exploits"),
            ("⛔ Bad IPs", "bad_ips"),
            ("💥 Exfiltrated Credentials", "exfil_creds")
        ],
        # mapping for default template to iterate over values conveniently
        "col_map": {
            "tests_by_ip": ["ip", "count", "ts"],
            "tests_by_user_pass_ip": ["user", "pass", "ip", "count"],
            "tests_by_user": ["user", "count"],
            "tests_by_password": ["password", "count"],
            "symlink_exploits": ["ip", "path", "count", "ts"],
            "bad_ips": ["ip"],
            "exfil_creds": ["user", "pass", "ip", "ts"]
        }
    }

    html_body = render_html(args.template, ctx)
    send_email(cfg, html_body)
    print("✅ E‑mail report sent (last", args.hours, "h)")


if __name__ == "__main__":
    main()
