#!/usr/bin/env python3
import sys
import os
import json
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_CREDS = os.environ.get("LOG_CREDS", os.path.join(BASE_DIR, "data", "log", "honey", "creds.log"))
LOG_NGINX = os.environ.get("LOG_NGINX", os.path.join(BASE_DIR, "data", "log", "nginx", "access.log"))
REPORT_DIR = os.environ.get("REPORT_DIR", os.path.join(BASE_DIR, "output_parsing"))
DB_DIR = os.environ.get("DB_DIR", os.path.join(BASE_DIR, "db"))
DB_FILE = os.environ.get("DB_FILE", os.path.join(DB_DIR, "honeypot.db"))

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# a. Create tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS honeypot_creds (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user     TEXT,
  password TEXT,
  ip       TEXT,
  ts       TEXT
)""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS symlink_exploits (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ip   TEXT,
  path TEXT,
  ts   TEXT
)""")
conn.commit()
print(f"🆗 SQLite schema ready ({DB_FILE})")

# b. Read and insert creds
if os.path.exists(LOG_CREDS) and os.path.getsize(LOG_CREDS) > 0:
    creds_data = []
    with open(LOG_CREDS, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 4:
                # user, pass, ip, ts
                ip = parts[2]
                ts = parts[3]
                if ip and ts:
                    creds_data.append((parts[0], parts[1], ip, ts))
    if creds_data:
        cursor.executemany("INSERT INTO honeypot_creds (user, password, ip, ts) VALUES (?, ?, ?, ?)", creds_data)
        conn.commit()
    print("✅ Imported creds.log → honeypot_creds")

# c. Read and insert nginx
if os.path.exists(LOG_NGINX) and os.path.getsize(LOG_NGINX) > 0:
    nginx_data = []
    with open(LOG_NGINX, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                doc = json.loads(line)
                req_uri = doc.get("request_uri", "")
                if req_uri.startswith("/lang/custom/"):
                    ip = doc.get("src_ip")
                    ts = doc.get("time_iso8601")
                    if ip and ts:
                        nginx_data.append((ip, req_uri, ts))
            except json.JSONDecodeError:
                pass
    if nginx_data:
        cursor.executemany("INSERT INTO symlink_exploits (ip, path, ts) VALUES (?, ?, ?)", nginx_data)
        conn.commit()
    print("✅ Imported nginx symlink attempts → symlink_exploits")

# d. Execute SQL queries
def dict_fetchall(cursor):
    return [dict(row) for row in cursor.fetchall()]

cursor.execute("SELECT ip, COUNT(*) as count FROM honeypot_creds GROUP BY ip ORDER BY count DESC")
tests_by_ip = dict_fetchall(cursor)

cursor.execute("SELECT user, password as pass, ip, COUNT(*) as count FROM honeypot_creds GROUP BY user, password, ip ORDER BY count DESC")
tests_by_user_pass_ip = dict_fetchall(cursor)

cursor.execute("SELECT user, COUNT(*) as count FROM honeypot_creds GROUP BY user ORDER BY count DESC")
tests_by_user = dict_fetchall(cursor)

cursor.execute("SELECT password, COUNT(*) as count FROM honeypot_creds GROUP BY password ORDER BY count DESC")
tests_by_password = dict_fetchall(cursor)

cursor.execute("SELECT ip, MIN(ts) as first_seen FROM honeypot_creds GROUP BY ip")
bad_ips = dict_fetchall(cursor)

cursor.execute("SELECT ip, ts as time FROM symlink_exploits")
symlink_exploits = dict_fetchall(cursor)

# f. Print human-readable summaries & write text files
print("Number of username/password test by IP")
print("-----------------------")
for row in tests_by_ip:
    print(f"{row['count']}\t{row['ip']}")
print()

print("Number of username/password test by username,password,IP")
print("-----------------------")
for row in tests_by_user_pass_ip:
    print(f"{row['count']}\t{row['user']},{row['pass']},{row['ip']}")
print()

print("Number of times each username was seen")
print("-----------------------")
for row in tests_by_user:
    print(f"{row['count']}\t{row['user']}")
print()

print("Number of times each password was seen")
print("-----------------------")
for row in tests_by_password:
    print(f"{row['count']}\t{row['password']}")
print()

print("Dumping IPs to bad_ips.txt")
print("-----------------------")
with open(os.path.join(REPORT_DIR, "bad_ips.txt"), "w", encoding="utf-8") as f:
    for row in bad_ips:
        line_out = f"{row['ip']}\t{row['first_seen']}"
        print(line_out)
        f.write(line_out + "\n")
print()

print("Dumping IPs exploiting Symlink Persistence Method to bad_ips_symlink.txt")
print("-----------------------")
with open(os.path.join(REPORT_DIR, "bad_ips_symlink.txt"), "w", encoding="utf-8") as f:
    for row in symlink_exploits:
        line_out = f"{row['ip']}\t{row['time']}"
        print(line_out)
        f.write(line_out + "\n")
print()

# e. Dump to report.json
report = {
    "tests_by_ip": tests_by_ip,
    "tests_by_user_pass_ip": tests_by_user_pass_ip,
    "tests_by_user": tests_by_user,
    "tests_by_password": tests_by_password,
    "bad_ips": bad_ips,
    "symlink_exploits": symlink_exploits
}
with open(os.path.join(REPORT_DIR, "report.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
print(f"✅ JSON report written to {REPORT_DIR}/report.json")

# Truncate logs
open(LOG_CREDS, 'w').close()
open(LOG_NGINX, 'w').close()

print("🗑️  Logs truncated – parse.py complete.")
