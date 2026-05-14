#!/usr/bin/env bash

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_CREDS="$BASE_DIR/data/log/honey/creds.log"
LOG_NGINX="$BASE_DIR/data/log/nginx/access.log"
REPORT_DIR="$BASE_DIR/output_parsing"
DB_DIR="$BASE_DIR/db"
DB_FILE="$DB_DIR/honeypot.db"

mkdir -p "$REPORT_DIR" "$DB_DIR"

###############################################################################
# 1) ORIGINAL PARSING (unchanged) -------------------------------------------
###############################################################################
# Tests by IP
tests_by_ip=$(awk -F'\t' '{count[$3]++} END{for (ip in count) printf "{\"ip\":\"%s\",\"count\":%d}\n", ip, count[ip]}' "$LOG_CREDS" \
  | sort -t: -k2 -nr \
  | jq -s '.')

# Tests by user,pass,IP
tests_by_user_pass_ip=$(awk -F'\t' '{count[$1"\t"$2"\t"$3]++} END{for (key in count) { split(key,a,"\t"); printf "{\"user\":\"%s\",\"pass\":\"%s\",\"ip\":\"%s\",\"count\":%d}\n", a[1],a[2],a[3],count[key] }}' "$LOG_CREDS" \
  | sort -t: -k4 -nr \
  | jq -s '.')

# Number of times each username was seen
tests_by_user=$(awk -F'\t' '{count[$1]++} END{for (u in count) printf "{\"user\":\"%s\",\"count\":%d}\n", u, count[u]}' "$LOG_CREDS" \
  | sort -t: -k2 -nr \
  | jq -s '.')

# Number of times each password was seen
tests_by_password=$(awk -F'\t' '{count[$2]++} END{for (p in count) printf "{\"password\":\"%s\",\"count\":%d}\n", p, count[p]}' "$LOG_CREDS" \
  | sort -t: -k2 -nr \
  | jq -s '.')

# Bad IPs list
bad_ips_list=$(awk -F'\t' '{print $3, $4}' "$LOG_CREDS" | sort -u \
  | awk '{printf "{\"ip\":\"%s\",\"first_seen\":\"%s\"}\n", $1, $2}' \
  | jq -s '.')

# Symlink exploit IPs from Nginx JSON log
symlink_list=$(jq -r 'select(.request_uri|startswith("/lang/custom/")) | {ip:.src_ip, time:.time_iso8601}' \
                   "$LOG_NGINX" \
                | jq -s '.')

# 2) Human-readable output
echo "Number of username/password test by IP"
echo "-----------------------"
echo "$tests_by_ip" | jq -r '.[] | "\(.count)\t\(.ip)"'
echo

echo "Number of username/password test by username,password,IP"
echo "-----------------------"
echo "$tests_by_user_pass_ip" | jq -r '.[] | "\(.count)\t\(.user),\(.pass),\(.ip)"'
echo

echo "Number of times each username was seen"
echo "-----------------------"
echo "$tests_by_user" | jq -r '.[] | "\(.count)\t\(.user)"'
echo

echo "Number of times each password was seen"
echo "-----------------------"
echo "$tests_by_password" | jq -r '.[] | "\(.count)\t\(.password)"'
echo

echo "Dumping IPs to bad_ips.txt"
echo "-----------------------"
echo "$bad_ips_list" | jq -r '.[] | "\(.ip)\t\(.first_seen)"' \
  | tee output_parsing/bad_ips.txt
echo

echo "Dumping IPs exploiting Symlink Persistence Method to bad_ips_symlink.txt"
echo "-----------------------"
echo "$symlink_list" | jq -r '.[] | "\(.ip)\t\(.time)"' \
  | tee output_parsing/bad_ips_symlink.txt
echo

# Build combined JSON (for legacy file consumers)
jq -n \
  --argjson tests_by_ip           "$tests_by_ip" \
  --argjson tests_by_user_pass_ip "$tests_by_user_pass_ip" \
  --argjson tests_by_user         "$tests_by_user" \
  --argjson tests_by_password     "$tests_by_password" \
  --argjson bad_ips               "$bad_ips_list" \
  --argjson symlink_exploits      "$symlink_list" \
  '{tests_by_ip: $tests_by_ip,
    tests_by_user_pass_ip: $tests_by_user_pass_ip,
    tests_by_user: $tests_by_user,
    tests_by_password: $tests_by_password,
    bad_ips: $bad_ips,
    symlink_exploits: $symlink_exploits}' \
  > "$REPORT_DIR/report.json"

echo "✅ JSON report written to $REPORT_DIR/report.json"

###############################################################################
# 2) Create SQLITE --------------------------------------------------------
###############################################################################
sqlite3 "$DB_FILE" <<'SQL'
BEGIN;
CREATE TABLE IF NOT EXISTS honeypot_creds (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user     TEXT,
  password TEXT,
  ip       TEXT,
  ts       TEXT            -- ISO‑8601 string
);
CREATE TABLE IF NOT EXISTS symlink_exploits (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ip   TEXT,
  path TEXT,
  ts   TEXT
);
COMMIT;
SQL

echo "🆗 SQLite schema ready ($DB_FILE)"

###############################################################################
# 3) Ingest creds.log --------------------------------------------------------
###############################################################################
if [[ -s "$LOG_CREDS" ]]; then
  # Use Python for safe parameterized insertion into SQLite
  python3 <<PYEOF
import sqlite3
import os
import sys

db_file = os.environ.get('DB_FILE', "$DB_FILE")
log_file = os.environ.get('LOG_CREDS', "$LOG_CREDS")

if not os.path.exists(log_file):
    sys.exit(0)

conn = sqlite3.connect(db_file)
cursor = conn.cursor()

with open(log_file, 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.strip('\n').split('\t')
        if len(parts) >= 4:
            # user, pass, ip, ts
            cursor.execute("INSERT INTO honeypot_creds (user, password, ip, ts) VALUES (?, ?, ?, ?)",
                           (parts[0], parts[1], parts[2], parts[3]))
conn.commit()
conn.close()
PYEOF
  echo "✅ Imported creds.log → honeypot_creds"
fi

###############################################################################
# 4) Ingest symlink exploits from nginx JSON log ----------------------------
###############################################################################
if [[ -s "$LOG_NGINX" ]]; then
  jq -c 'select(.request_uri|startswith("/lang/custom/")) | {ip:.src_ip, path:.request_uri, ts:.time_iso8601}' "$LOG_NGINX" |
  python3 <<PYEOF
import sqlite3
import os
import sys
import json

db_file = os.environ.get('DB_FILE', "$DB_FILE")

conn = sqlite3.connect(db_file)
cursor = conn.cursor()

for line in sys.stdin:
    try:
        doc = json.loads(line)
        cursor.execute("INSERT INTO symlink_exploits (ip, path, ts) VALUES (?, ?, ?)",
                       (doc.get('ip'), doc.get('path'), doc.get('ts')))
    except Exception:
        continue
conn.commit()
conn.close()
PYEOF
  echo "✅ Imported nginx symlink attempts → symlink_exploits"
fi

###############################################################################
# 5) Truncate logs so they aren’t re‑processed next run ----------------------
###############################################################################
: > "$LOG_CREDS"
: > "$LOG_NGINX"

echo "🗑️  Logs truncated – parse.sh complete."

