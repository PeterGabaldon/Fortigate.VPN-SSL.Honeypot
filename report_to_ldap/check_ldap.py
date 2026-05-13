import sqlite3
import yaml
import os
import smtplib
from email.message import EmailMessage
from ldap3 import Server, Connection, core

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "ldap_config", "ldap_config.yaml")
STATE_FILE = os.path.join(os.path.dirname(__file__), "ldap_config", "state_ldap.txt")
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "honeypot.db")

def load_config():
    if not os.path.exists(CONFIG_PATH):
        fallback = CONFIG_PATH + ".template"
        if os.path.exists(fallback):
            with open(fallback, "r") as f:
                return yaml.safe_load(f)
        return None
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def get_last_timestamp():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    return "0"

def save_last_timestamp(ts):
    with open(STATE_FILE, "w") as f:
        f.write(str(ts))

def send_alert(config, user, password):
    email_cfg = config['alert_email']
    msg = EmailMessage()
    msg['Subject'] = email_cfg['subject']
    msg['From'] = email_cfg['from']
    msg['To'] = ", ".join(email_cfg['to'])
    msg.set_content(f"Alert! Valid credentials compromised.\n\nUser: {user}\nPassword: {password}\n")

    try:
        if email_cfg.get('use_ssl'):
            server = smtplib.SMTP_SSL(email_cfg['smtp_host'], email_cfg['smtp_port'])
        else:
            server = smtplib.SMTP(email_cfg['smtp_host'], email_cfg['smtp_port'])
            server.starttls()

        if email_cfg.get('smtp_user') and email_cfg.get('smtp_pass'):
            server.login(email_cfg['smtp_user'], email_cfg['smtp_pass'])

        server.send_message(msg)
        server.quit()
        print(f"Alert email sent for user: {user}")
    except Exception as e:
        print(f"Failed to send alert email: {e}")

def main():
    config = load_config()
    if not config:
        print("Config not found")
        return

    last_ts = get_last_timestamp()

    try:
        conn_db = sqlite3.connect(DB_PATH)
        cursor = conn_db.cursor()
        cursor.execute("SELECT user, password, ts FROM honeypot_creds WHERE ts > ? ORDER BY ts ASC", (last_ts,))
        records = cursor.fetchall()

        max_ts = last_ts
        checked_creds = set()

        for user, password, ts in records:
            if (user, password) in checked_creds:
                max_ts = max(max_ts, str(ts))
                continue

            checked_creds.add((user, password))

            ldap_cfg = config['ldap']
            domain = ldap_cfg.get('domain', '')
            bind_user = f"{user}@{domain}" if domain else user

            server = Server(ldap_cfg['server'])
            try:
                conn_ldap = Connection(server, user=bind_user, password=password, auto_bind=True)
                print(f"Bind succeeded for {bind_user}")
                # Send email
                send_alert(config, user, password)
                conn_ldap.unbind()
            except core.exceptions.LDAPBindError:
                print(f"Bind failed for {bind_user}")
            except Exception as e:
                print(f"Error connecting to LDAP for {bind_user}: {e}")

            max_ts = max(max_ts, str(ts))

        if records:
            save_last_timestamp(max_ts)

    except Exception as e:
        print(f"Database error: {e}")
    finally:
        if 'conn_db' in locals() and conn_db:
            conn_db.close()

if __name__ == "__main__":
    main()