import sqlite3
import yaml
import os
import smtplib
import re
import ssl
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ldap3 import Server, Connection, Tls, core
from jinja2 import Environment, FileSystemLoader, select_autoescape

def make_bind_user(user, domain):
    if not user:
        return user
    
    # 1. If username contains '@', do not append @domain
    if "@" in user:
        return user
        
    # 2. If username contains '\', do not append @domain
    if "\\" in user:
        return user
        
    # 3. If username looks like a full DN, e.g. starts with CN=, UID=, OU=, DC=, etc.
    if re.match(r'^(cn|uid|ou|dc|o|c|sn|mail)=', user, re.IGNORECASE):
        return user
        
    # 4. Otherwise, append @domain when domain is configured
    if domain:
        return f"{user}@{domain}"
        
    return user

def looks_like_ldap_dn(user):
    if not user:
        return False
    # Check if starts with common DN prefixes (CN=, UID=, OU=, DC=, etc.)
    if re.match(r'^(cn|uid|ou|dc|o|c|sn|mail)=', user, re.IGNORECASE):
        return True
    # Or contains DN-style comma-separated components (like "cn=xxx,ou=yyy")
    if "," in user and "=" in user:
        return True
    return False

def make_ntlm_bind_user(user, ntlm_domain):
    if not user:
        return user
        
    if "\\" in user:
        return user

    if looks_like_ldap_dn(user):
        raise ValueError("DN-style usernames cannot be used with NTLM authentication")

    if "@" in user:
        return user

    if ntlm_domain:
        # Add comments explaining that ntlm_domain should be the NetBIOS domain name
        # for example EXAMPLE, not necessarily the DNS domain example.local.
        return f"{ntlm_domain}\\{user}"

    return user

def ensure_ntlm_dependencies():
    try:
        from Crypto.Hash import MD4
        _ = MD4
    except ImportError:
        raise ImportError("NTLM authentication requires pycryptodome. Install it with: pip install pycryptodome")


def build_ldap_server(ldap_cfg):
    server_uri = ldap_cfg.get('server', '')
    validate_cert = ldap_cfg.get('validate_cert', True)
    ca_certs_file = ldap_cfg.get('ca_certs_file', None)
    timeout = ldap_cfg.get('timeout', 10)
    start_tls = ldap_cfg.get('start_tls', False)
    
    is_ldaps = server_uri.lower().startswith("ldaps://")
    
    tls_obj = None
    if is_ldaps or start_tls:
        tls_obj = Tls(
            validate=ssl.CERT_REQUIRED if validate_cert else ssl.CERT_NONE,
            ca_certs_file=ca_certs_file
        )
        
    server = Server(
        host=server_uri,
        tls=tls_obj,
        connect_timeout=timeout
    )
    return server

def try_ldap_bind(ldap_cfg, bind_user, password):
    server_uri = ldap_cfg.get('server', '')
    start_tls = ldap_cfg.get('start_tls', False)
    allow_cleartext_simple_bind = ldap_cfg.get('allow_cleartext_simple_bind', False)
    auth_method = ldap_cfg.get('auth_method', 'simple').lower()
    
    if auth_method not in ('simple', 'ntlm'):
        return False, f"Unsupported LDAP auth_method: {auth_method}. Supported values are: simple, ntlm"
        
    is_ldaps = server_uri.lower().startswith("ldaps://")
    is_ldap = server_uri.lower().startswith("ldap://")
    is_cleartext = is_ldap or (not is_ldaps and "://" not in server_uri)
    
    if is_cleartext and not start_tls and not allow_cleartext_simple_bind:
        error_msg = (
            "Cleartext LDAP simple bind is refused by default to prevent credential exposure over the network. "
            "Please configure LDAPS (ldaps://...), enable StartTLS (start_tls: true), or explicitly set "
            "allow_cleartext_simple_bind: true in the configuration."
        )
        return False, error_msg

    try:
        if auth_method == 'ntlm':
            try:
                ensure_ntlm_dependencies()
            except ImportError as e:
                return False, str(e)

        server = build_ldap_server(ldap_cfg)
        
        conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication='NTLM' if auth_method == 'ntlm' else 'SIMPLE',
            auto_bind=False
        )
        
        conn.open()
        
        if start_tls:
            conn.start_tls()
            
        try:
            if not conn.bind():
                error_info = str(conn.result.get('description', 'Unknown LDAP bind error'))
                conn.unbind()
                return False, f"LDAP bind failed: {error_info}"
        except core.exceptions.LDAPBindError as e:
            conn.unbind()
            return False, f"LDAP bind failed: {e}"
            
        return True, conn
        
    except Exception as e:
        return False, f"LDAP connection/bind error: {e}"



CONFIG_PATH = os.path.join(os.path.dirname(__file__), "ldap_config", "ldap_config.yaml")
STATE_FILE = os.path.join(os.path.dirname(__file__), "ldap_config", "state_ldap.txt")
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "honeypot.db")
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "alert_template.html.jinja")

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

def render_html_alert(user, password):
    env = Environment(
        loader=FileSystemLoader(os.path.dirname(TEMPLATE_PATH)),
        autoescape=select_autoescape(["html", "xml", "jinja"])
    )
    template = env.get_template(os.path.basename(TEMPLATE_PATH))
    return template.render(user=user, password=password)

def send_alert(config, user, password):
    email_cfg = config['alert_email']
    msg = MIMEMultipart("alternative")
    msg['Subject'] = email_cfg['subject']
    msg['From'] = email_cfg['from']
    msg['To'] = ", ".join(email_cfg['to'])
    
    # Set headers for high-priority email delivery
    msg['X-Priority'] = '1'
    msg['X-MSMail-Priority'] = 'High'
    msg['Importance'] = 'High'
    
    text_content = f"Alert! Valid credentials compromised.\n\nUser: {user}\nPassword: {password}\n"
    html_content = render_html_alert(user, password)
    
    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

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
    
    ldap_cfg = config.get('ldap')
    if not ldap_cfg:
        print("LDAP configuration not found")
        return
    
    domain = ldap_cfg.get('domain', '')
    server_uri = ldap_cfg.get('server', '')
    start_tls = ldap_cfg.get('start_tls', False)
    allow_cleartext_simple_bind = ldap_cfg.get('allow_cleartext_simple_bind', False)
    auth_method = ldap_cfg.get('auth_method', 'simple').lower()
    
    if auth_method not in ('simple', 'ntlm'):
        print(f"ERROR: Unsupported LDAP auth_method: {auth_method}. Supported values are: simple, ntlm")
        return
        
    # 1. Fast-fail if cleartext simple bind is refused
    is_ldaps = server_uri.lower().startswith("ldaps://")
    is_ldap = server_uri.lower().startswith("ldap://")
    is_cleartext = is_ldap or (not is_ldaps and "://" not in server_uri)
    
    if is_cleartext and not start_tls and not allow_cleartext_simple_bind:
        print(
            "ERROR: Cleartext LDAP simple bind is refused by default to prevent credential exposure over the network.\n"
            "Please configure LDAPS (ldaps://...), enable StartTLS (start_tls: true), or explicitly set "
            "allow_cleartext_simple_bind: true in the configuration."
        )
        return
    
    max_failures = ldap_cfg.get('max_failures_per_user', 3)
    lockout_window = ldap_cfg.get('lockout_window_seconds', 86400)
    
    last_ts = get_last_timestamp()
    
    try:
        conn_db = sqlite3.connect(DB_PATH)
        cursor = conn_db.cursor()
        
        # Ensure the valid_ldap_creds table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS valid_ldap_creds (
                user TEXT,
                password TEXT,
                ts TEXT
            )
        """)
        # Ensure the ldap_attempts table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ldap_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                password TEXT,
                success INTEGER,
                ts TEXT
            )
        """)
        conn_db.commit()
        
        # Prune old attempts outside the lockout window to keep table small
        now = datetime.now(timezone.utc)
        cutoff_ts = (now - timedelta(seconds=lockout_window)).isoformat()
        cursor.execute("DELETE FROM ldap_attempts WHERE ts < ?", (cutoff_ts,))
        conn_db.commit()
        
        cursor.execute("SELECT user, password, ts FROM honeypot_creds WHERE ts > ? ORDER BY ts ASC", (last_ts,))
        records = cursor.fetchall()
        
        max_ts = last_ts
        checked_creds = set()

        for user, password, ts in records:
            if (user, password) in checked_creds:
                max_ts = max(max_ts, str(ts))
                continue
            
            checked_creds.add((user, password))
            
            # 1. Skip if already successfully verified in valid_ldap_creds
            cursor.execute("SELECT 1 FROM valid_ldap_creds WHERE user = ? AND password = ? LIMIT 1", (user, password))
            if cursor.fetchone():
                print(f"Credentials for {user} already verified as valid, skipping bind check.")
                max_ts = max(max_ts, str(ts))
                continue
                
            # 2. Skip if this specific credential combination has already been tried and failed
            cursor.execute("SELECT 1 FROM ldap_attempts WHERE user = ? AND password = ? AND success = 0 LIMIT 1", (user, password))
            if cursor.fetchone():
                print(f"Credentials for {user} (password: [REDACTED]) already checked and failed in the past, skipping bind check.")
                max_ts = max(max_ts, str(ts))
                continue
                
            # 3. Check rate limiting to prevent Active Directory account lockout
            cursor.execute("SELECT COUNT(*) FROM ldap_attempts WHERE user = ? AND success = 0", (user,))
            failed_attempts = cursor.fetchone()[0]
            if failed_attempts >= max_failures:
                print(f"Skipping LDAP bind check for user {user} to prevent lockout (failures in window: {failed_attempts}/{max_failures}).")
                max_ts = max(max_ts, str(ts))
                continue
            
            try:
                if auth_method == 'ntlm':
                    ensure_ntlm_dependencies()
                    ntlm_domain = ldap_cfg.get('ntlm_domain', '')
                    bind_user = make_ntlm_bind_user(user, ntlm_domain)
                else:
                    bind_user = make_bind_user(user, domain)
            except ValueError as ve:
                print(f"Skipping LDAP bind check for user {user}: {ve}")
                max_ts = max(max_ts, str(ts))
                continue
            except ImportError as ie:
                print(f"ERROR: {ie}")
                return

            now_str = datetime.now(timezone.utc).isoformat()
            
            success, result = try_ldap_bind(ldap_cfg, bind_user, password)
            if success:
                conn_ldap = result
                print(f"Bind succeeded for {bind_user}")
                # Save to database for email report
                cursor.execute("INSERT INTO valid_ldap_creds (user, password, ts) VALUES (?, ?, ?)", (user, password, ts))
                cursor.execute("INSERT INTO ldap_attempts (user, password, success, ts) VALUES (?, ?, 1, ?)", (user, password, now_str))
                # Send email
                send_alert(config, user, password)
                conn_ldap.unbind()
            else:
                err_msg = result
                print(f"Bind failed for {bind_user}: {err_msg}")
                # Log actual authentication/bind failures to prevent AD lockout
                if "LDAP bind failed" in err_msg:
                    cursor.execute("INSERT INTO ldap_attempts (user, password, success, ts) VALUES (?, ?, 0, ?)", (user, password, now_str))
                
            max_ts = max(max_ts, str(ts))

        conn_db.commit()

        if records:
            save_last_timestamp(max_ts)
            
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        if 'conn_db' in locals() and conn_db:
            conn_db.close()

if __name__ == "__main__":
    main()