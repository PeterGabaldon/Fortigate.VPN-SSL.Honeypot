from flask import Flask, Response, request, redirect, send_from_directory
from datetime import datetime, timezone
from pathlib import Path

import uuid

app = Flask(__name__)

def make_etag():
    return f'"{uuid.uuid4().hex}"'

@app.route('/', methods=['GET'])
def root():
    html_body = (
        '<html><script type="text/javascript">\n'
        'if (window!=top) top.location=window.location;'
        'top.location="/remote/login";\n'
        '</script></html>'
    )
    # Generate a random ETag for each response
    response = Response(html_body, status=200, mimetype='text/html')
    # Set headers
    response.headers.update({
        'ETag': make_etag(),
        'Accept-Ranges': 'bytes',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000'
    })
    return response

@app.route('/remote/login', methods=['GET'])
def remote_login():
    # Handle default lang redirect
    if 'lang' not in request.args:
        resp = redirect('/remote/login?lang=en', code=303)
        # Redirect headers
        resp.headers.update({
            'Keep-Alive': 'timeout=10, max=99',
            'Connection': 'Keep-Alive',
            'Content-Type': 'text/plain',
            'X-Frame-Options': 'SAMEORIGIN',
            'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000'
        })
        return resp
    # Serve login page for lang=en
    # HTML body omitted for brevity; same as before
    error_div = ''
    if request.args.get('err') == 'sslvpn_login_permission_denied':
        error_div = """
            <div class="error-message" id="err_str">
            <div class="message-content" id="err_val"
            title="sslvpn_login_permission_denied">
            Error: Permission denied.</div></div>
        """
    html_body = f"""<!DOCTYPE html>
<html lang="en" class="main-app">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=8; IE=EDGE">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="apple-itunes-app" content="app-id=1475674905">
        <link href="/styles.css" rel="stylesheet" type="text/css">
        <link href="/css/legacy-main.css" rel="stylesheet" type="text/css">
        <title>Please Login</title>
    </head>
    <body>
        <div class="view-container">
            <form class="prompt legacy-prompt" action="/remote/logincheck" method="post" name="f" autocomplete="off">
                <div class="content with-header with-sslvpn">
                    <div class="sslvpn-left">
                        <img src="/assets/brand-login-left.svg" alt="brand-left" height="500px"/>
                    </div>
                    <div class="sub-content sub-sslvpn">
                        <div class="sslvpn-title">
                            <img src="/assets/sslvpn-portal-login.svg" width="300px" alt="SSL-VPN Portal login" />
                        </div>
                        <div class="wide-inputs">
                            {error_div}
                            <!--remoteauthtimeout=10-->
<input type="text" name="username" id="username" placeholder="Username"><input type="password" name="credential" id="credential" placeholder="Password" maxlength="128"><div class="info-message" id="token_msg" style="display: none;"><div class="message-content" id="token_label"></div></div><input type="password" style="display: none;" maxlength="128" name="credential2" id="credential2"><input type="password" style="display: none;" maxlength="128" name="credential3" id="credential3"><div class="button-actions wide"><button class="primary" type="button" name="ftm_push_button" id="ftm_push_button" onclick="try_ftm_push()    " style="display: none" disabled>Use FTM Push</button></div><input type="password" style="display: none;" placeholder="Token" name="code" id="code"><div id="driftmsg" style="display: none;" class="warning-message">Token clock drift detected. Please input the next code and continue.</div><input type="password" style="display: none;" name="code2" id="code2" placeholder="Next Token Code">
                        </div>
                        <div class="button-actions wide sslvpn-buttons">
                            <button class="primary" type="button" name="login_button" id="login_button" onClick="try_login()">
                                Login
                            </button>
                            <button type="button" name="skip_button" id="skip_button" onClick="try_skip()" style="display:none">
                                Skip
                            </button>
                            <button id="launch-forticlient-button" type="button" onClick="launchFortiClient()">
                                <f-icon class="ftnt-forticlient"></f-icon>
                                <span>Launch FortiClient</span>
                            </button>
                            <iframe id="launch-forticlient-iframe" style="display:none"></iframe>
                            <button id="saml-login-bn" class="primary" type="button" name="saml_login_bn" onClick="launchSamlLogin()"  style="display:none">
                            SSO Login
                            </button>
                        </div>
                    </div>
                    <div class="sslvpn-right">
                        <img src="/assets/brand-login-right.svg" alt="brand-right" height="500px"/>
                    </div>
                </div>
            </form>
        </div>
    </body>
    <input type=hidden name="ftm_push_enabled" id="ftm_push_enabled" value="1"><input type=hidden name=just_logged_in value=1><input type=hidden name=magic id=magic_id value=""><input type=hidden name=reqid id=reqid_id value="0"><input type=hidden name=grpid id=grpid_id value=""><input type=hidden name=realm id=realm_id value=""><input type=hidden name=redir value="/sslvpn/portal/index.html"><input type=hidden name=saml_login id=saml_login_id value="0"><script type="text/javascript" src="/js/legacy_theme_setup.js"></script><script type="text/javascript" src="/sslvpn/js/login.js "></script><script type="text/javascript" src="/remote/fgt_lang?lang=en"></script><script>document.onkeydown = key_pressdown;function load_login_strings() {{var tmp = document.getElementById("err_val");var name = document.getElementById("username");var pass = document.getElementById("credential");if (tmp) {{tmp.innerHTML = fgt_lang["error"] + ": " + fgt_lang[tmp.getAttribute('title')];}}name.placeholder = fgt_lang["Username"];pass.placeholder = fgt_lang["sslvpn_portal::Password"];}}window.onload = load_login_strings;</script>
</html>
"""
    response = Response(html_body, status=200, mimetype='text/html; charset=utf-8')
    # Set expired cookies
    past = datetime(1984, 3, 11, 12, 0)
    response.set_cookie('SVPNCOOKIE', '', path='/', expires=past, secure=True, httponly=True, samesite='Strict')
    response.set_cookie('SVPNNETWORKCOOKIE', '', path='/remote/network', expires=past, secure=True, httponly=True, samesite='Strict')
    # Set headers
    response.headers.update({
        'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        'X-UA-Compatible': 'requiresActiveX=true',
        'Keep-Alive': 'timeout=10, max=98',
        'Connection': 'Keep-Alive',
        'Content-Type': 'text/html; charset=utf-8',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/sslvpn/js/login.js', methods=['GET'])
def login_js():
    # Serve WOFF font from disk
    js_dir = 'js'
    filename = 'login.js'
    # Build response
    response = send_from_directory(js_dir, filename, mimetype='application/x-javascript')
    # Set headers
    response.headers.update({
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'application/x-javascript',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/assets/brand-login-right.svg', methods=['GET'])
def brand_login_right():
    assets_dir = 'assets'
    filename = 'brand-login-right.svg'
    # Build response
    response = send_from_directory(assets_dir, filename, mimetype='image/svg+xml')
    response.headers.update({
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'image/svg+xml',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/assets/brand-login-left.svg', methods=['GET'])
def brand_login_left():
    assets_dir = 'assets'
    filename = 'brand-login-left.svg'
    # Build response
    response = send_from_directory(assets_dir, filename, mimetype='image/svg+xml')
    response.headers.update({
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'image/svg+xml',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/assets/sslvpn-portal-login.svg', methods=['GET'])
def sslvpn_portal_login():
    assets_dir = 'assets'
    filename = 'sslvpn-portal-login.svg'
    # Build response
    response = send_from_directory(assets_dir, filename, mimetype='image/svg+xml')
    response.headers.update({
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'image/svg+xml',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/js/legacy_theme_setup.js', methods=['GET'])
def legacy_theme_setup_js():
    js_dir = 'js'
    filename = 'legacy_theme_setup.js'
    # Build response
    response = send_from_directory(js_dir, filename, mimetype='application/x-javascript')
    response.headers.update({
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'application/x-javascript',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/remote/fgt_lang', methods=['GET'])
def fgt_lang():
    # Language resource bundle
    js_dir = 'js'
    filename = 'fgt_lang?lang=en'
    # Build response
    response = send_from_directory(js_dir, filename, mimetype='application/x-javascript')
    # Match headers
    response.headers.update({
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'application/javascript',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
        'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    })
    return response

@app.route('/styles.css', methods=['GET'])
def styles_css():
    css_dir = 'css'
    filename = 'styles.css'
    # Build response
    response = send_from_directory(css_dir, filename, mimetype='text/css')
    response.headers.update({
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'text/css',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response

@app.route('/css/legacy-main.css', methods=['GET'])
def legacy_main_css():
    css_dir = 'css'
    filename = 'legacy-main.css'
    # Build response
    response = send_from_directory(css_dir, filename, mimetype='text/css')
    response.headers.update({
        'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        'ETag': make_etag(),
        'Cache-Control': 'max-age=0, must-revalidate',
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'text/css',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
    })
    return response   

@app.route('/fonts/ftnt-icons.woff', methods=['GET'])
def ftnt_icons():
    # Serve WOFF font from disk
    font_dir = 'fonts'
    filename = 'ftnt-icons.woff'
    # Build response
    response = send_from_directory(font_dir, filename, mimetype='application/font-woff')
    # Set headers
    response.headers.update({
    'Accept-Ranges': 'bytes',
    'Keep-Alive': 'timeout=10, max=100',
    'Connection': 'Keep-Alive',
    'X-Frame-Options': 'SAMEORIGIN',
    'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
    'X-XSS-Protection': '1; mode=block',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000'
})
    return response

@app.route('/lato-regular.woff2', methods=['GET'])
def ftnt_lato_regultar():
    # Serve WOFF font from disk
    font_dir = 'fonts'
    filename = 'lato-regular.woff2'
    # Build response
    response = send_from_directory(font_dir, filename, mimetype='application/font-woff')
    # Set headers
    response.headers.update({
    'Accept-Ranges': 'bytes',
    'Keep-Alive': 'timeout=10, max=100',
    'Connection': 'Keep-Alive',
    'X-Frame-Options': 'SAMEORIGIN',
    'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
    'X-XSS-Protection': '1; mode=block',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000'
})
    return response    

@app.route('/remote/logincheck', methods=['POST'])
def login_check():
    # Parse raw body for credentials
    data = request.get_data(as_text=True)
    # Example format: "ajax=1&username=test&realm=&credential=test"
    params = dict(item.split('=', 1) for item in data.split('&') if '=' in item)
    username = params.get('username',  '[BLANK USERNAME]')
    password = params.get('credential', '[BLANK PASSWORD]')
    if not username:
        username = '[BLANK USERNAME]'

    if not password:
        password = '[BLANK PASSWORD]'

    # Client IP
    ip = request.headers.get('X-Forwarded-For')
    # Log credentials to file
    log_dir = Path('/var/log/fortihoney')
    log_file = log_dir / 'creds.log'
    date = datetime.now(timezone.utc).isoformat()
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        with log_file.open('a') as f:
            f.write(f"{username}\t{password}\t{ip}\t{date}\n")
    except Exception:
        # If logging fails, ignore to not disrupt response
        pass
    # Prepare response
    past = datetime(1984, 3, 11, 12, 0)
    body = 'ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en'
    response = Response(body, status=200, mimetype='text/plain')
    response.set_cookie('SVPNCOOKIE', '', path='/', expires=past, secure=True, httponly=True, samesite='Strict')
    response.set_cookie('SVPNNETWORKCOOKIE', '', path='/remote/network', expires=past, secure=True, httponly=True, samesite='Strict')
    response.headers.update({
        'ETag': make_etag(),
        'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        'Keep-Alive': 'timeout=10, max=100',
        'Connection': 'Keep-Alive',
        'Content-Type': 'text/plain',
        'Content-Length': str(len(body)),
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000'
    })
    return response

@app.errorhandler(404)
def handle_not_found(e):
    # Return 403 Forbidden for undefined routes
    path = request.path
    html_body = f'''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>403 Forbidden</TITLE>
</HEAD><BODY>
<H1>Forbidden</H1>
You don't have permission to access {path}
on this server.<P>
<P>Additionally, a 400 Bad Request
error was encountered while trying to use an ErrorDocument to handle the request.
</BODY></HTML>'''
    response = Response(html_body, status=403, mimetype='text/html; charset=utf-8')
    # Set headers
    response.headers.update({
        'Date': datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'),
        'Keep-Alive': 'timeout=10, max=99',
        'Connection': 'Keep-Alive',
        'Content-Type': 'text/html; charset=utf-8',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "frame-ancestors 'self'; object-src 'self'; script-src 'self' https: 'unsafe-eval' 'unsafe-inline' blob:;",
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000',
        'Content-Length': str(len(html_body))
    })
    return response    

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

