
"""CyberShield cloud dashboard.
Secure session login + read-only telemetry receiver.
Python standard library only.
"""

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import os
import json
import time
import base64
import hmac
import hashlib
import secrets

ROOT = os.path.dirname(os.path.abspath(__file__))
SESSION_DURATION = 12 * 60 * 60  # 12 hours

LATEST = {
    'received_at': None,
    'device': None,
    'system': {'mode': 'waiting'},
    'processes': {'mode': 'waiting', 'items': []},
    'connections': {'mode': 'waiting', 'items': []},
    'scan': None
}

AGENT_TOKEN = os.environ.get('CYBERSHIELD_AGENT_TOKEN', '')
DASH_USER = os.environ.get('DASHBOARD_USER', 'aditya')
DASH_PASS = os.environ.get('DASHBOARD_PASSWORD', '')

# Session signatures are derived from server secrets.
SESSION_SECRET = hashlib.sha256(
    (DASH_PASS + AGENT_TOKEN + 'CyberShield-Session').encode()
).digest()


class Handler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def send_security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Cache-Control', 'no-store')

    def json_response(self, obj, status=200):
        data = json.dumps(obj).encode()

        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(data)

    def session_signature(self, expiry):
        message = str(expiry).encode()
        return hmac.new(
            SESSION_SECRET, message, hashlib.sha256
        ).hexdigest()

    def create_session(self):
        expiry = int(time.time()) + SESSION_DURATION
        value = f'{expiry}.{self.session_signature(expiry)}'
        return value

    def session_valid(self):
        cookie_header = self.headers.get('Cookie', '')

        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()

            if not cookie.startswith('cybershield_session='):
                continue

            value = cookie.split('=', 1)[1]

            try:
                expiry_text, signature = value.split('.', 1)
                expiry = int(expiry_text)

                if expiry < int(time.time()):
                    return False

                expected = self.session_signature(expiry)

                return hmac.compare_digest(signature, expected)

            except (ValueError, TypeError):
                return False

        return False

    def set_session_cookie(self, value):
        self.send_header(
            'Set-Cookie',
            'cybershield_session=' + value
            + '; Path=/; HttpOnly; Secure; SameSite=Strict'
        )

    def clear_session_cookie(self):
        self.send_header(
            'Set-Cookie',
            'cybershield_session=; Path=/; Max-Age=0'
            + '; HttpOnly; Secure; SameSite=Strict'
        )

    def login_page(self):
        html = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#080b14">
<title>CyberShield | Secure Login</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;min-height:100vh;display:grid;place-items:center;
 background:radial-gradient(ellipse at top,#14223c,#070a12 65%);
 color:#e8f0ff;font-family:Arial,sans-serif;padding:20px
}
.card{
 width:100%;max-width:390px;padding:34px 26px;border-radius:20px;
 background:#101827;border:1px solid #273851;
 box-shadow:0 20px 80px #0008
}
.logo{font-size:28px;font-weight:800;letter-spacing:2px}
.logo span{color:#42d9ff}
.sub{color:#94a5bf;font-size:13px;margin:8px 0 28px}
label{display:block;font-size:13px;margin:16px 0 8px;color:#b9c8dc}
input{
 width:100%;padding:14px;border-radius:10px;border:1px solid #2b3c55;
 background:#080e19;color:white;outline:none
}
input:focus{border-color:#41cfff}
button{
 width:100%;margin-top:22px;padding:14px;border:0;border-radius:10px;
 background:linear-gradient(90deg,#13b8e9,#536dff);
 color:white;font-weight:bold;font-size:15px;cursor:pointer
}
button:disabled{opacity:.6}
#error{color:#ff7889;min-height:20px;margin-top:14px;font-size:13px}
.foot{margin-top:25px;color:#61728a;font-size:11px;text-align:center}
</style>
</head>
<body>
<div class="card">
 <div class="logo">CYBER<span>SHIELD</span></div>
 <div class="sub">SECURE MONITORING DASHBOARD</div>
 <form id="loginForm">
  <label>Username</label>
  <input id="username" autocomplete="username" required>
  <label>Password</label>
  <input id="password" type="password" autocomplete="current-password" required>
  <button id="btn" type="submit">SECURE LOGIN</button>
  <div id="error"></div>
 </form>
 <div class="foot">AUTHORIZED ACCESS ONLY · CYBERSHIELD</div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',async function(e){
 e.preventDefault();
 const btn=document.getElementById('btn');
 const err=document.getElementById('error');
 btn.disabled=true;
 btn.textContent='VERIFYING...';
 err.textContent='';
 try{
  const r=await fetch('/api/login',{
   method:'POST',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({
    username:document.getElementById('username').value,
    password:document.getElementById('password').value
   })
  });
  const data=await r.json();
  if(!r.ok)throw new Error(data.message||'Login failed');
  location.replace('/');
 }catch(ex){
  err.textContent=ex.message||'Login failed';
  btn.disabled=false;
  btn.textContent='SECURE LOGIN';
 }
});
</script>
</body>
</html>"""

        data = html.encode()

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(data)

    def require_session(self):
        if self.session_valid():
            return True

        self.json_response(
            {'ok': False, 'message': 'Login required'},
            status=401
        )
        return False

    def do_GET(self):
        path = urlparse(self.path).path

        # Custom login page
        if path == '/login':
            if self.session_valid():
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.login_page()
            return

        # Login-required homepage
        if path in ('/', '/index.html'):
            if not self.session_valid():
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return

            return super().do_GET()

        # Frontend resources remain accessible to the login page.
        if path in ('/style.css', '/app.js'):
            return super().do_GET()

        # All dashboard APIs require a valid session.
        if path.startswith('/api/'):
            if not self.require_session():
                return

            if path == '/api/health':
                connected = bool(
                    LATEST['received_at']
                    and time.time() - LATEST['received_at'] < 35
                )
                return self.json_response({
                    'ok': True,
                    'cloud': True,
                    'agent_connected': connected,
                    'last_seen': LATEST['received_at']
                })

            if path == '/api/system':
                return self.json_response(LATEST['system'])

            if path == '/api/processes':
                return self.json_response(LATEST['processes'])

            if path == '/api/connections':
                return self.json_response(LATEST['connections'])

            if path == '/api/scan':
                return self.json_response(
                    LATEST['scan'] or {
                        'mode': 'unknown',
                        'message': 'No scan received from the Windows agent yet.'
                    }
                )

            if path == '/api/device':
                connected = bool(
                    LATEST['received_at']
                    and time.time() - LATEST['received_at'] < 35
                )
                return self.json_response({
                    'device': LATEST['device'],
                    'received_at': LATEST['received_at'],
                    'connected': connected
                })

            self.json_response({'error': 'Not found'}, status=404)
            return

        # Do not expose other files/folders.
        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path

        # Custom login endpoint
        if path == '/api/login':
            try:
                size = int(self.headers.get('Content-Length', '0'))

                if size < 1 or size > 10000:
                    self.json_response(
                        {'ok': False, 'message': 'Invalid request'},
                        status=400
                    )
                    return

                data = json.loads(self.rfile.read(size))
                username = str(data.get('username', ''))
                password = str(data.get('password', ''))

                if (
                    not DASH_PASS
                    or not hmac.compare_digest(username, DASH_USER)
                    or not hmac.compare_digest(password, DASH_PASS)
                ):
                    self.json_response(
                        {'ok': False, 'message': 'Invalid username or password'},
                        status=401
                    )
                    return

                session = self.create_session()

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', '11')
                self.send_security_headers()
                self.set_session_cookie(session)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return

            except Exception:
                self.json_response(
                    {'ok': False, 'message': 'Invalid login request'},
                    status=400
                )
                return

        # Logout endpoint
        if path == '/api/logout':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '11')
            self.send_security_headers()
            self.clear_session_cookie()
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return

        # Windows agent telemetry endpoint
        if path != '/api/agent/report':
            self.send_error(404)
            return

        expected = 'Bearer ' + AGENT_TOKEN

        if (
            not AGENT_TOKEN
            or not hmac.compare_digest(
                self.headers.get('Authorization', ''),
                expected
            )
        ):
            self.send_error(401, 'Agent authentication failed')
            return

        try:
            size = int(self.headers.get('Content-Length', '0'))

            if size < 2 or size > 1_000_000:
                raise ValueError('Invalid payload size')

            data = json.loads(self.rfile.read(size))

            if not isinstance(data, dict):
                raise ValueError('Invalid payload')

            LATEST.update({
                'received_at': time.time(),
                'device': str(data.get('device', 'Windows PC'))[:80],
                'system': data.get('system', {'mode': 'unavailable'}),
                'processes': data.get(
                    'processes', {'mode': 'unavailable', 'items': []}
                ),
                'connections': data.get(
                    'connections', {'mode': 'unavailable', 'items': []}
                ),
                'scan': data.get('scan')
            })

            self.json_response({
                'ok': True,
                'received_at': LATEST['received_at']
            })

        except Exception:
            self.send_error(400, 'Invalid telemetry')

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8000'))

    if not DASH_PASS or not AGENT_TOKEN:
        raise SystemExit(
            'Set DASHBOARD_PASSWORD and '
            'CYBERSHIELD_AGENT_TOKEN environment variables.'
        )

    print('CyberShield cloud dashboard listening on port', port)

    server = ThreadingHTTPServer(('0.0.0.0', port), Handler)
    server.serve_forever()
