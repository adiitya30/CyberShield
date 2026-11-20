"""CyberShield cloud dashboard. Read-only telemetry receiver; Python standard library only."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
import os, json, time, base64, hmac
ROOT=os.path.dirname(os.path.abspath(__file__))
LATEST={'received_at':None,'device':None,'system':{'mode':'waiting'},'processes':{'mode':'waiting','items':[]},'connections':{'mode':'waiting','items':[]},'scan':None}
AGENT_TOKEN=os.environ.get('CYBERSHIELD_AGENT_TOKEN','')
DASH_USER=os.environ.get('DASHBOARD_USER','aditya')
DASH_PASS=os.environ.get('DASHBOARD_PASSWORD','')
class Handler(SimpleHTTPRequestHandler):
 def __init__(self,*a,**kw): super().__init__(*a,directory=ROOT,**kw)
 def authorized(self):
  if not DASH_PASS: return False
  raw=self.headers.get('Authorization','')
  if not raw.startswith('Basic '): return False
  try: user,pwd=base64.b64decode(raw[6:]).decode().split(':',1)
  except Exception: return False
  return hmac.compare_digest(user,DASH_USER) and hmac.compare_digest(pwd,DASH_PASS)
 def challenge(self):
  self.send_response(401); self.send_header('WWW-Authenticate','Basic realm="CyberShield Private Dashboard"'); self.send_header('Content-Length','0'); self.end_headers()
 def do_GET(self):
  if not self.authorized(): self.challenge(); return
  p=urlparse(self.path).path
  if p=='/api/health': return self.json({'ok':True,'cloud':True,'agent_connected':bool(LATEST['received_at'] and time.time()-LATEST['received_at']<35),'last_seen':LATEST['received_at']})
  if p=='/api/system': return self.json(LATEST['system'])
  if p=='/api/processes': return self.json(LATEST['processes'])
  if p=='/api/connections': return self.json(LATEST['connections'])
  if p=='/api/scan': return self.json(LATEST['scan'] or {'mode':'unknown','message':'No scan received from the Windows agent yet.'})
  if p=='/api/device': return self.json({'device':LATEST['device'],'received_at':LATEST['received_at'],'connected':bool(LATEST['received_at'] and time.time()-LATEST['received_at']<35)})
  return super().do_GET()
 def do_POST(self):
  if urlparse(self.path).path!='/api/agent/report': self.send_error(404); return
  if not AGENT_TOKEN or not hmac.compare_digest(self.headers.get('Authorization',''), 'Bearer '+AGENT_TOKEN): self.send_error(401,'Agent authentication failed'); return
  try:
   n=int(self.headers.get('Content-Length','0'))
   if n<2 or n>1_000_000: raise ValueError('Invalid payload size')
   data=json.loads(self.rfile.read(n))
   if not isinstance(data,dict): raise ValueError('Invalid payload')
   # Only allow the expected telemetry fields; no arbitrary commands or files.
   LATEST.update({'received_at':time.time(),'device':str(data.get('device','Windows PC'))[:80], 'system':data.get('system',{'mode':'unavailable'}), 'processes':data.get('processes',{'mode':'unavailable','items':[]}), 'connections':data.get('connections',{'mode':'unavailable','items':[]}), 'scan':data.get('scan')})
   self.json({'ok':True,'received_at':LATEST['received_at']})
  except Exception as e: self.send_error(400,'Invalid telemetry: '+str(e))
 def json(self,obj):
  b=json.dumps(obj).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
 def log_message(self,*a): pass
if __name__=='__main__':
 port=int(os.environ.get('PORT','8000'))
 if not DASH_PASS or not AGENT_TOKEN: raise SystemExit('Set DASHBOARD_PASSWORD and CYBERSHIELD_AGENT_TOKEN environment variables before starting.')
 print('CyberShield cloud dashboard listening on port',port)
 ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever()
