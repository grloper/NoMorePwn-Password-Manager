"""Actual Chromium extension; native-message receiver is explicitly intercepted.

All login pages and credentials are fictional/local. No registry changes,
real accounts, external services, installed profiles or production vaults.
"""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlparse
from playwright.sync_api import sync_playwright

REPO=Path(__file__).resolve().parents[1]
ROOT=Path(tempfile.mkdtemp(prefix='nomorepwn-browser-evidence-'))
EXT=REPO/'extension/dist/chrome'
runtime=ROOT/'runtime';runtime.mkdir(exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        parsed=urlparse(self.path)
        mode=parse_qs(parsed.query).get('mode',['valid'])[0]
        body=f'''<!doctype html><title>Local login fixture</title><h1>Fictional local login fixture</h1>
        <form method="post" action="/submit?mode={mode}"><label>Username<input name="username" autocomplete="username"></label>
        <label>Password<input name="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form>'''
        if parsed.path=='/dashboard' and mode=='reject-late':
            self.send_response(401);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(b'<h1>Invalid credentials</h1>');return
        if parsed.path=='/dashboard' and mode in ('chain-cross','chain-login'):
            self.send_response(302)
            location=(f'http://attacker.other.co.uk:{self.server.server_port}/dashboard' if mode=='chain-cross' else '/login?error=1')
            self.send_header('Location',location);self.end_headers();return
        if parsed.path=='/dashboard':body='<h1>Dashboard - local fixture</h1><p>Signed in as audit-user</p>'
        self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(body.encode())
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length',0)))
        mode=parse_qs(urlparse(self.path).query).get('mode',['valid'])[0]
        if mode=='reject':
            self.send_response(401);self.send_header('Content-Type','text/html');self.end_headers();self.wfile.write(b'<h1>Invalid credentials</h1>');return
        self.send_response(303)
        location=f'/dashboard?mode={mode}' if mode!='cross' else f'http://attacker.other.co.uk:{self.server.server_port}/dashboard'
        self.send_header('Location',location);self.send_header('Set-Cookie','session=fixture-only; Path=/');self.end_headers()

server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
results=[]
try:
    with sync_playwright() as pw:
        profile=tempfile.mkdtemp(prefix='nomorepwn-browser-',dir=runtime)
        context=pw.chromium.launch_persistent_context(profile,channel='chromium',headless=True,ignore_default_args=['--disable-extensions'],args=[
            f'--disable-extensions-except={EXT}',f'--load-extension={EXT}',
            '--host-resolver-rules=MAP login.audit.co.uk 127.0.0.1, MAP attacker.other.co.uk 127.0.0.1','--no-proxy-server'])
        try:
            sw=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
            extension_id=sw.url.split('/')[2]
            assert extension_id=='cjgphedkabfdfbhkfleagmanmmhlolkl',extension_id
            # On slow runners (windows-latest CI) Playwright can attach to the worker before Chromium has
            # bound the extension APIs: chrome has only loadTimes/csi and chrome.runtime is undefined.
            # Wait for the real API instead of sleeping a fixed time; never proceed (or stub) without it.
            deadline=time.monotonic()+30
            while True:
                try:
                    if sw.evaluate("() => typeof chrome!=='undefined' && !!chrome.runtime && typeof chrome.runtime.sendNativeMessage==='function'"):break
                except Exception:
                    # worker may have been replaced while starting; follow the newest extension worker
                    live=[w for w in context.service_workers if w.url.startswith('chrome-extension://'+extension_id)]
                    if live:sw=live[-1]
                if time.monotonic()>deadline:
                    raise SystemExit('extension service worker never exposed chrome.runtime.sendNativeMessage (30s)')
                time.sleep(.1)
            print('Worker capabilities:',sw.evaluate('() => ({url:location.href,chrome:Object.keys(globalThis.chrome||{})})'))
            sw.evaluate('''() => { globalThis.auditNative=[]; chrome.runtime.sendNativeMessage=(host,message,callback)=>{
                auditNative.push({host,verified:message.verified===true,unverified:message.unverified===true,targetOrigin:new URL(message.targetUrl).origin});
                callback({type:"ok"}); }; }''')
            for mode in ['valid','reject','cross','reject-late','chain-cross','chain-login']:
                sw.evaluate('() => { auditNative.length=0; }')
                page=context.new_page()
                origin='login.audit.co.uk' if mode=='cross' else '127.0.0.1'
                page.goto(f'http://{origin}:{server.server_port}/login?mode={mode}')
                page.get_by_label('Username').fill('audit-user')
                page.get_by_label('Password').fill('fictional-password-only')
                page.get_by_role('button',name='Sign in').click()
                deadline=time.monotonic()+6
                calls=[]
                while time.monotonic()<deadline:
                    page.wait_for_timeout(100)
                    calls=sw.evaluate('() => auditNative')
                    if calls and mode!='reject':break
                results.append({'mode':mode,'calls':calls,'extension_id':extension_id,'receiver':'intercepted native API, not desktop app'})
                page.close()
        finally:context.close()
finally:server.shutdown();server.server_close()
out=ROOT/('nomorepwn-browser-'+os.environ.get('AUDIT_PHASE','baseline')+'.json')
out.write_text(json.dumps(results,indent=2),encoding='utf-8')
print(json.dumps(results,indent=2))

assert results[0]["calls"] and results[0]["calls"][0]["verified"]
assert results[1]["calls"] == []
assert results[2]["calls"] and all(not c["verified"] and c["unverified"] for c in results[2]["calls"])
assert results[3]["calls"] == []
for result in results[4:]:
    assert result['calls'] and all(not c['verified'] and c['unverified'] for c in result['calls']), result
