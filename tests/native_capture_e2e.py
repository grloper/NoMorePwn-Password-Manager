"""Real offscreen app/controller + native-host child + Qt local IPC.
Only a task-owned fictional vault and isolated per-process socket identity.
No browser registration, startup changes, provider calls or real credentials.
"""
from pathlib import Path
import json, os, struct, subprocess, sys, tempfile, threading, time, uuid

REPO=Path(__file__).resolve().parents[1]
ROOT=Path(tempfile.mkdtemp(prefix='nomorepwn-native-evidence-'))
runtime=ROOT/'runtime';runtime.mkdir(exist_ok=True)
data=Path(tempfile.mkdtemp(prefix='nomorepwn-vault-',dir=runtime))
identity='AuditNoMorePwn'+uuid.uuid4().hex
os.environ.update(NOMOREPWN_DATA=str(data),QT_QPA_PLATFORM='offscreen')
for name in ('LOGNAME','USER','LNAME','USERNAME'):os.environ[name]=identity
repo=REPO
sys.path.insert(0,str(repo));os.environ['PYTHONPATH']=str(repo)
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFontDatabase
from PySide6.QtNetwork import QLocalServer
from nomorepwn import vault,config
from nomorepwn.settings import Settings
from nomorepwn_app.controller import AppController

master='fictional audit master 42!'
Settings(updates_enabled=False,backup_enabled=False,show_notifications=False,
         lock_on_minimize=False,autolock_minutes=0).save()
vault.create_vault(config.DB_PATH,master)
seed=vault.Vault.unlock(config.DB_PATH,master)
for service,user in [('code.example.invalid','demo-engineer'),('mail.example.invalid','demo-user'),('cloud.example.invalid','demo-operator')]:
    seed.add_credential(service,user,'fictional-not-a-real-secret',group_name='Demo accounts')
seed.lock()
app=QApplication([]);app.setQuitOnLastWindowClosed(False)
for font_name in ('segoeui.ttf','segoeuib.ttf','consola.ttf'):
    font=Path(os.environ.get('WINDIR',''))/'Fonts'/font_name
    if font.exists():QFontDatabase.addApplicationFont(str(font))
ctrl=AppController(app)
server=QLocalServer();assert server.listen('NoMorePwn-instance-'+identity)
connections=[]
def accept():
    conn=server.nextPendingConnection();connections.append(conn)
    def handle():
        reply=ctrl.handle_ipc_message(conn.readAll().data())
        if reply:conn.write(reply);conn.flush()
        conn.disconnectFromServer()
    conn.readyRead.connect(handle)
server.newConnection.connect(accept)
ctrl.start()

def pump_until(predicate,seconds=15):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline and not predicate():app.processEvents();time.sleep(.01)
    assert predicate(),'timed out'

def unlock():
    ctrl.window._unlock.pw.setText(master)
    ctrl.window._unlock.unlock_btn.click()
    pump_until(lambda:ctrl.vault is not None)

def request(payload):
    encoded=json.dumps(payload).encode();framed=struct.pack('<I',len(encoded))+encoded
    output={}
    def run():
        p=subprocess.run([sys.executable,'-m','nomorepwn_app','--native-host'],input=framed,capture_output=True,cwd=repo,timeout=15)
        output.update(stdout=p.stdout,stderr=p.stderr,code=p.returncode)
    thread=threading.Thread(target=run);thread.start();pump_until(lambda:not thread.is_alive(),20);thread.join()
    assert output['code']==0,output['stderr'].decode(errors='replace')
    size=struct.unpack('<I',output['stdout'][:4])[0]
    return json.loads(output['stdout'][4:4+size])

results=[]
try:
    unlock()
    results.append({'scenario':'ping real native child','reply':request({'type':'ping'})})
    before=len(ctrl.vault.list_credentials())
    response=request({'type':'save-credential','verified':True,'targetUrl':'https://capture.example.invalid/login',
                      'username':'demo-captured','password':'fictional-capture-secret'})
    after=len(ctrl.vault.list_credentials())
    results.append({'scenario':'real IPC save','reply':response,'before':before,'after':after})
    response=request({'type':'save-credential','verified':True,'targetUrl':'http://127.0.0.1:12345/login',
                      'username':'demo-local','password':'fictional-local-secret'})
    results.append({'scenario':'loopback host-port save','reply':response,'count':len(ctrl.vault.list_credentials())})
    for _ in range(30):app.processEvents();time.sleep(.01)
    (ROOT/'images').mkdir(parents=True,exist_ok=True)
    from PySide6.QtCore import Qt
    listing=ctrl.window._shell.vault_view.list
    for index in range(listing.count()):
        if listing.item(index).data(Qt.UserRole) is not None:
            listing.setCurrentRow(index);break
    app.processEvents()
    ctrl.window.grab().save(str(ROOT/'images/nomorepwn-actual-vault.png'))
    ctrl.window._shell._group.button(2).click()
    app.processEvents()
    ctrl.window.grab().save(str(ROOT/'images/nomorepwn-actual-generator.png'))
    ctrl.window._shell._group.button(1).click()
    for _ in range(40):app.processEvents();time.sleep(.01)
    ctrl.window.grab().save(str(ROOT/'images/nomorepwn-actual-security.png'))
    ctrl.lock(manual=True)
    response=request({'type':'save-credential','verified':True,'targetUrl':'https://queued.example.invalid/login',
                      'username':'demo-queued','password':'fictional-queued-secret'})
    results.append({'scenario':'locked vault capture rejected','reply':response,'plaintext_queue_exists':hasattr(ctrl,'_pending_captures')})
    unlock()
    results.append({'scenario':'unlock does not silently persist a rejected capture','count':len(ctrl.vault.list_credentials())})
    results.append({'scenario':'invalid capture reports failure','reply':request({'type':'save-credential','verified':True,
                    'targetUrl':'https://invalid.example.invalid/login','username':'invalid user','password':'fixture-only'})})
    assert results[1]['after']==results[1]['before']+1
    assert results[3]['reply']['code']=='vault-locked'
    assert results[-1]['reply']['code']=='capture-not-saved'
    assert b'fictional-capture-secret' not in config.DB_PATH.read_bytes()
finally:
    if ctrl.vault:ctrl.lock(manual=True)
    server.close();ctrl.tray.tray.hide();ctrl.window.hide();app.processEvents()
    (ROOT/('nomorepwn-native-'+os.environ.get('AUDIT_PHASE','baseline')+'.json')).write_text(json.dumps(results,indent=2),encoding='utf-8')
print(json.dumps(results,indent=2))
