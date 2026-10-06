import io,json,os,time
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from PIL import Image
from app.core import extract_file, InputError, ProviderError, verdict, SIGNALS
from app.main import app

ORIGIN='http://testserver'
HEAD={'origin':ORIGIN,'x-inbox-request':'1'}

def answers(**over):
    a={k:{'noul':0.0} for k in SIGNALS};a['risk']={'choice':'no_obvious_warning_signs'}
    for k,v in over.items():a[k]={'noul':v}
    return a

class Fake:
    def ocr(self,image):return 'From: payroll@example.test\nSend your password to claim your pay.',{'prompt_tokens':10}
    def classify(self,text):return verdict(answers(requests_secrets=.99)),{'model':'mock/jev','usage':{'input_tokens':10,'output_tokens':5,'cost':0}}
    def explain(self,text,assessment):return {'summary':'A password request is a warning sign.','evidence':['Requests a password.'],'next_steps':['Verify independently.'],'limitations':'Identity is not authenticated.'},{'prompt_tokens':30,'completion_tokens':20}

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv('EVIDENCE_SELECTION','ai')
    monkeypatch.setenv('DB_PATH',str(tmp_path/'cases.db'));monkeypatch.setenv('DATA_ENCRYPTION_KEY',Fernet.generate_key().decode());monkeypatch.setenv('LOCAL_DEV','1');monkeypatch.setenv('PUBLIC_ORIGIN',ORIGIN);monkeypatch.setenv('BOOTSTRAP_KEY','operator-testing-key')
    with TestClient(app) as c:
        app.state.models=Fake();yield c

def signin(c,role='submitter'):
    code=app.state.store.invite('Test '+role,role)
    r=c.post('/api/login',json={'code':code},headers=HEAD);assert r.status_code==200
    return c.cookies.get('inbox_session')

def analyze(c):return c.post('/api/analyze',data={'consent':'yes','text':'Urgent! Send your password to claim your wages.'},headers=HEAD)

def test_auth_and_headers(client):
    assert client.get('/api/me').status_code==401
    r=client.get('/');assert r.status_code==200
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']
    assert 'no-store' in r.headers['cache-control']
    assert client.post('/api/analyze',headers=HEAD).status_code==401

@pytest.mark.parametrize('headers',[{}, {'origin':'https://evil.test','x-inbox-request':'1'},{'origin':ORIGIN}])
def test_csrf(client,headers):
    signin(client);assert client.post('/api/logout',json={},headers=headers).status_code==403

def test_invite_single_use(client):
    code=app.state.store.invite('person','submitter')
    assert client.post('/api/login',json={'code':code},headers=HEAD).status_code==200
    assert client.post('/api/login',json={'code':code},headers=HEAD).status_code==401

def test_role_escalation(client):
    signin(client)
    assert client.post('/api/invites',json={'role':'reviewer'},headers=HEAD).status_code==403
    signin(client,'reviewer')
    assert client.post('/api/invites',json={'role':'reviewer'},headers=HEAD).status_code==403
    assert client.post('/api/invites',json={'name':'Friend'},headers=HEAD).status_code==200

def test_review_isolation_delete(client):
    owner=signin(client);r=analyze(client);assert r.status_code==200;r=r.json();cid=r['id']
    assert r['payload']['assessment']['risk']=='likely_phishing'
    signin(client);assert client.get('/api/cases/'+cid).status_code==404
    assert client.post('/api/cases/'+cid+'/share',headers=HEAD,json={}).status_code==404
    reviewer=signin(client,'reviewer');assert client.get('/api/cases/'+cid).status_code==404
    client.cookies.set('inbox_session',owner)
    assert client.post('/api/cases/'+cid+'/share',headers=HEAD,json={}).status_code==200
    client.cookies.set('inbox_session',reviewer)
    assert client.get('/api/cases/'+cid).status_code==200
    assert client.post('/api/cases/'+cid+'/delete',headers=HEAD,json={}).status_code==404
    assert client.post('/api/cases/'+cid+'/review',headers=HEAD,json={'note':'Escalate to IT by known channel.'}).status_code==200
    client.cookies.set('inbox_session',owner)
    assert client.get('/api/cases/'+cid).json()['payload']['review']['note'].startswith('Escalate')
    assert client.post('/api/cases/'+cid+'/delete',headers=HEAD,json={}).status_code==200
    assert client.get('/api/cases/'+cid).status_code==404

def test_encryption_expiry(client):
    signin(client);cid=analyze(client).json()['id']
    raw=open(app.state.store.path,'rb').read();assert b'claim your wages' not in raw
    with app.state.store.db() as c:c.execute('UPDATE cases SET expires=?',(time.time()-1,))
    assert client.get('/api/cases/'+cid).status_code==404

def test_fail_closed(client):
    signin(client)
    def broken(t):raise ProviderError('Jev unavailable')
    app.state.models.classify=broken
    assert analyze(client).status_code==503
    assert client.get('/api/cases').json()['cases']==[]

def test_explanation_fallback(client):
    signin(client)
    def broken(*args):raise ProviderError('Azure unavailable')
    app.state.models.explain=broken
    r=analyze(client);assert r.status_code==200;assert r.json()['payload']['explanation_fallback'] is True

def test_limit(client,monkeypatch):
    monkeypatch.setenv('USER_HOURLY_LIMIT','1');signin(client)
    assert analyze(client).status_code==200
    assert analyze(client).status_code==429

def test_input_validation(client):
    signin(client)
    assert client.post('/api/analyze',data={'text':'a'*30},headers=HEAD).status_code==400
    assert client.post('/api/analyze',data={'consent':'yes','text':'a'*50001},headers=HEAD).status_code==400
    assert client.post('/api/analyze',data={'consent':'yes'},files={'file':('payload.exe',b'x')},headers=HEAD).status_code==400
    assert client.post('/api/analyze',data={'consent':'yes','text':'a'*30},files={'file':('a.txt',b'hello')},headers=HEAD).status_code==400
    assert client.post('/api/analyze',content=b'x'*(8*1024*1024+65537),headers=HEAD).status_code==413

def outlook_msg(props):
    """Minimal Outlook .msg (CFB v3, every stream in the mini stream) from {'__substg1.0_...': bytes}."""
    import struct
    E,F,FS=0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFD
    streams=sorted({'__properties_version1.0':b'\0'*32,**props}.items(),key=lambda kv:(len(kv[0]),kv[0].upper()))
    mini=b'';minifat=[];starts=[]
    for _,data in streams:
        n=max(1,-(-len(data)//64));first=len(minifat);starts.append(first)
        minifat+=[first+i+1 for i in range(n-1)]+[E];mini+=data.ljust(n*64,b'\0')
    def entry(name,kind,right,child,start,size):
        raw=name.encode('utf-16-le')+b'\0\0'
        return raw.ljust(64,b'\0')+struct.pack('<HBBIII16sIQQIQ',len(raw),kind,1,F,right,child,b'',0,0,0,start,size)
    ndir=-(-(len(streams)+1)//4);nmf=-(-len(minifat)*4//512);nms=-(-len(mini)//512)
    dirs=entry('Root Entry',5,F,1,ndir+nmf,len(mini))
    for i,(name,data) in enumerate(streams):dirs+=entry(name,2,i+2 if i+1<len(streams) else F,F,starts[i],len(data))
    dirs=dirs.ljust(ndir*512,b'\0')
    chain=lambda a,n:[a+i+1 for i in range(n-1)]+[E]
    fat=chain(0,ndir)+chain(ndir,nmf)+chain(ndir+nmf,nms)+[FS];fat+=[F]*(128-len(fat))
    head=b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'+b'\0'*16+struct.pack('<HHHHH6sIIIIIIIII',0x3E,3,0xFFFE,9,6,b'',0,1,0,0,4096,ndir,nmf,E,0)
    head+=struct.pack('<I',ndir+nmf+nms)+struct.pack('<I',F)*108
    return head+dirs+struct.pack('<%dI'%len(minifat),*minifat).ljust(nmf*512,b'\xff')+mini.ljust(nms*512,b'\0')+struct.pack('<128I',*fat)

def u(s):return s.encode('utf-16-le')

def test_outlook_msg_upload(client):
    msg=outlook_msg({'__substg1.0_0037001F':u('Payroll update'),'__substg1.0_0C1A001F':u('Payroll Team'),
        '__substg1.0_5D01001F':u('payroll@example.test'),'__substg1.0_0E04001F':u('Pat Doe'),
        '__substg1.0_1000001F':u('Please reply with your password and MFA code today.')})
    text,im,source=extract_file(msg,'Payroll update.msg')
    assert text.splitlines()[:4]==['From: Payroll Team <payroll@example.test>','Reply-To: ','To: Pat Doe','Subject: Payroll update']
    assert 'MFA code' in text and im is None and source.startswith('Outlook email file')
    signin(client)
    r=client.post('/api/analyze',data={'consent':'yes'},files={'file':('Payroll update.msg',msg)},headers=HEAD)
    assert r.status_code==200 and r.json()['payload']['source'].startswith('Outlook email file')

def test_outlook_msg_headers_and_html_body():
    hdrs='From: "IT Desk" <helpdesk@evil.test>\r\nReply-To: collect@evil.test\r\nTo: pat@example.test\r\n\r\n'
    html=b'<p>Your mailbox is full.</p><a href="https://evil.test">Fix now</a><script>execute()</script>'
    text,_,_=extract_file(outlook_msg({'__substg1.0_007D001F':u(hdrs),'__substg1.0_0037001F':u('Mailbox full'),
        '__substg1.0_0C1A001F':u('IT Desk'),'__substg1.0_10130102':html}),'x.MSG')
    assert 'From: IT Desk <helpdesk@evil.test>' in text and 'Reply-To: collect@evil.test' in text
    assert 'Your mailbox is full.' in text and 'execute()' not in text

@pytest.mark.parametrize('data,reason',[(b'From: a@example.test\nSubject: plain text renamed',"This MSG file could not be read."),
    ('ole-no-body','No readable email body found.')])
def test_bad_outlook_msg(data,reason):
    if data=='ole-no-body':data=outlook_msg({'__substg1.0_0037001F':u('Empty')})
    with pytest.raises(InputError,match=reason):extract_file(data,'x.msg')

def test_rejected_upload_says_why(client):
    signin(client)
    r=client.post('/api/analyze',data={'consent':'yes'},files={'file':('photo.heic',b'x'*64)},headers=HEAD)
    assert r.status_code==400 and 'Supported files' in r.json()['detail']
    r=client.post('/api/analyze',data={'consent':'yes'},files={'file':('outlook.msg',b'From: a@example.test\nnot outlook')},headers=HEAD)
    assert r.status_code==400 and r.json()['detail']=='This MSG file could not be read.'
    r=client.post('/api/analyze',data={'consent':'yes'},files={'file':('long.txt',b'x'*50001)},headers=HEAD)
    assert r.status_code==400 and '50,000' in r.json()['detail']

def test_image(client):
    signin(client);b=io.BytesIO();Image.new('RGB',(100,100),'white').save(b,'PNG')
    r=client.post('/api/analyze',data={'consent':'yes'},files={'file':('shot.png',b.getvalue())},headers=HEAD)
    assert r.status_code==200 and r.json()['payload']['source']=='screenshot'

@pytest.mark.parametrize('name,data',[('a.svg',b'<svg/>'),('x.png',b'not image'),('x.txt',b'\xff'),('x.pdf',b'not pdf')])
def test_bad_files(name,data):
    with pytest.raises(InputError):extract_file(data,name)

def test_eml_does_not_follow_html():
    data=b'From: Fake <fake@example.test>\nSubject: Hello\nContent-Type: text/html\n\n<p>Hello test email</p><a href="https://example.test">Click</a><script>execute()</script>'
    text,im,_=extract_file(data,'a.eml');assert 'execute()' not in text and 'declared link' in text and im is None

@pytest.mark.parametrize('value',[float('nan'),float('inf'),-1,1.1,True,'0.5'])
def test_classifier_output_bounds(value):
    with pytest.raises(ProviderError):verdict(answers(coercion=value))

def test_logout_revokes(client):
    token=signin(client);assert client.post('/api/logout',json={},headers=HEAD).status_code==200
    assert app.state.store.user(token) is None

def test_agent_submission_and_revocation(client):
    signin(client,'reviewer')
    r=client.post('/api/agent-token',json={'name':'Contest demo'},headers=HEAD);assert r.status_code==200
    token=r.json()['token'];uid=r.json()['id']
    agentheaders=HEAD|{'Authorization':'Bearer '+token}
    client.cookies.clear()
    assert client.get('/api/cases',headers=agentheaders).status_code==401
    r=client.post('/api/agent/analyze',json={'text':'Send your password to claim your payroll funds.','sanitized':True,'share':True},headers=agentheaders)
    assert r.status_code==200 and r.json()['shared'] is True
    assert 'text' not in r.json()
    cid=r.json()['case_id'];signin(client,'reviewer')
    assert client.get('/api/cases/'+cid).status_code==200
    assert client.post('/api/agent-token/'+uid+'/revoke',json={},headers=HEAD).status_code==200
    assert client.post('/api/agent/analyze',json={'text':'example email text content longer than twenty characters','sanitized':True},headers=agentheaders).status_code==401

def test_high_risk_not_downgraded_by_missing_evidence():
    assert verdict(answers(requests_secrets=.95,insufficient=.8))['risk']=='likely_phishing'

def test_case_escaping_static(client):
    js=client.get('/static/app.js').text
    assert 'innerHTML' not in js and 'textContent' in js


def test_isolated_parser(client):
    from app.main import isolated_extract
    text,image,source=isolated_extract(b'Example message body for extraction test.','x.txt')
    assert text.startswith('Example') and image is None


def test_open_guest_access(client):
    assert client.get('/api/me').status_code==401
    r=client.post('/api/guest',json={},headers=HEAD);assert r.status_code==200 and r.json()['created'] is True
    assert client.get('/api/me').json()['role']=='guest'
    # Same browser keeps its session; no invitation needed to check a message.
    assert client.post('/api/guest',json={},headers=HEAD).json()['created'] is False
    assert analyze(client).status_code==200
    # Guests cannot invite or see the reviewer queue tools.
    assert client.post('/api/invites',json={'name':'x'},headers=HEAD).status_code==403
    assert client.post('/api/guest',headers={}).status_code==403  # CSRF rules still apply

def test_guests_do_not_consume_pilot_seats(client,monkeypatch):
    from app import store as store_mod
    for _ in range(105):app.state.store.start_guest()
    assert app.state.store.invite('Reviewer','reviewer')

def test_long_thread_under_limit_is_accepted(client):
    signin(client)
    thread='From: a@example.test\nSubject: Re: invoice\n\n'+('> earlier reply line in a long quoted thread\n'*1100)
    assert 45000<len(thread)<50000
    assert client.post('/api/analyze',data={'consent':'yes','text':thread},headers=HEAD).status_code==200
