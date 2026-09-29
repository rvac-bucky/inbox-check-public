import concurrent.futures,time
import pytest
from tests.test_app import client,signin,analyze,HEAD
from app.main import app
from app.store import RateLimited,digest

OP=HEAD|{'X-Operator-Key':'operator-testing-key'}
def link(c):
 r=c.post('/api/enrollment-links',json={'label':'Test group'},headers=OP);assert r.status_code==200;return r.json()
def join(c,code,name='Guest',**extra):return c.post('/api/join',json={'code':code,'name':name,'consent':True,**extra},headers=HEAD)

def test_shared_link_isolation(client):
 l=link(client);assert l['expires']>time.time()+6*86400
 r=join(client,l['code'],'One');assert r.status_code==200 and r.json()['created']
 a=client.cookies.get('inbox_session');u=client.get('/api/me').json();assert u['role']=='submitter'
 cid=analyze(client).json()['id'];client.cookies.clear()
 assert join(client,l['code'],'Two').status_code==200
 v=client.get('/api/me').json();assert u['id']!=v['id'] and v['role']=='submitter'
 assert client.get('/api/cases/'+cid).status_code==404
 assert client.post('/api/cases/'+cid+'/share',json={},headers=HEAD).status_code==404
 assert client.get('/api/enrollment-links',headers=HEAD).status_code==403
 assert client.post('/api/enrollment-links',json={},headers=HEAD).status_code==403
 assert client.post('/api/enrollment-links/'+l['id']+'/revoke',json={},headers=HEAD).status_code==403
 assert client.post('/api/agent-token',json={},headers=HEAD).status_code==403
 assert client.post('/api/invites',json={'role':'reviewer'},headers=HEAD).status_code==403
 client.cookies.set('inbox_session',a);assert client.get('/api/cases/'+cid).status_code==200
 assert client.get('/api/enrollment-links',headers=OP).json()['links'][0]['joins']==2

def test_shared_link_roles_and_expiry(client):
 assert client.get('/api/enrollment-links').status_code==401
 assert client.post('/api/enrollment-links',json={},headers=HEAD).status_code==401
 signin(client,'reviewer');l=client.post('/api/enrollment-links',json={'label':'Group'},headers=HEAD).json()
 assert client.get('/api/enrollment-links',headers=HEAD).json()['links'][0]['code']==l['code']
 client.cookies.clear();assert join(client,l['code'],role='reviewer').status_code==400
 with app.state.store.db() as c:c.execute('UPDATE enrollment_links SET expires=?',(time.time()-1,))
 assert join(client,l['code']).status_code==401
 assert client.get('/api/enrollment-links',headers=OP).json()['links']==[]

def test_revoke_join_keeps_existing_session(client):
 l=link(client);join(client,l['code']);u=client.get('/api/me').json()
 assert client.post('/api/enrollment-links/'+l['id']+'/revoke',json={},headers=OP).status_code==200
 assert client.get('/api/me').json()==u
 assert join(client,l['code'],'Another').status_code==401
 client.cookies.clear();assert join(client,l['code']).status_code==401
 row=client.get('/api/enrollment-links',headers=OP).json()['links'][0];assert not row['enabled'] and 'code' not in row

def test_existing_session_not_replaced(client):
 l=link(client);signin(client,'reviewer');before=client.cookies.get('inbox_session');u=client.get('/api/me').json()
 r=join(client,l['code']);assert r.json()['created'] is False
 assert client.cookies.get('inbox_session')==before and client.get('/api/me').json()==u
 assert client.get('/api/enrollment-links',headers=HEAD).json()['links'][0]['joins']==0

@pytest.mark.parametrize('data',[{}, {'name':''},{'name':' '*5},{'name':'x'*81},{'name':'x\nfoo'},{'name':{}},{'consent':False},{'consent':'yes'},{'code':'short'},{'role':'reviewer'}])
def test_join_validation(client,data):
 l=link(client);body={'code':l['code'],'name':'Good','consent':True};body.update(data)
 if not data:body={}
 assert client.post('/api/join',json=body,headers=HEAD).status_code==400
 with app.state.store.db() as c:assert c.execute('SELECT count(*) FROM users').fetchone()[0]==0

def test_join_csrf_and_cookie_flags(client,monkeypatch):
 l=link(client)
 assert client.post('/api/join',json={'code':l['code'],'name':'Guest','consent':True},headers={'Origin':'https://evil.test','X-Inbox-Request':'1'}).status_code==403
 monkeypatch.delenv('LOCAL_DEV');r=join(client,l['code']);cookie=r.headers['set-cookie'].lower()
 assert all(v in cookie for v in ('secure','httponly','samesite=strict'))

def test_many_valid_joins_not_blocked_by_single_invite_limit(client):
 l=link(client)
 for _ in range(20):
  client.cookies.clear();assert join(client,l['code']).status_code==200
 with app.state.store.db() as c:
  assert c.execute('SELECT count(*) FROM users').fetchone()[0]==20
  assert c.execute('SELECT count(*) FROM login_buckets').fetchone()[0]==2


def test_invalid_joins_bounded(client):
 for i in range(350):
  r=join(client,str(i).zfill(32))
  assert r.status_code in (401,429)
 with app.state.store.db() as c:
  assert c.execute('SELECT count(*) FROM login_buckets').fetchone()[0]<=301
  assert c.execute('SELECT count(*) FROM users').fetchone()[0]==0

def test_concurrent_join_cap_and_role(client):
 l=link(client)
 with app.state.store.db() as c:
  for i in range(98):
   uid=str(i);c.execute('INSERT INTO users VALUES(?,?,?)',(uid,'Existing','submitter'));c.execute('INSERT INTO sessions VALUES(?,?,?)',(digest('s'+uid),uid,time.time()+1000))
 def run(_):
  try:return app.state.store.join_enrollment(l['code'],'Concurrent')
  except RateLimited:return None
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:results=list(ex.map(run,range(5)))
 assert sum(bool(x) for x in results)==2
 with app.state.store.db() as c:assert c.execute('SELECT count(*) FROM users').fetchone()[0]==100


def test_link_storage_encrypted_and_bounded(client):
 l=link(client)
 with app.state.store.db() as c:
  row=c.execute('SELECT secret,hash FROM enrollment_links').fetchone();assert l['code'].encode() not in row['secret'];assert row['hash']==digest(l['code'])
 for _ in range(9):link(client)
 assert client.post('/api/enrollment-links',json={},headers=OP).status_code==429
