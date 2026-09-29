import asyncio,time,io,concurrent.futures
import pytest,httpx
from starlette.datastructures import UploadFile
from tests.test_app import client,signin,analyze,HEAD,ORIGIN
from app.main import app
from app.store import Store,RateLimited,digest
from app.core import InputError

def test_rejected_files_consume_processing_quota(client,monkeypatch):
 signin(client);monkeypatch.setenv('USER_HOURLY_LIMIT','1');calls=[]
 def reject(*a):calls.append(1);raise InputError('Rejected synthetic file')
 monkeypatch.setattr('app.main.isolated_extract',reject)
 for status in (400,429):
  r=client.post('/api/analyze',headers=HEAD,data={'consent':'yes'},files={'file':('bad.exe',b'bad')});assert r.status_code==status
 assert len(calls)==1

def test_large_upload_never_rolls_to_disk(client,monkeypatch):
 signin(client);seen=[];original=UploadFile.read
 async def read(self,*a,**k):seen.append(self.file._rolled);return await original(self,*a,**k)
 monkeypatch.setattr(UploadFile,'read',read)
 import tempfile
 def forbidden(*a,**k):raise AssertionError('Upload tried to spill to disk')
 monkeypatch.setattr(tempfile.SpooledTemporaryFile,'rollover',forbidden)
 r=client.post('/api/analyze',headers=HEAD,data={'consent':'yes'},files={'file':('large.txt',b'x'*1100000)})
 assert r.status_code==400 and seen and not any(seen)

def test_login_attempt_storage_bounded_and_valid_other_invite_works(client):
 for i in range(35):
  r=client.post('/api/login',headers=HEAD,json={'code':'X'*43});assert r.status_code==(401 if i<15 else 429)
 with app.state.store.db() as db:
  assert db.execute('SELECT count(*) FROM login_attempts').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM login_buckets').fetchone()[0]==2
  assert max(x[0] for x in db.execute('SELECT count FROM login_buckets'))==15
 signin(client)

def test_login_bucket_flood_has_hard_bound_across_restart(client):
 st=app.state.store
 for i in range(400):
  try:st.redeem(str(i).zfill(43))
  except RateLimited:pass
 with st.db() as db:
  assert db.execute('SELECT count(*) FROM login_buckets').fetchone()[0]==301
  assert db.execute("SELECT count FROM login_buckets WHERE key='global'").fetchone()[0]==300
 again=Store()
 with pytest.raises(RateLimited):again.redeem('y'*43)

def test_bucket_expiry_allows_recovery(client):
 st=app.state.store
 for _ in range(15):st.redeem('X'*43)
 with st.db() as db:db.execute('UPDATE login_buckets SET started=?',(time.time()-301,))
 assert st.redeem('X'*43) is None

def test_orphan_cleanup_preserves_live_users_and_case_ownership(client):
 owner=signin(client);cid=analyze(client).json()['id'];uid=client.get('/api/me').json()['id']
 other=signin(client);otherid=client.get('/api/me').json()['id']
 with app.state.store.db() as db:
  db.execute('UPDATE sessions SET expires=? WHERE user_id=?',(time.time()-1,uid));db.execute('INSERT INTO users VALUES(?,?,?)',('orphan','synthetic','submitter'));app.state.store.purge(db)
  ids={r[0] for r in db.execute('select id from users')};assert uid in ids and otherid in ids and 'orphan' not in ids
  db.execute('UPDATE cases SET expires=?',(time.time()-1,));app.state.store.purge(db)
  assert db.execute('SELECT 1 FROM users WHERE id=?',(uid,)).fetchone() is None

def test_historical_user_cap_recovers(client):
 with app.state.store.db() as db:db.executemany('INSERT INTO users VALUES(?,?,?)',[(str(i),'expired','submitter') for i in range(100)])
 code=app.state.store.invite('new tester','submitter');assert app.state.store.redeem(code)

def test_redemption_capacity_atomic(client):
 st=app.state.store;codes=[st.invite('synthetic','submitter') for _ in range(5)]
 with st.db() as db:
  for i in range(98):
   db.execute('INSERT INTO users VALUES(?,?,?)',(str(i),'active','submitter'));db.execute('INSERT INTO sessions VALUES(?,?,?)',(str(i),str(i),time.time()+500))
 def redeem(code):
  try:return bool(st.redeem(code))
  except RateLimited:return False
 with concurrent.futures.ThreadPoolExecutor(max_workers=5) as e:assert sum(e.map(redeem,codes))==2
 with st.db() as db:assert db.execute('select count(*) from users').fetchone()[0]==100

def test_operator_revoke_user_and_invite(client):
 session=signin(client);cid=analyze(client).json()['id'];uid=client.get('/api/me').json()['id'];code=app.state.store.invite('unused','submitter')
 h=HEAD|{'X-Operator-Key':'operator-testing-key'}
 assert client.post('/api/operator/revoke',headers=HEAD,json={'kind':'user','value':uid}).status_code==403
 assert client.post('/api/operator/revoke',headers=h,json={'kind':'invite','value':code}).status_code==200
 assert client.post('/api/login',headers=HEAD,json={'code':code}).status_code==401
 assert client.post('/api/operator/revoke',headers=h,json={'kind':'user','value':uid}).status_code==200
 assert client.get('/api/me').status_code==401
 with app.state.store.db() as db:assert db.execute('select 1 from cases where id=?',(cid,)).fetchone()

def test_reviewer_cannot_revoke_human_via_agent_endpoint(client):
 owner=signin(client);uid=client.get('/api/me').json()['id'];signin(client,'reviewer')
 assert client.post('/api/agent-token/'+uid+'/revoke',headers=HEAD,json={}).status_code==200
 assert app.state.store.user(owner)

@pytest.mark.parametrize('path,headers,status',[('/',{},200),('/api/me',{},401),('/api/logout',{},403)])
def test_hsts_even_when_tls_terminated_upstream(client,monkeypatch,path,headers,status):
 monkeypatch.setenv('PUBLIC_ORIGIN','https://pilot.example.test')
 r=client.post(path,headers=headers,json={}) if path.endswith('logout') else client.get(path)
 assert r.status_code==status and r.headers['strict-transport-security']=='max-age=31536000'

def test_json_body_smaller_than_upload_limit(client):
 assert client.post('/api/login',headers=HEAD,content=b'x'*32769).status_code==413

@pytest.mark.parametrize('data',[ [('consent','yes'),('consent','yes')], [('consent','yes'),('unexpected','oops')]])
def test_duplicate_or_unknown_fields_rejected(client,data):
 from urllib.parse import urlencode
 signin(client);r=client.post('/api/analyze',headers=HEAD|{'Content-Type':'application/x-www-form-urlencoded'},content=urlencode(data));assert r.status_code==400

def test_slow_upload_does_not_take_model_slots_and_times_out(client,monkeypatch):
 import app.intake as intake
 monkeypatch.setattr(intake,'BODY_IDLE_SECONDS',0.5);monkeypatch.setattr(intake,'BODY_TOTAL_SECONDS',1.0)
 tokens=[signin(client) for _ in range(3)]
 async def go():
  active=[asyncio.Event(),asyncio.Event()];statuses=[]
  async def stalled(i):
   sent=False
   async def receive():
    nonlocal sent
    if not sent:sent=True;return {'type':'http.request','body':b'--x\r\nContent-Disposition: form-data; name="consent"\r\n\r\nyes\r\n','more_body':True}
    active[i].set();await asyncio.sleep(5);return {'type':'http.disconnect'}
   async def send(msg):
    if msg['type']=='http.response.start':statuses.append(msg['status'])
   scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST','scheme':'http','path':'/api/analyze','raw_path':b'/api/analyze','query_string':b'','root_path':'','server':('testserver',80),'client':('synthetic',1),'headers':[(b'host',b'testserver'),(b'origin',ORIGIN.encode()),(b'x-inbox-request',b'1'),(b'cookie',('inbox_session='+tokens[i]).encode()),(b'content-type',b'multipart/form-data; boundary=x')]}
   await app(scope,receive,send)
  tasks=[asyncio.create_task(stalled(i)) for i in range(2)]
  await asyncio.wait_for(asyncio.gather(*(e.wait() for e in active)),2)
  assert app.state.busy==0
  async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url=ORIGIN,cookies={'inbox_session':tokens[2]}) as ac:
   assert (await ac.post('/api/analyze',headers=HEAD,data={'consent':'yes','text':'An ordinary sanitized synthetic test email.'})).status_code==200
  async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url=ORIGIN,cookies={'inbox_session':tokens[0]}) as ac:
   assert (await ac.post('/api/analyze',headers=HEAD,data={'consent':'yes','text':'Same identity should not occupy another slot.'})).status_code==429
  await asyncio.wait_for(asyncio.gather(*tasks),2)
  assert statuses==[408,408]
 asyncio.run(go());assert not app.state.active_users and app.state.busy==0
