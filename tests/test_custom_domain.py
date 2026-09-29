import pytest
from tests.test_app import client,signin,HEAD
from app.main import app

NEW='https://testmyemail.rvacyber.com'
OLD='https://rva-inboxcheck.azurewebsites.net'

def config(monkeypatch):
    monkeypatch.setenv('PUBLIC_ORIGIN',NEW)
    monkeypatch.setenv('ADDITIONAL_PUBLIC_ORIGINS',OLD)

@pytest.mark.parametrize('origin',[NEW,OLD])
def test_matching_hosts_allowed(client,monkeypatch,origin):
    config(monkeypatch)
    code=app.state.store.invite('Domain test','submitter')
    headers={'Origin':origin,'X-Inbox-Request':'1'}
    assert client.post(origin+'/api/login',headers=headers,json={'code':code}).status_code==200
    assert client.get(origin+'/api/me').json()['invite_origin']==NEW
    other=OLD if origin==NEW else NEW
    assert client.get(other+'/api/me').status_code==401
    assert client.post(other+'/api/login',headers={'Origin':other,'X-Inbox-Request':'1'},json={'code':code}).status_code==401
    assert client.post(origin+'/api/logout',headers=headers,json={}).status_code==200

@pytest.mark.parametrize('host,origin',[(OLD,NEW),(NEW,OLD),(NEW,'https://evil.test'),(NEW,'https://news.rvacyber.com'),(NEW,NEW+'.evil.test'),(NEW,'null'),(NEW,'http://testmyemail.rvacyber.com'),(NEW,NEW+'/'),(NEW,'')])
def test_origin_boundaries(client,monkeypatch,host,origin):
    config(monkeypatch)
    r=client.post(host+'/api/logout',headers={'Origin':origin,'X-Inbox-Request':'1','X-Forwarded-Host':'testmyemail.rvacyber.com'},json={})
    assert r.status_code==403

def test_header_required(client,monkeypatch):
    config(monkeypatch)
    assert client.post(NEW+'/api/logout',headers={'Origin':NEW},json={}).status_code==403

def test_canonical_invite_origin(client,monkeypatch):
    signin(client,'reviewer')
    config(monkeypatch)
    assert client.get('/api/me').json()['invite_origin']==NEW

def test_single_origin_default_still_works(client):
    signin(client)
    assert client.post('/api/logout',headers=HEAD,json={}).status_code==200


@pytest.mark.parametrize('origin',[NEW,OLD])
def test_shared_enrollment_both_domains(client,monkeypatch,origin):
    config(monkeypatch)
    link=app.state.store.create_enrollment('Domain pilot')
    h={'Origin':origin,'X-Inbox-Request':'1'}
    r=client.post(origin+'/api/join',headers=h,json={'code':link['code'],'name':'Guest','consent':True})
    assert r.status_code==200 and r.json()['created']
    u=client.get(origin+'/api/me').json();assert u['role']=='submitter' and u['invite_origin']==NEW
    other=OLD if origin==NEW else NEW
    assert client.get(other+'/api/me').status_code==401
    assert client.post(other+'/api/join',headers=h,json={'code':link['code'],'name':'Guest','consent':True}).status_code==403
    r=client.post(other+'/api/join',headers={'Origin':other,'X-Inbox-Request':'1'},json={'code':link['code'],'name':'Other browser domain','consent':True})
    assert r.status_code==200
    assert client.get(other+'/api/me').json()['id']!=u['id']

def test_forwarded_host_cannot_authorize_wrong_host(client,monkeypatch):
    config(monkeypatch)
    r=client.post(OLD+'/api/join',headers={'Origin':NEW,'X-Inbox-Request':'1','X-Forwarded-Host':'testmyemail.rvacyber.com'},json={'code':'x'*32,'name':'Guest','consent':True})
    assert r.status_code==403
