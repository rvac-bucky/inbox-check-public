import pytest
from cryptography.fernet import Fernet
from app.configuration import errors

def valid():
 return dict(DATA_ENCRYPTION_KEY=Fernet.generate_key().decode(),BOOTSTRAP_KEY='a'*48,PUBLIC_ORIGIN='https://check.example.org',OPENROUTER_API_KEY='test',AI_BASE_URL='https://api.example.org/v1',AI_API_KEY='test',AI_MODEL='vision-model')

def test_valid_byo_setup():assert errors(valid())==[]

@pytest.mark.parametrize('changes',[{'PUBLIC_ORIGIN':'http://check.example.org'}, {'PUBLIC_ORIGIN':'https://u:p@check.example.org'}, {'PUBLIC_ORIGIN':'https://check.example.org/path'}, {'LOCAL_DEV':'1'},{'MAILCHECK_MAILBOX':'test@example.org'},{'DATA_ENCRYPTION_KEY':'bad'},{'AI_BASE_URL':'http://api.example.org/v1'},{'AI_MODEL':''},{'SCREENING_ROUTE':'misspelled'}])
def test_invalid_configuration_names_not_values(changes):
 env=valid();env.update(changes)
 result=errors(env)
 assert result and 'https://u:p@' not in str(result)

def test_complete_byo_mailbox():
 env=valid();env.update(MAILCHECK_TENANT_ID='tenant',MAILCHECK_CLIENT_ID='client',MAILCHECK_CLIENT_SECRET='secret',MAILCHECK_MAILBOX='test@my-domain.example')
 assert errors(env)==[]

def test_compatible_api_uses_own_endpoint_and_key(monkeypatch):
 import httpx,json
 from app.core import Models
 monkeypatch.setenv('AI_BASE_URL','https://api.example.org/v1')
 monkeypatch.setenv('AI_API_KEY','synthetic-only-key')
 monkeypatch.setenv('AI_MODEL','vision-json')
 calls=[]
 class Client:
  def __init__(self,*a,**k):pass
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def post(self,url,headers,json):
   calls.append((url,headers,json))
   return httpx.Response(200,json={'choices':[{'finish_reason':'stop','message':{'content':'{"readable":true,"text":"A synthetic note"}'}}],'usage':{}},request=httpx.Request('POST',url))
 monkeypatch.setattr(httpx,'Client',Client)
 value,_=Models().azure_call('Extract text','synthetic')
 assert value['readable'] and calls[0][0]=='https://api.example.org/v1/chat/completions'
 assert calls[0][1]['Authorization']=='Bearer synthetic-only-key' and calls[0][2]['model']=='vision-json'
 assert 'api-key' not in calls[0][1]
