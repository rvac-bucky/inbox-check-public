import json
import pytest
from app.core import Models,ProviderError,verdict,SIGNALS
from app.privacy import redact
from app.main import app
from tests.test_app import client,signin,HEAD,answers

def a(risk='suspicious',confidence=.18,**kw):
    out=answers(**kw);out['risk']={'choice':risk,'confidence':confidence};return out

def test_incomplete_fragment_routes_unknown():
    d=verdict(a(insufficient=.78))
    assert d['risk']=='insufficient_evidence'
    assert d['decision']['raw_choice']=='suspicious' and d['decision']['rule']=='insufficient_or_uncertain'

@pytest.mark.parametrize('risk',['suspicious','likely_phishing','no_obvious_warning_signs'])
def test_uncertainty_not_adverse_evidence(risk):
    assert verdict(a(risk,confidence=.1))['risk']=='insufficient_evidence'

@pytest.mark.parametrize('signal,value,expected',[('requests_secrets',.99,'likely_phishing'),('payment_pressure',.99,'suspicious'),('identity_mismatch',.99,'suspicious')])
def test_concrete_threat_not_hidden_by_unknown(signal,value,expected):
    assert verdict(a('insufficient_evidence',.01,insufficient=.95,**{signal:value}))['risk']==expected

@pytest.mark.parametrize('value',[float('nan'),True,-.1,1.1,'0.5'])
def test_confidence_requires_valid_number(value):
    with pytest.raises(ProviderError):verdict(a(confidence=value))

def test_bad_probability_distribution():
    out=a();out['risk']['probabilities']={'suspicious':.5}
    with pytest.raises(ProviderError):verdict(out)

@pytest.mark.parametrize('text,secret',[
 ('Your sign-in code is 123456. Do not share it.','123456'),
 ('Verification code: 123 456','123 456'),
 ('Your recovery code is ABCD-1234-EFGH','ABCD-1234-EFGH'),
 ('Password: correct-horse-battery-staple','correct-horse-battery-staple'),
 ('Your verification code\n654321','654321'),
 ('Use this OTP: 123-456','123-456'),
 ('API key: sk-abcdefghijklmnopqrst12345','sk-abcdefghijklmnopqrst12345'),
 ('-----BEGIN PRIVATE KEY-----\nDUMMY\n-----END PRIVATE KEY-----','DUMMY')])
def test_secret_redaction(text,secret):assert secret not in redact(text)

def test_redaction_retains_threat_semantics_and_normal_amount():
    assert 'Reply with your password' in redact('Reply with your password and MFA code now.')
    assert '$25' in redact('Invoice amount $25 due tomorrow.')

def test_azure_cannot_write_advice_or_claims():
    assessment=verdict(answers())
    m=Models();m.azure_call=lambda *a,**kw:({'evidence_ids':['1'],'summary':'Verified sender','next_steps':['Type the email URL']},{})
    with pytest.raises(ProviderError):m.explain('Synthetic newsletter.',assessment)

def test_generated_selection_is_grounded_and_cautions_not_rejected():
    assessment=verdict(answers());m=Models()
    m.azure_call=lambda *a,**kw:({'evidence_ids':['1']},{})
    r,u=m.explain('We cannot tell whether the email is safe.',assessment)
    assert r['evidence']==['Email excerpt (unverified): “We cannot tell whether the email is safe.”']
    assert 'does not establish authenticity' in r['summary']
    assert any('saved bookmark' in x for x in r['next_steps'])

def test_code_redacted_before_azure_and_not_echoed():
    m=Models();captured=[]
    def call(system,content,**kw):
        captured.append(content);return {'evidence_ids':['1']},{}
    m.azure_call=call
    r,_=m.explain('Your sign-in code is 123456. Open https://example.test.',verdict(answers()))
    assert '123456' not in str(captured)+str(r)
    assert 'https://' not in str(captured)+str(r)

def test_application_masks_before_classifier_storage(client):
    signin(client)
    original=app.state.models.classify;seen=[]
    def classify(text):seen.append(text);return original(text)
    app.state.models.classify=classify
    r=client.post('/api/analyze',headers=HEAD,data={'consent':'yes','text':'Your requested sign-in code is 123456. Do not share it.'})
    assert r.status_code==200 and '123456' not in str(seen)+r.text
    stored=app.state.store.get(r.json()['id'],app.state.store.user(client.cookies.get('inbox_session')))
    assert '123456' not in str(stored)

def test_historical_cases_get_safe_guidance_without_rewriting(client):
    signin(client)
    user=app.state.store.user(client.cookies.get('inbox_session'))
    payload={'text':'Your verification code is 123456.','assessment':verdict(answers()),'explanation':{'summary':'This email is authentic','next_steps':['Type the URL']},'explanation_fallback':False}
    cid=app.state.store.save(user['id'],payload)
    r=client.get('/api/cases/'+cid).json()['payload']
    assert '123456' not in r['text'] and 'authentic' not in r['explanation']['summary'].replace('authenticity','')
    assert r['explanation_status']['reason']=='legacy_guidance'
    assert app.state.store.get(cid,user)['payload']==payload

@pytest.mark.parametrize("text",["Your sign-in code is 123456. Do not share it.","Password: correct-horse-battery-staple","Verification code: 123 456"])
def test_redaction_is_idempotent(text):
    assert redact(redact(text))==redact(text)
