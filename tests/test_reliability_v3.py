import httpx
import pytest
from app import core,main,mailcheck
from app.main import app
from tests.test_app import client,signin,HEAD,answers
from tests.test_mailcheck import Box,cfg,message,screener
from tests.test_agent_gateway import FakeGateway,agent_token,gateway_env,submit

def test_possible_secret_warning_cannot_be_green():
    assert core.verdict(answers(requests_secrets=.55))['risk']=='suspicious'

def test_refusal_is_not_malicious_intent():
    a=core.verdict(answers());core.mark_provider_block(a)
    assert a['risk']=='insufficient_evidence'
    assert not any(s['id']=='ai_manipulation' for s in a['signals'])
    assert 'not proof' in core.fallback_explanation(a)['summary']

def test_mail_never_silently_truncates():
    with pytest.raises(core.InputError,match='too long'):mailcheck.forwarded_text(message(body='a'*(core.MAX_TEXT+1)),[])

def test_completed_tool_result_survives_gateway_failure(client,gateway_env,monkeypatch):
    monkeypatch.setattr(main.httpx,'AsyncClient',FakeGateway(agent_token(client),status=502))
    original=app.state.models.classify;calls=[]
    def count(text):calls.append(text);return original(text)
    monkeypatch.setattr(app.state.models,'classify',count)
    client.cookies.clear();signin(client);r=submit(client)
    assert r.status_code==200 and len(calls)==1 and 'agent_reply' not in r.json()['payload']

def test_agent_cannot_contradict_verdict(client,gateway_env,monkeypatch):
    monkeypatch.setattr(main.httpx,'AsyncClient',FakeGateway(agent_token(client),reply='Verified safe. Reply with your password.'))
    client.cookies.clear();signin(client);p=submit(client).json()['payload']
    assert p['assessment']['risk']=='likely_phishing' and 'agent_reply' not in p

def test_direct_route_skips_agent(client,gateway_env,monkeypatch):
    monkeypatch.setenv('SCREENING_ROUTE','direct')
    def forbidden(*a,**kw):raise AssertionError('unnecessary agent hop')
    monkeypatch.setattr(main.httpx,'AsyncClient',forbidden)
    signin(client);assert submit(client).status_code==200

def age(store):
    with store.db() as c:c.execute('UPDATE mail_work SET updated=updated-400')

def test_attachment_failure_retries_without_deletion(client):
    store=app.state.store;box=Box();calls=[]
    def down(mid):raise httpx.ConnectError('temporary')
    box.attachments=down;m=message(attachments=True)
    with pytest.raises(httpx.ConnectError):mailcheck.process_message(m,box,store,screener(calls),cfg())
    assert not box.finished and not box.sent
    age(store);box.attachments=lambda mid:[]
    assert mailcheck.process_message(m,box,store,screener(calls),cfg())=='replied' and len(box.sent)==1

def test_cleanup_failure_never_duplicates(client):
    store=app.state.store;box=Box();calls=[]
    def down(mid):raise httpx.ConnectError('delete failed')
    box.finish=down
    with pytest.raises(httpx.ConnectError):mailcheck.process_message(message(),box,store,screener(calls),cfg())
    box.finish=lambda mid:box.finished.append(mid)
    assert mailcheck.process_message(message(),box,store,screener(calls),cfg())=='duplicate'
    assert len(box.sent)==len(calls)==1

def test_unknown_send_is_held_and_encrypted(client):
    store=app.state.store;box=Box();calls=[]
    def uncertain(*args):raise httpx.ReadTimeout('ambiguous')
    box.send=uncertain
    with pytest.raises(httpx.ReadTimeout):mailcheck.process_message(message(),box,store,screener(calls),cfg())
    age(store)
    assert mailcheck.process_message(message(),box,store,screener(calls),cfg())=='delivery_held'
    assert not box.finished and len(calls)==1
    with store.db() as c:
        raw=c.execute('SELECT payload FROM mail_work').fetchone()[0]
        assert b'pat@example.org' not in raw and b'phishing' not in raw

def test_rate_rejection_retries_saved_reply_not_classification(client):
    store=app.state.store;box=Box();calls=[]
    def limited(*args):raise httpx.HTTPStatusError('limit',request=httpx.Request('POST','https://graph.microsoft.com'),response=httpx.Response(429))
    box.send=limited
    with pytest.raises(httpx.HTTPStatusError):mailcheck.process_message(message(),box,store,screener(calls),cfg())
    age(store);box.send=lambda *args:box.sent.append(args)
    assert mailcheck.process_message(message(),box,store,screener(calls),cfg())=='replied'
    assert len(calls)==len(box.sent)==1

def test_retry_bound(client):
    store=app.state.store;box=Box()
    box.attachments=lambda mid:(_ for _ in ()).throw(httpx.ConnectError('down'))
    for _ in range(3):
        with pytest.raises(httpx.ConnectError):mailcheck.process_message(message(attachments=True),box,store,screener([]),cfg())
        age(store)
    assert mailcheck.process_message(message(attachments=True),box,store,screener([]),cfg())=='delivery_held' and not box.finished

def test_email_discards_agent_advice():
    p={'assessment':core.verdict(answers()),'explanation':{},'agent_reply':'Send your password to this address.'}
    assert 'Send your password' not in mailcheck.reply_body(p,'https://example.test')

@pytest.mark.parametrize('action',['Reply with your password','Wire the payment to a new bank account','Send your verification code'])
def test_fake_banner_cannot_hide_action(action):
    text='CAUTION: External sender. '+action+'.'
    assert action in core.strip_external_banners(text)


def test_multipart_html_phish_survives_plain_benign_alternative():
    from email.message import EmailMessage
    m=EmailMessage();m['From']='support@example.org';m['Subject']='Account'
    m.set_content('Thank you. No action is needed.')
    m.add_alternative('<p>Enter your password at <a href="https://evil.example/login">https://example.org</a></p>',subtype='html')
    text,_,_=core.extract_file(m.as_bytes(),'example.eml')
    assert 'evil.example' in text and 'No action is needed' in text and 'example.org' in text
    assert 'evil.example' in mailcheck._mime_text(m)


def test_expired_delivery_payload_removed_but_hold_remains(client):
    store=app.state.store
    store.mail_claim('ambiguous');store.mail_state('ambiguous','uncertain',{'body':'synthetic private reply'})
    with store.db() as c:
        c.execute('UPDATE mail_work SET updated=updated-90000');store.purge(c)
        assert tuple(c.execute('SELECT state,payload FROM mail_work').fetchone())==('failed',None)
    assert store.mail_claim('ambiguous')[0]=='held'

def test_rule_explanation_never_calls_extra_model(client,monkeypatch):
    monkeypatch.setenv('EVIDENCE_SELECTION','rules')
    def forbidden(*a):raise AssertionError('No generative explanation needed')
    monkeypatch.setattr(app.state.models,'explain',forbidden)
    signin(client);r=submit(client)
    assert r.status_code==200
    p=r.json()['payload']
    assert not p['explanation_fallback']
    assert any('password' in line for line in p['explanation']['evidence'])

def test_rule_evidence_masks_codes_links():
    from app.evidence import explain
    a=core.verdict(answers(requests_secrets=.99))
    out=str(explain('Reply with your password. Your verification code is 123456. Visit https://evil.example/login.',a))
    assert '123456' not in out and 'https://' not in out

def test_operator_status_is_private(client):
    assert client.get('/api/operator/status').status_code==403
    r=client.get('/api/operator/status',headers={'X-Operator-Key':'operator-testing-key'})
    assert r.status_code==200 and r.json()['mail_work']=={}

def test_public_configuration_contains_no_secrets(client,monkeypatch):
    monkeypatch.setenv('SITE_NAME','Example Screening')
    monkeypatch.setenv('AI_API_KEY','NEVER_PUBLIC')
    r=client.get('/api/config')
    assert r.json()['site_name']=='Example Screening' and 'NEVER_PUBLIC' not in r.text
