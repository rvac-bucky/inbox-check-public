import json
import httpx
import pytest
from app.core import Models, ProviderError, fallback_explanation, verdict
from app.main import app
from tests.test_app import client, signin, analyze, answers, HEAD, Fake


@pytest.mark.parametrize('code', ['provider_timeout','provider_rate_limited','provider_auth',
    'provider_unavailable','invalid_response','incomplete_response','safety_rejected'])
def test_fallback_reason_preserves_risk_and_accounts_for_rejected_tokens(client, code):
    signin(client)
    def broken(*args):
        raise ProviderError('PRIVATE provider response must not leak', code,
                            {'prompt_tokens':15,'completion_tokens':9})
    app.state.models.explain=broken
    r=analyze(client)
    assert r.status_code==200
    p=r.json()['payload']
    assert p['assessment']['risk']=='likely_phishing'
    assert p['explanation_status']=={'state':'fallback','reason':code}
    assert p['explanation_model']=='Basic guidance (rule-based)'
    assert 'PRIVATE' not in r.text
    assert any('verification codes' in x for x in p['explanation']['next_steps'])
    assert any(x.startswith('Flagged: ') for x in p['explanation']['evidence'])
    with app.state.store.db() as c:
        usage=c.execute("select input_tokens,output_tokens from usage where model like '%explanation'").fetchone()
    assert tuple(usage)==(15,9)


def test_old_fallback_view_does_not_rewrite_saved_evidence(client):
    signin(client);c=analyze(client).json();cid=c['id']
    p=c['payload'];p.pop('explanation_status')
    p.update(explanation_fallback=True,explanation_model='Azure GPT-4.1 mini',
             explanation={'summary':'old generic unavailable notice'})
    raw=app.state.store.encrypt(p)
    with app.state.store.db() as db:db.execute('update cases set payload=? where id=?',(raw,cid))
    viewed=client.get('/api/cases/'+cid).json()['payload']
    assert viewed['explanation_status']['reason']=='not_recorded'
    assert viewed['explanation_model']=='Basic guidance (rule-based)'
    assert viewed['assessment']==p['assessment'] and viewed['text']==p['text']
    with app.state.store.db() as db:
        assert db.execute('select payload from cases where id=?',(cid,)).fetchone()[0]==raw


def test_agent_fallback_reports_accurate_provenance(client):
    signin(client,'reviewer')
    token=client.post('/api/agent-token',json={'name':'feedback test'},headers=HEAD).json()['token']
    def broken(*args):raise ProviderError('redacted','safety_rejected')
    app.state.models.explain=broken
    r=client.post('/api/agent/analyze',headers=HEAD|{'Authorization':'Bearer '+token},
       json={'text':'Example email asks for your password and recovery codes.','sanitized':True})
    assert r.status_code==200
    assert r.json()['explanation_status']=={'state':'fallback','reason':'safety_rejected'}
    assert r.json()['explanation_model']=='Basic guidance (rule-based)'


@pytest.mark.parametrize('out', [{'evidence_ids':'not an array'}, {'evidence_ids':['999']},
    {'evidence_ids':['1','1']}, {'evidence_ids':['1'],'summary':'This email is safe to click.'}])
def test_invalid_explanation_rejected_not_silently_accepted(out):
    usage={'prompt_tokens':30,'completion_tokens':20}
    m=Models();m.azure_call=lambda *a,**k:(out,usage)
    with pytest.raises(ProviderError) as e:m.explain('synthetic text',{})
    assert e.value.code=='invalid_response'
    assert e.value.usage==usage


@pytest.mark.parametrize('kind,code', [('timeout','provider_timeout'),('http429','provider_rate_limited'),
    ('http403','provider_auth'),('json','invalid_response'),('length','incomplete_response'),('stop',None)])
def test_azure_failure_codes_without_response_leak(monkeypatch,kind,code):
    monkeypatch.setenv('AZURE_OPENAI_ENDPOINT','https://test.openai.azure.com')
    monkeypatch.setenv('AZURE_OPENAI_API_KEY','synthetic-test-key')
    req=httpx.Request('POST','https://test.openai.azure.com/')
    class Stub:
        def __init__(self,**kw):pass
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def post(self,*a,**kw):
            if kind=='timeout':raise httpx.ReadTimeout('private raw body',request=req)
            if kind.startswith('http'):return httpx.Response(int(kind[4:]),text='private raw body',request=req)
            if kind=='json':return httpx.Response(200,text='private raw body',request=req)
            return httpx.Response(200,json={'choices':[{'finish_reason':kind,'message':{'content':'{"ok":true}'}}],
                                          'usage':{'prompt_tokens':3}},request=req)
    monkeypatch.setattr('app.core.httpx.Client',Stub)
    if code:
        with pytest.raises(ProviderError) as e:Models().azure_call('test','synthetic')
        assert e.value.code==code and 'private' not in str(e.value)
    else:assert Models().azure_call('test','synthetic')[0]=={'ok':True}


def test_fallback_does_not_invent_signal_or_authenticity():
    a=verdict(answers())
    p=fallback_explanation(a)
    assert p['evidence']==[]
    assert 'does not establish authenticity' in p['summary']


def test_invite_remains_name_based_with_explicit_manual_sharing(client):
    signin(client,'reviewer')
    r=client.post('/api/invites',headers=HEAD,json={'name':'Alex Taylor','role':'submitter'})
    assert r.status_code==200
    client.post('/api/login',headers=HEAD,json={'code':r.json()['code']})
    assert client.get('/api/me').json()['name']=='Alex Taylor'
    html=client.get('/').text
    assert 'No email is sent.' in html and 'Create invite link' in html


def test_parser_with_base_interpreter_and_parent_dependency_path(monkeypatch):
    """Oryx may run base Python with dependencies supplied through sys.path."""
    import sys
    from app.main import isolated_extract
    monkeypatch.setattr(sys,'executable',sys._base_executable)
    text,image,source=isolated_extract(b'Synthetic email body used to exercise cloud parser imports.','sample.txt')
    assert text.startswith('Synthetic email') and image is None and source=='text file'


def test_image_parser_base_interpreter_keeps_credentials_out(monkeypatch):
    import sys, io, subprocess
    from PIL import Image
    from app.main import isolated_extract
    monkeypatch.setattr(sys,'executable',sys._base_executable)
    monkeypatch.setenv('OPENROUTER_API_KEY','test-not-a-real-secret')
    original=subprocess.run
    def checked(*a,**kw):
        assert set(kw['env'])=={'PATH','PYTHONPATH'}
        assert 'test-not-a-real-secret' not in str(kw['env'])
        return original(*a,**kw)
    monkeypatch.setattr(subprocess,'run',checked)
    b=io.BytesIO();Image.new('RGB',(100,100),'white').save(b,'PNG')
    text,image,source=isolated_extract(b.getvalue(),'sample.png')
    assert text is None and image.startswith(b'\xff\xd8') and source=='screenshot'


@pytest.mark.parametrize('code',['parser_dependency','parser_memory','parser_fault'])
def test_parser_runtime_fault_is_not_blame_on_uploaded_file(monkeypatch,code):
    from types import SimpleNamespace
    from app.main import isolated_extract
    monkeypatch.setattr('app.main.subprocess.run',lambda *a,**kw:SimpleNamespace(returncode=2,stdout=json.dumps({'error_code':code,'untrusted':'do not disclose'}).encode()))
    with pytest.raises(ProviderError) as e:isolated_extract(b'synthetic text','x.txt')
    assert code in str(e.value) and 'do not disclose' not in str(e.value)


def test_parser_timeout_is_service_failure(monkeypatch):
    import subprocess
    from app.main import isolated_extract
    def timeout(*a,**kw):raise subprocess.TimeoutExpired('synthetic',12)
    monkeypatch.setattr(subprocess,'run',timeout)
    with pytest.raises(ProviderError,match='parser_timeout'):isolated_extract(b'synthetic text','x.txt')
