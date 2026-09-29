import re
import httpx
import pytest
from app import main
from app.main import app
from tests.test_app import HEAD, ORIGIN, client, signin  # noqa: F401  (fixture reuse)

REAL_ASYNC_CLIENT = httpx.AsyncClient
EMAIL = 'From: payroll@unknown.example\nUrgent! Send your password to claim your wages today.'


def agent_token(c):
    signin(c, 'reviewer')
    return c.post('/api/agent-token', json={'name': 'Azure agent'}, headers=HEAD).json()['token']


class FakeGateway:
    """Plays the OpenClaw gateway: optionally redeems the ticket through the real app, then replies."""
    def __init__(self, token, call_tool=True, reply='Likely phishing. Do not reply or send your password.', status=200, ticket_override=None):
        self.token, self.call_tool, self.reply, self.status, self.ticket_override = token, call_tool, reply, status, ticket_override
        self.requests = []

    def __call__(self, *args, **kwargs):
        gateway = self

        class Client:
            async def __aenter__(self): return self
            async def __aexit__(self, *exc): return False

            async def post(self, url, headers=None, json=None):
                gateway.requests.append({'url': url, 'headers': headers, 'json': json})
                prompt = json['messages'][0]['content']
                ticket = gateway.ticket_override or re.search(r'Screening ticket: (\S+)', prompt).group(1)
                if gateway.call_tool:
                    transport = httpx.ASGITransport(app=app)
                    async with REAL_ASYNC_CLIENT(transport=transport, base_url=ORIGIN) as tool:
                        gateway.tool_response = await tool.post('/api/agent/screen', json={'ticket': ticket},
                                                                headers=HEAD | {'Authorization': 'Bearer ' + gateway.token})
                return httpx.Response(gateway.status, json={'choices': [{'message': {'content': gateway.reply}}]},
                                      request=httpx.Request('POST', url))
        return Client()


@pytest.fixture
def gateway_env(monkeypatch):
    monkeypatch.setenv('AGENT_GATEWAY_URL', 'https://agent.example.test')
    monkeypatch.setenv('AGENT_GATEWAY_TOKEN', 'gateway-secret')


def submit(c):
    return c.post('/api/analyze', data={'consent': 'yes', 'text': EMAIL}, headers=HEAD)


def test_web_submission_is_screened_through_agent_ticket(client, gateway_env, monkeypatch):
    fake = FakeGateway(agent_token(client));monkeypatch.setattr(main.httpx, 'AsyncClient', fake)
    client.cookies.clear();signin(client)
    r = submit(client);assert r.status_code == 200, r.text
    body = r.json();p = body['payload']
    assert p['assessment']['risk'] == 'likely_phishing'
    assert p['agent_reply'].startswith('Likely phishing') and p['agent'] == 'Inbox Check OpenClaw agent'
    assert fake.tool_response.status_code == 200 and 'case_id' not in fake.tool_response.json()
    req = fake.requests[0]
    assert req['url'] == 'https://agent.example.test/v1/chat/completions'
    assert req['headers'] == {'Authorization': 'Bearer gateway-secret'}
    assert req['json']['user'].startswith('pilot-') and '<untrusted_email>' in req['json']['messages'][0]['content']
    # The case belongs to the web user, not the agent identity, and stays private.
    case = client.get('/api/cases/' + body['id']);assert case.status_code == 200 and case.json()['owned'] and not case.json()['shared']
    assert main.AGENT_TICKETS == {}


def test_agent_that_skips_the_tool_falls_back_to_direct_screening(client, gateway_env, monkeypatch):
    monkeypatch.setattr(main.httpx, 'AsyncClient', FakeGateway(agent_token(client), call_tool=False, reply='Looks safe!'))
    client.cookies.clear();signin(client)
    r = submit(client);assert r.status_code == 200, r.text
    p = r.json()['payload']
    # The agent's unverified reply is discarded; the verdict comes from Jev on the same text.
    assert 'agent_reply' not in p and p['agent'] == 'Direct screening (agent_incomplete)'
    assert p['assessment']['risk'] == 'likely_phishing' and main.AGENT_TICKETS == {}


def test_gateway_failure_falls_back_to_direct_screening(client, gateway_env, monkeypatch):
    monkeypatch.setattr(main.httpx, 'AsyncClient', FakeGateway(agent_token(client), status=502))
    client.cookies.clear();signin(client)
    r = submit(client);assert r.status_code == 200, r.text
    p = r.json()['payload'];assert p['agent'] == 'Direct screening (agent_unavailable)' and 'agent_reply' not in p


def test_gateway_and_jev_failure_still_fails_closed(client, gateway_env, monkeypatch):
    monkeypatch.setattr(main.httpx, 'AsyncClient', FakeGateway(agent_token(client), status=502))
    def down(*args):raise main.ProviderError('Jev is unavailable; no assessment was produced')
    monkeypatch.setattr(main.app.state.models, 'classify', down)
    client.cookies.clear();signin(client)
    r = submit(client);assert r.status_code == 503 and 'no assessment' in r.json()['detail']
    assert client.get('/api/cases').json()['cases'] == []


def test_azure_content_filter_refusal_is_reported_as_a_warning_sign(client, gateway_env, monkeypatch):
    from app import core
    monkeypatch.setattr(main.httpx, 'AsyncClient', FakeGateway(agent_token(client), status=502))
    monkeypatch.setattr(main.app.state.models, 'classify', lambda text:
                        (dict(risk='no_obvious_warning_signs', message_type='Other correspondence', signals=[], decision={}), {'model':'mock/jev','usage':{}}))
    def filtered(*args):raise main.ProviderError('Azure content filter refused the request','content_filtered')
    monkeypatch.setattr(main.app.state.models, 'explain', filtered)
    client.cookies.clear();signin(client)
    r = submit(client);assert r.status_code == 200, r.text
    p = r.json()['payload']
    assert p['assessment']['risk'] == 'suspicious'
    assert any(s['id'] == 'ai_manipulation' and s['strength'] == 'strong' for s in p['assessment']['signals'])
    assert p['explanation_status'] == {'state':'fallback','reason':'content_filtered'}
    assert p['explanation']['summary'].startswith("Azure OpenAI's safety filter refused")


def test_content_filter_detection():
    from app import core
    def resp(status, body):return httpx.Response(status, json=body, request=httpx.Request('POST', 'https://x.openai.azure.com'))
    assert core.content_filtered(resp(400, {'error':{'code':'content_filter','message':'filtered'}}))
    assert core.content_filtered(resp(400, {'error':{'code':None,'innererror':{'code':'ResponsibleAIPolicyViolation'}}}))
    assert not core.content_filtered(resp(400, {'error':{'code':'invalid_request_error'}}))
    assert not core.content_filtered(resp(429, {'error':{'code':'content_filter'}}))


def test_ticket_is_single_use_bound_and_requires_agent_token(client, gateway_env, monkeypatch):
    token = agent_token(client)
    assert client.post('/api/agent/screen', json={'ticket': 'x' * 43}, headers=HEAD | {'Authorization': 'Bearer ' + token}).status_code == 404
    assert client.post('/api/agent/screen', json={'ticket': 'x' * 43}, headers=HEAD | {'Authorization': 'Bearer nope'}).status_code == 401
    assert client.post('/api/agent/screen', json={'ticket': 'x' * 43, 'text': 'other'}, headers=HEAD | {'Authorization': 'Bearer ' + token}).status_code == 404
    # A forged ticket (e.g. injected by email content) cannot redeem anything.
    fake = FakeGateway(token, ticket_override='forged-ticket-value-000000000000000');monkeypatch.setattr(main.httpx, 'AsyncClient', fake)
    client.cookies.clear();signin(client)
    r = submit(client);assert fake.tool_response.status_code == 404
    # The forged redemption fails; the submission is screened directly and the agent reply is not shown.
    assert r.status_code == 200 and 'agent_reply' not in r.json()['payload']


def test_agent_reply_is_bounded_and_masked(client, gateway_env, monkeypatch):
    monkeypatch.setattr(main.httpx, 'AsyncClient', FakeGateway(agent_token(client), reply='Code 123456\x07 ' + 'a' * 5000))
    client.cookies.clear();signin(client)
    p = submit(client).json()['payload']
    assert len(p['agent_reply']) <= main.AGENT_REPLY_MAX and '\x07' not in p['agent_reply']


def test_direct_path_unchanged_without_gateway(client, monkeypatch):
    monkeypatch.delenv('AGENT_GATEWAY_URL', raising=False)
    signin(client);p = submit(client).json()['payload']
    assert 'agent_reply' not in p and p['assessment']['risk'] == 'likely_phishing'


def test_screenshot_refused_by_azure_filter_warns_the_user(client, monkeypatch):
    monkeypatch.delenv('AGENT_GATEWAY_URL', raising=False)
    def filtered(*args):raise main.ProviderError('Azure content filter refused the request','content_filtered')
    monkeypatch.setattr(main.app.state.models, 'ocr', filtered)
    monkeypatch.setattr(main, 'isolated_extract', lambda data, name: ('', b'img', 'screenshot'))
    signin(client)
    r = client.post('/api/analyze', data={'consent': 'yes'}, files={'file': ('shot.png', b'\x89PNG fake', 'image/png')}, headers=HEAD)
    assert r.status_code == 422 and 'manipulate AI tools' in r.json()['detail']
