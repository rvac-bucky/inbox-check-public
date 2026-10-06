import base64
import pytest
from app import mailcheck
from app.core import InputError
from app.main import app
from tests.test_app import HEAD, client, signin  # noqa: F401  (fixture reuse)

MAILBOX = 'check@rvacyber.com'
PHISH = 'From: IT Support <it@micros0ft-security.co>\nSubject: Mailbox full\nVerify your password within 24 hours at http://bit.ly/x'


def cfg(**over):
    env = {'MAILCHECK_TENANT_ID': 't', 'MAILCHECK_CLIENT_ID': 'c', 'MAILCHECK_CLIENT_SECRET': 's',
           'MAILCHECK_MAILBOX': MAILBOX, 'MAILCHECK_INTERNAL_DOMAINS': 'rvacyber.com', 'PUBLIC_ORIGIN': 'https://check.example.test'}
    env.update(over)
    return mailcheck.MailConfig(env)


def dmarc(domain, result='pass'):
    return {'name': 'Authentication-Results',
            'value': f'spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc={result} action=none header.from={domain};compauth=pass reason=100'}


def message(sender='pat@example.org', subject='Fwd: Mailbox full', body=None, headers=None, mid='m1', attachments=False):
    return {'id': mid, 'internetMessageId': '<' + mid + '@x>', 'subject': subject, 'hasAttachments': attachments,
            'from': {'emailAddress': {'address': sender}},
            'internetMessageHeaders': headers if headers is not None else [dmarc(sender.split('@')[1])],
            'body': {'contentType': 'html', 'content': body if body is not None else
                     '<p>Is this real?</p><div>---------- Forwarded message ---------</div><div>' + PHISH.replace('\n', '<br>') + '</div>'}}


class Box:
    def __init__(self, attachments=()):
        self.sent, self.finished, self._attachments = [], [], list(attachments)
    def send(self, to, subject, body): self.sent.append((to, subject, body))
    def finish(self, mid): self.finished.append(mid)
    def attachments(self, mid): return self._attachments


def screener(calls):
    def screen(u, text, source):
        calls.append((u['id'], text, source))
        return 'case1', {'assessment': {'risk': 'likely_phishing', 'signals': []},
                         'explanation': {'summary': 'Looks like <b>phishing</b>.', 'evidence': ['Asks for a password.'], 'next_steps': ['Do not click.']}}
    return screen


def linked_user(store, email='pat@example.org'):
    uid = store.redeem(store.invite('Pat', 'submitter'))
    user = store.user(uid)
    code = store.create_mail_link(user['id'])
    assert store.claim_mail_link(code, email)['id'] == user['id']
    return user


# ---------- sender authentication ----------

def test_dmarc_must_pass_and_align():
    h = mailcheck.header_map([dmarc('example.org')])
    assert mailcheck.sender_verified(h, 'pat@example.org')
    assert not mailcheck.sender_verified(h, 'pat@other.org')  # aligned to a different domain
    assert not mailcheck.sender_verified(mailcheck.header_map([dmarc('example.org', 'fail')]), 'pat@example.org')
    assert not mailcheck.sender_verified(mailcheck.header_map([]), 'pat@example.org')


def test_internal_mail_needs_our_domain_and_exchange_auth():
    h = mailcheck.header_map([{'name': 'X-MS-Exchange-Organization-AuthAs', 'value': 'Internal'}])
    assert mailcheck.sender_verified(h, 'jim@rvacyber.com', {'rvacyber.com'})
    assert not mailcheck.sender_verified(h, 'jim@evil.test', {'rvacyber.com'})


def test_automated_mail_is_never_answered():
    for name, value in (('Auto-Submitted', 'auto-replied'), ('Precedence', 'bulk'), ('List-Id', '<x.list>')):
        assert mailcheck.is_automated(mailcheck.header_map([{'name': name, 'value': value}]))
    assert not mailcheck.is_automated(mailcheck.header_map([{'name': 'Auto-Submitted', 'value': 'no'}]))


# ---------- forwarded content ----------

def test_inline_gmail_forward_drops_the_users_own_note():
    text, source = mailcheck.forwarded_text(message(), [])
    assert text.startswith('From: IT Support') and 'Is this real?' not in text and source == 'forwarded email'


def test_outlook_forward_header_block():
    body = 'Can you check?\n\nFrom: IT Support <it@micros0ft-security.co>\nSent: Monday\nTo: Pat\nSubject: Mailbox full\n\nVerify your password now.'
    text, _ = mailcheck.forwarded_text({'body': {'contentType': 'text', 'content': body}}, [])
    assert text.startswith('From: IT Support') and 'Can you check' not in text


def test_attached_email_is_preferred():
    eml = b'From: Bank <alerts@bank-secure.test>\r\nSubject: Locked\r\nContent-Type: text/plain\r\n\r\nConfirm your PIN at http://x.test\r\n'
    att = {'@odata.type': '#microsoft.graph.fileAttachment', 'name': 'suspicious.eml', 'contentType': 'message/rfc822',
           'contentBytes': base64.b64encode(eml).decode()}
    text, source = mailcheck.forwarded_text(message(), [att])
    assert 'alerts@bank-secure.test' in text and 'Confirm your PIN' in text and source == 'forwarded email (attachment)'


def test_links_survive_as_declared_links():
    text, _ = mailcheck.forwarded_text(message(body='<div>---------- Forwarded message ---------</div><a href="http://evil.test/login">Sign in</a> to keep your account open today'), [])
    assert '[declared link: http://evil.test/login]' in text


# ---------- processing ----------

def test_link_code_links_a_verified_sender(client):
    store = app.state.store
    uid = store.redeem(store.invite('Pat', 'submitter'));user = store.user(uid)
    code = store.create_mail_link(user['id'])
    box = Box()
    out = mailcheck.process_message(message(subject='link ' + code.lower()), box, store, screener([]), cfg())
    assert out == 'linked' and box.sent[0][0] == 'pat@example.org' and box.finished == ['m1']
    assert store.mail_user('Pat@Example.org')['id'] == user['id']
    # Codes are single use.
    assert mailcheck.process_message(message(subject=code, mid='m2'), Box(), store, screener([]), cfg()) == 'ignored_bad_code'


def test_link_code_from_forged_sender_is_ignored(client):
    store = app.state.store
    uid = store.redeem(store.invite('Pat', 'submitter'));code = store.create_mail_link(store.user(uid)['id'])
    box = Box()
    out = mailcheck.process_message(message(subject=code, headers=[dmarc('example.org', 'fail')]), box, store, screener([]), cfg())
    assert out == 'ignored_unverified' and box.sent == [] and store.mail_user('pat@example.org') is None


def test_linked_sender_gets_a_screened_reply(client):
    store = app.state.store;user = linked_user(store);calls = [];box = Box()
    out = mailcheck.process_message(message(), box, store, screener(calls), cfg())
    assert out == 'replied' and box.finished == ['m1'] and len(box.sent) == 1
    to, subject, body = box.sent[0]
    assert to == 'pat@example.org' and subject.startswith('Inbox Check: 🔴 RED — Do not act on this message')
    assert '&lt;b&gt;phishing&lt;/b&gt;' in body and '<b>phishing</b>' not in body  # escaped
    assert calls[0][0] == user['id'] and calls[0][1].startswith('From: IT Support')


def test_each_message_is_answered_once(client):
    store = app.state.store;linked_user(store);box = Box()
    assert mailcheck.process_message(message(), box, store, screener([]), cfg()) == 'replied'
    assert mailcheck.process_message(message(), box, store, screener([]), cfg()) == 'duplicate'
    assert len(box.sent) == 1


@pytest.mark.parametrize('msg,outcome', [
    (message(headers=[dmarc('example.org'), {'name': 'Auto-Submitted', 'value': 'auto-replied'}]), 'ignored_automated'),
    (message(sender=MAILBOX, headers=[dmarc('rvacyber.com')]), 'ignored_automated'),
    (message(headers=[dmarc('example.org'), {'name': 'X-Inbox-Check', 'value': 'result'}]), 'ignored_automated'),
])
def test_no_reply_cases(client, msg, outcome):
    store = app.state.store;linked_user(store);box = Box()
    assert mailcheck.process_message(msg, box, store, screener([]), cfg()) == outcome
    assert box.sent == [] and box.finished == ['m1']


def test_empty_forward_gets_guidance(client):
    store = app.state.store;linked_user(store);box = Box()
    assert mailcheck.process_message(message(body='<p>hi</p>'), box, store, screener([]), cfg()) == 'no_content'
    assert 'could not find the email' in box.sent[0][2]


def test_provider_failure_implies_nothing(client):
    store = app.state.store;linked_user(store);box = Box()
    def down(u, text, source): raise RuntimeError('provider')
    assert mailcheck.process_message(message(), box, store, down, cfg()) == 'screen_failed'
    assert 'no assessment is implied' in box.sent[0][2]


def test_rate_limit_applies_to_email(client, monkeypatch):
    monkeypatch.setenv('USER_HOURLY_LIMIT', '1')
    store = app.state.store;linked_user(store);box = Box()
    assert mailcheck.process_message(message(), box, store, screener([]), cfg()) == 'replied'
    assert mailcheck.process_message(message(mid='m2'), box, store, screener([]), cfg()) == 'rate_limited'


def test_linked_user_survives_session_purge(client):
    store = app.state.store;user = linked_user(store)
    with store.db() as c:
        c.execute('DELETE FROM sessions');store.purge(c)
    assert store.mail_user('pat@example.org')['id'] == user['id']


# ---------- web endpoints ----------

def test_mail_link_endpoints(client):
    signin(client)
    assert client.get('/api/mail-link').json() == {'enabled': False}
    app.state.mailcfg = cfg()
    r = client.post('/api/mail-link', json={}, headers=HEAD).json()
    assert r['mailbox'] == MAILBOX and mailcheck.LINK_CODE.fullmatch(r['code'])
    assert client.get('/api/mail-link').json()['addresses'] == []
    uid = app.state.store.user(client.cookies.get('inbox_session'))['id']
    app.state.store.claim_mail_link(r['code'], 'me@example.org')
    assert client.get('/api/mail-link').json()['addresses'] == ['me@example.org']
    assert client.post('/api/mail-link/remove', json={'email': 'ME@example.org'}, headers=HEAD).json() == {'ok': True}
    assert app.state.store.mail_user('me@example.org') is None and uid


def test_mail_loop_screens_end_to_end(client, monkeypatch):
    import asyncio
    from app import main
    store = app.state.store;user = linked_user(store);box = Box()
    box.unread = lambda: [message()]
    monkeypatch.setattr(main.mailcheck, 'GraphMailbox', lambda cfg: box)
    monkeypatch.delenv('AGENT_GATEWAY_URL', raising=False)
    async def stop(*a): raise asyncio.CancelledError
    monkeypatch.setattr(main.asyncio, 'sleep', stop)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main.mail_loop(app, cfg()))
    assert len(box.sent) == 1 and box.sent[0][1].startswith('Inbox Check: 🔴 RED — Do not act on this message')
    with store.db() as c:
        (n,) = c.execute('SELECT count(*) FROM cases WHERE user_id=?', (user['id'],)).fetchone()
    assert n == 1


def test_any_verified_sender_can_check_without_linking(client):
    store = app.state.store;box = Box();calls = []
    assert mailcheck.process_message(message(sender='stranger@example.org'), box, store, screener(calls), cfg()) == 'replied'
    assert box.sent[0][0] == 'stranger@example.org' and store.mail_user('stranger@example.org')['role'] == 'guest'
    # Same sender keeps the same identity (and the same hourly limit).
    assert mailcheck.process_message(message(sender='stranger@example.org', mid='m2'), box, store, screener(calls), cfg()) == 'replied'
    assert calls[0][0] == calls[1][0]


def test_forged_stranger_gets_nothing(client):
    store = app.state.store;box = Box()
    msg = message(sender='victim@example.org', headers=[dmarc('example.org', 'fail')])
    assert mailcheck.process_message(msg, box, store, screener([]), cfg()) == 'ignored_unverified' and box.sent == []
