"""Forward-to-check mailbox: read forwarded mail, screen it, reply to the verified sender.

Anyone may use it, but replies go only to senders whose message passed DMARC (or was sent
inside our own tenant), so a forged From line can never turn the mailbox into a reply cannon. Every
message is handled once, then deleted from the mailbox; the screened case lives in the
encrypted store with the normal 24-hour expiry.
"""
import base64
import email
import html
import logging
import os
import re
import time
from email import policy
from email.utils import parseaddr

import httpx

from .core import clean, html_text, InputError, MAX_TEXT

log = logging.getLogger('inboxcheck.mail')
GRAPH = 'https://graph.microsoft.com/v1.0'
LINK_CODE = re.compile(r'\bIC-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}\b')
FORWARD_MARKERS = re.compile(
    r'(?im)^(?:-{2,}\s*(?:Forwarded message|Original Message)\s*-{2,}|Begin forwarded message:|_{10,})\s*$')
RISK_LABELS = {'likely_phishing': 'Likely phishing', 'suspicious': 'Suspicious — verify first',
               'no_obvious_warning_signs': 'No obvious warning signs', 'insufficient_evidence': 'Not enough evidence'}


class MailConfig:
    def __init__(self, env=os.environ):
        self.tenant = env.get('MAILCHECK_TENANT_ID', '')
        self.client = env.get('MAILCHECK_CLIENT_ID', '')
        self.secret = env.get('MAILCHECK_CLIENT_SECRET', '')
        self.mailbox = env.get('MAILCHECK_MAILBOX', '').strip().lower()
        self.internal_domains = {d.strip().lower() for d in env.get('MAILCHECK_INTERNAL_DOMAINS', '').split(',') if d.strip()}
        self.origin = env.get('PUBLIC_ORIGIN', '').rstrip('/')
        self.interval = max(10, int(env.get('MAILCHECK_POLL_SECONDS', '20')))

    @property
    def enabled(self):
        return all((self.tenant, self.client, self.secret, self.mailbox))


# ---------- header checks ----------

def header_map(headers):
    out = {}
    for h in headers or []:
        name = (h.get('name') or '').lower()
        out.setdefault(name, []).append(h.get('value') or '')
    return out


def is_automated(headers):
    """Never answer auto-replies, bounces or list mail: that is how reply loops start."""
    auto = ' '.join(headers.get('auto-submitted', [])).lower()
    if auto and 'no' not in auto.split(';')[0].strip():
        return True
    if any(v.strip().lower() in ('bulk', 'list', 'junk', 'auto_reply') for v in headers.get('precedence', [])):
        return True
    return bool(headers.get('x-autoreply') or headers.get('x-autorespond') or headers.get('list-id'))


def sender_verified(headers, sender, internal_domains=frozenset()):
    """True when the From address is authenticated: DMARC pass aligned to the sender's
    domain, or a message Exchange authenticated as internal to our own tenant."""
    domain = sender.rsplit('@', 1)[-1].lower() if '@' in sender else ''
    if not domain:
        return False
    if domain in internal_domains and any(v.strip().lower() == 'internal' for v in headers.get('x-ms-exchange-organization-authas', [])):
        return True
    for value in headers.get('authentication-results', []):
        m = re.search(r'\bdmarc=(\w+)[^;]*?header\.from=([^\s;]+)', value, re.I)
        if m and m.group(1).lower() == 'pass' and m.group(2).strip().lower().rstrip('.') == domain:
            return True
    return False


# ---------- forwarded content ----------

def _mime_text(msg):
    pieces = [f'{h}: {str(msg.get(h, ""))}' for h in ('From', 'Reply-To', 'To', 'Subject', 'Date') if msg.get(h)]
    body = msg.get_body(preferencelist=('plain', 'html'))
    if body is not None:
        content = body.get_content()
        pieces.append(html_text(content) if body.get_content_subtype() == 'html' else content)
    return '\n'.join(pieces)


def attached_email_text(attachments):
    """First attached email (.eml / message/rfc822 / Outlook item), as screening text."""
    for a in attachments or []:
        kind = a.get('@odata.type', '')
        name = (a.get('name') or '').lower()
        ctype = (a.get('contentType') or '').lower()
        raw = a.get('mime')
        if raw is None and kind.endswith('fileAttachment') and (name.endswith('.eml') or ctype == 'message/rfc822'):
            raw = base64.b64decode(a.get('contentBytes') or '')
        if raw:
            try:
                return _mime_text(email.message_from_bytes(raw, policy=policy.default))
            except Exception:
                continue
    return None


def inline_forward_text(body_html_or_text, content_type='html'):
    """The forwarded part of an inline forward: everything from the first forward marker.
    Without a marker, the whole body (minus nothing) is the best evidence we have."""
    text = html_text(body_html_or_text) if content_type.lower() == 'html' else body_html_or_text
    text = re.sub(r'\n{3,}', '\n\n', text).strip()
    m = FORWARD_MARKERS.search(text)
    if m:
        return text[m.end():].strip()
    # Outlook often forwards with a bare header block: "From: ... Sent: ... To: ... Subject: ..."
    m = re.search(r'(?im)^From:.*\n(?:.*\n){0,3}?(?:Sent|Date):', text)
    return text[m.start():].strip() if m else text


def forwarded_text(message, attachments):
    text = attached_email_text(attachments)
    source = 'forwarded email (attachment)'
    if not text:
        body = message.get('body') or {}
        text = inline_forward_text(body.get('content') or '', body.get('contentType') or 'html')
        source = 'forwarded email'
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text).strip()
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT]
    return clean(text), source


# ---------- reply ----------

def reply_body(payload, origin):
    a = payload['assessment']; e = payload.get('explanation') or {}
    label = RISK_LABELS.get(a['risk'], a['risk'])
    esc = html.escape
    parts = [f'<p style="font-size:18px"><b>Inbox Check result: {esc(label)}</b></p>']
    if e.get('summary'):
        parts.append(f'<p>{esc(e["summary"])}</p>')
    if payload.get('agent_reply'):
        parts.append(f'<p>{esc(payload["agent_reply"])}</p>')
    if e.get('evidence'):
        parts.append('<p><b>What we noticed</b></p><ul>' + ''.join(f'<li>{esc(x)}</li>' for x in e['evidence']) + '</ul>')
    if e.get('next_steps'):
        parts.append('<p><b>Next steps</b></p><ul>' + ''.join(f'<li>{esc(x)}</li>' for x in e['next_steps']) + '</ul>')
    if origin:
        parts.append(f'<p>You can also paste or upload messages at <a href="{esc(origin)}/">Inbox Check</a>.</p>')
    parts.append('<p style="color:#666;font-size:12px">Automated screening of the text you forwarded, not proof that a message is safe. '
                 'Sender identity, hidden link targets and attachments were not verified. Do not click links or reply to the '
                 'original message until you have checked it through a channel you already trust.</p>')
    return '\n'.join(parts)


def notice_body(text):
    return f'<p>{html.escape(text)}</p><p style="color:#666;font-size:12px">RVA Cyber Inbox Check</p>'


# ---------- Microsoft Graph ----------

class GraphMailbox:
    def __init__(self, cfg, client=None):
        self.cfg = cfg; self.client = client or httpx.Client(timeout=30, follow_redirects=False)
        self._token = None; self._expires = 0

    def token(self):
        if self._token and time.time() < self._expires - 120:
            return self._token
        r = self.client.post(f'https://login.microsoftonline.com/{self.cfg.tenant}/oauth2/v2.0/token',
                             data={'client_id': self.cfg.client, 'client_secret': self.cfg.secret,
                                   'scope': 'https://graph.microsoft.com/.default', 'grant_type': 'client_credentials'})
        r.raise_for_status(); d = r.json()
        self._token = d['access_token']; self._expires = time.time() + int(d.get('expires_in', 3600))
        return self._token

    def _h(self):
        return {'Authorization': 'Bearer ' + self.token()}

    def unread(self, top=10):
        r = self.client.get(f'{GRAPH}/users/{self.cfg.mailbox}/mailFolders/inbox/messages', headers=self._h(), params={
            '$filter': 'isRead eq false', '$top': str(top), '$orderby': 'receivedDateTime',
            '$select': 'id,subject,from,sender,body,internetMessageId,internetMessageHeaders,hasAttachments'})
        r.raise_for_status(); return r.json().get('value', [])

    def attachments(self, mid):
        base = f'{GRAPH}/users/{self.cfg.mailbox}/messages/{mid}/attachments'
        r = self.client.get(base, headers=self._h(), params={'$select': 'id,name,contentType,size'})
        r.raise_for_status(); out = []
        for a in r.json().get('value', [])[:5]:
            if (a.get('size') or 0) > 8 * 1024 * 1024:
                continue
            kind = a.get('@odata.type', '')
            if kind.endswith('itemAttachment'):
                m = self.client.get(f'{base}/{a["id"]}/$value', headers=self._h())
                if m.status_code == 200:
                    out.append({**a, 'mime': m.content})
            elif kind.endswith('fileAttachment') and ((a.get('name') or '').lower().endswith('.eml') or (a.get('contentType') or '').lower() == 'message/rfc822'):
                f = self.client.get(f'{base}/{a["id"]}', headers=self._h())
                if f.status_code == 200:
                    out.append(f.json())
        return out

    def send(self, to, subject, body_html):
        r = self.client.post(f'{GRAPH}/users/{self.cfg.mailbox}/sendMail', headers=self._h(), json={
            'message': {'subject': subject[:200], 'body': {'contentType': 'HTML', 'content': body_html},
                        'toRecipients': [{'emailAddress': {'address': to}}],
                        'internetMessageHeaders': [{'name': 'X-Inbox-Check', 'value': 'result'}]},
            'saveToSentItems': False})
        r.raise_for_status()

    def finish(self, mid):
        # Deleted, not archived: the case store is the only retained copy, with its own expiry.
        r = self.client.delete(f'{GRAPH}/users/{self.cfg.mailbox}/messages/{mid}', headers=self._h())
        if r.status_code not in (204, 404):
            r = self.client.patch(f'{GRAPH}/users/{self.cfg.mailbox}/messages/{mid}', headers=self._h(), json={'isRead': True})
            r.raise_for_status()


# ---------- processing ----------

def process_message(message, mailbox, store, screen, cfg):
    """Handle one inbound message. `screen(user, text, source)` returns (case_id, payload).
    Returns a short outcome label for logs (never message content)."""
    mid = message['id']
    key = message.get('internetMessageId') or mid
    if not store.mail_first_seen(key):
        mailbox.finish(mid); return 'duplicate'
    headers = header_map(message.get('internetMessageHeaders'))
    sender = (parseaddr(((message.get('from') or {}).get('emailAddress') or {}).get('address') or '')[1] or '').lower()
    if not sender or sender == cfg.mailbox or is_automated(headers) or headers.get('x-inbox-check'):
        mailbox.finish(mid); return 'ignored_automated'
    if not sender_verified(headers, sender, cfg.internal_domains):
        mailbox.finish(mid); return 'ignored_unverified'
    subject = message.get('subject') or ''
    code = LINK_CODE.search(subject.upper())
    if code:
        u = store.claim_mail_link(code.group(0), sender)
        if u:
            mailbox.send(sender, 'Inbox Check: this address is linked', notice_body(
                'This address is now linked to your Inbox Check account. Forward any email you are unsure about to '
                + cfg.mailbox + ' and you will get the result back here.'))
            mailbox.finish(mid); return 'linked'
        mailbox.finish(mid); return 'ignored_bad_code'
    u = store.mail_user_or_create(sender)
    if not u:
        mailbox.finish(mid); return 'ignored_capacity'
    if not store.reserve(u['id']):
        mailbox.send(sender, 'Inbox Check: limit reached', notice_body(
            'You have reached the pilot checking limit for now. Please try again later.'))
        mailbox.finish(mid); return 'rate_limited'
    attachments = mailbox.attachments(mid) if message.get('hasAttachments') else []
    try:
        text, source = forwarded_text(message, attachments)
        if len(text) < 20:
            raise InputError('empty')
        cid, payload = screen(u, text, source)
    except InputError:
        mailbox.send(sender, 'Inbox Check: nothing to check', notice_body(
            'We could not find the email to check. Forward the suspicious message itself (or attach it), '
            'including its sender line and body.'))
        mailbox.finish(mid); return 'no_content'
    except Exception as e:  # provider failures: tell the user, imply nothing
        log.warning('mailcheck screening failed: %s', type(e).__name__)
        mailbox.send(sender, 'Inbox Check: check did not complete', notice_body(
            'The check did not complete, so no assessment is implied. Please try again in a few minutes.'))
        mailbox.finish(mid); return 'screen_failed'
    label = RISK_LABELS.get(payload['assessment']['risk'], 'Result')
    mailbox.send(sender, f'Inbox Check: {label}' + (f' — {subject[:120]}' if subject else ''), reply_body(payload, cfg.origin))
    mailbox.finish(mid); return 'replied'
