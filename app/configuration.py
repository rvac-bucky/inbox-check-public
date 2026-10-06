"""Self-host configuration checks; prints setting names, never values."""
import os
from urllib.parse import urlsplit
from cryptography.fernet import Fernet

def errors(env):
    out=[]
    try:Fernet(env.get('DATA_ENCRYPTION_KEY','').encode())
    except (ValueError,TypeError):out.append('DATA_ENCRYPTION_KEY must be a Fernet key.')
    if len(env.get('BOOTSTRAP_KEY',''))<32:out.append('BOOTSTRAP_KEY must contain at least 32 random characters.')
    origin=urlsplit(env.get('PUBLIC_ORIGIN',''))
    local=env.get('LOCAL_DEV')=='1'
    if not origin.hostname or origin.username or origin.password or origin.path not in ('','/') or origin.query or origin.fragment:
        out.append('PUBLIC_ORIGIN must be an origin, without credentials, path, query or fragment.')
    if local:
        if origin.hostname not in ('localhost','127.0.0.1','::1') or origin.scheme!='http':out.append('LOCAL_DEV requires an HTTP loopback origin.')
    elif origin.scheme!='https':out.append('PUBLIC_ORIGIN must use HTTPS outside local development.')
    if not env.get('OPENROUTER_API_KEY'):out.append('OPENROUTER_API_KEY is required for the typed classifier.')
    if env.get('AI_BASE_URL'):
        u=urlsplit(env['AI_BASE_URL'])
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:out.append('AI_BASE_URL must be an HTTPS API base URL.')
        for name in ('AI_API_KEY','AI_MODEL'):
            if not env.get(name):out.append(name+' is required when AI_BASE_URL is set.')
    elif not env.get('AZURE_OPENAI_ENDPOINT','').endswith('.openai.azure.com'):
        out.append('Configure AI_BASE_URL/AI_API_KEY/AI_MODEL or AZURE_OPENAI_ENDPOINT (with key or managed identity).')
    fields=('MAILCHECK_TENANT_ID','MAILCHECK_CLIENT_ID','MAILCHECK_CLIENT_SECRET','MAILCHECK_MAILBOX')
    if any(env.get(k) for k in fields):
        for k in fields:
            if not env.get(k):out.append(k+' is required when mail checking is enabled.')
        mailbox=env.get('MAILCHECK_MAILBOX','')
        if mailbox.count('@')!=1 or any(c.isspace() for c in mailbox):out.append('MAILCHECK_MAILBOX must be one mailbox address.')
    if env.get('EVIDENCE_SELECTION','rules') not in ('rules','ai'):out.append('EVIDENCE_SELECTION must be rules or ai.')
    if env.get('SCREENING_ROUTE','direct') not in ('direct','agent','auto'):out.append('SCREENING_ROUTE must be direct, agent or auto.')
    if env.get('SCREENING_ROUTE')=='agent' and not all(env.get(k) for k in ('AGENT_GATEWAY_URL','AGENT_GATEWAY_TOKEN')):out.append('Agent route needs AGENT_GATEWAY_URL and AGENT_GATEWAY_TOKEN.')
    return out

def main():
    issues=errors(os.environ)
    if issues:
        for issue in issues:print(issue)
        raise SystemExit(2)
    print('Configuration valid (secret values withheld).')

if __name__=='__main__':main()
