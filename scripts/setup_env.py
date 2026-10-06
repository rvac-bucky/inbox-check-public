#!/usr/bin/env python3
"""Generate local encryption/operator keys without printing them or overwriting config."""
import base64,os,secrets
from pathlib import Path
root=Path(__file__).resolve().parents[1]
text=(root/'.env.example').read_text()
text=text.replace('DATA_ENCRYPTION_KEY=\n','DATA_ENCRYPTION_KEY='+base64.urlsafe_b64encode(os.urandom(32)).decode()+'\n')
text=text.replace('BOOTSTRAP_KEY=\n','BOOTSTRAP_KEY='+secrets.token_urlsafe(48)+'\n')
fd=os.open(root/'.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:f.write(text)
print('Created .env (0600). Add your provider credentials privately. Existing files are never overwritten.')
