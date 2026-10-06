import logging
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from cryptography.fernet import Fernet, MultiFernet, InvalidToken

class RateLimited(ValueError):
    pass

def digest(s): return hashlib.sha256(s.encode()).hexdigest()

class Store:
    def __init__(self):
        self.path = os.environ.get('DB_PATH','/home/inboxcheck/cases.db')
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        # DATA_ENCRYPTION_KEY encrypts; DATA_ENCRYPTION_KEY_PREVIOUS (comma-separated) only
        # decrypts, and startup re-encrypts every stored row under the current key, so an old
        # key can be retired as soon as this has run once.
        previous=[k.strip() for k in os.environ.get('DATA_ENCRYPTION_KEY_PREVIOUS','').split(',') if k.strip()]
        self.box = MultiFernet([Fernet(k.encode()) for k in [os.environ['DATA_ENCRYPTION_KEY'].strip()]+previous])
        with self.db() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS agent_tokens(hash TEXT PRIMARY KEY,user_id TEXT,expires REAL);
            CREATE TABLE IF NOT EXISTS invites(hash TEXT PRIMARY KEY,name TEXT,role TEXT,expires REAL);
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,role TEXT);
            CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,user_id TEXT,expires REAL);
            CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,user_id TEXT,created REAL,expires REAL,shared INTEGER DEFAULT 0,payload BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts(user_id TEXT,at REAL);
            CREATE TABLE IF NOT EXISTS login_attempts(ip TEXT,at REAL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,at REAL,user_id TEXT,case_id TEXT,action TEXT);
            CREATE TABLE IF NOT EXISTS usage(at REAL,model TEXT,input_tokens INTEGER,output_tokens INTEGER,cost REAL);
            CREATE TABLE IF NOT EXISTS enrollment_links(id TEXT PRIMARY KEY, hash TEXT UNIQUE, secret BLOB NOT NULL, label TEXT NOT NULL, created REAL, expires REAL, enabled INTEGER DEFAULT 1, joins INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS login_buckets(key TEXT PRIMARY KEY, started REAL, count INTEGER);
            CREATE TABLE IF NOT EXISTS mail_senders(email TEXT PRIMARY KEY, user_id TEXT NOT NULL, created REAL);
            CREATE TABLE IF NOT EXISTS mail_link_codes(hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires REAL);
            CREATE TABLE IF NOT EXISTS mail_seen(hash TEXT PRIMARY KEY, at REAL);
            CREATE TABLE IF NOT EXISTS mail_work(hash TEXT PRIMARY KEY, state TEXT NOT NULL, attempts INTEGER NOT NULL, updated REAL NOT NULL, payload BLOB);
            CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS agent_user ON agent_tokens(user_id);
            CREATE INDEX IF NOT EXISTS cases_user ON cases(user_id);
            CREATE INDEX IF NOT EXISTS attempts_user_at ON attempts(user_id,at);
            CREATE INDEX IF NOT EXISTS attempts_at ON attempts(at);
            CREATE INDEX IF NOT EXISTS cases_expires ON cases(expires);
            CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires);
            CREATE INDEX IF NOT EXISTS invites_expires ON invites(expires);
            CREATE INDEX IF NOT EXISTS agents_expires ON agent_tokens(expires);
            CREATE INDEX IF NOT EXISTS events_at ON events(at);
            CREATE INDEX IF NOT EXISTS usage_at ON usage(at);
            DELETE FROM login_attempts;
            ''')
        os.chmod(self.path,0o600)
        if previous:
            done,bad=self.rotate_keys()
            logging.getLogger('inboxcheck.store').warning('data key rotation: %d rows re-encrypted, %d unreadable',done,bad)

    def rotate_keys(self):
        """Re-encrypt stored rows under the current key. Rows no configured key can read are left
        untouched (they expire on their own). Returns (rotated, unreadable)."""
        done=bad=0
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            for table,col,identifier in (('cases','payload','id'),('enrollment_links','secret','id'),('mail_work','payload','hash')):
                for rid,blob in c.execute(f'SELECT {identifier},{col} FROM {table} WHERE {col} IS NOT NULL').fetchall():
                    try:c.execute(f'UPDATE {table} SET {col}=? WHERE {identifier}=?',(self.box.rotate(blob),rid));done+=1
                    except InvalidToken:bad+=1
        return done,bad

    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row
        try:
            c.execute('PRAGMA busy_timeout=10000'); c.execute('PRAGMA secure_delete=ON')
            with c: yield c
        finally:c.close()

    def encrypt(self,d):return self.box.encrypt(json.dumps(d).encode())
    def decrypt(self,b):return json.loads(self.box.decrypt(b).decode())

    def purge(self,c):
        now=time.time()
        for t in ('cases','sessions','invites','agent_tokens','enrollment_links','mail_link_codes'):c.execute(f'DELETE FROM {t} WHERE expires<?',(now,))
        c.execute('DELETE FROM mail_seen WHERE at<?',(now-30*86400,))
        c.execute("UPDATE mail_work SET payload=NULL,state='failed' WHERE updated<? AND payload IS NOT NULL",(now-86400,))
        c.execute('DELETE FROM mail_work WHERE updated<?',(now-30*86400,))
        for t in ('attempts','events','usage'):c.execute(f'DELETE FROM {t} WHERE at<?',(now-7*86400,))
        c.execute('DELETE FROM login_buckets WHERE started<?',(now-300,))
        # Preserve ownership of retained cases, including expired-session users.
        c.execute('''DELETE FROM users WHERE NOT EXISTS(SELECT 1 FROM sessions WHERE sessions.user_id=users.id)
            AND NOT EXISTS(SELECT 1 FROM agent_tokens WHERE agent_tokens.user_id=users.id)
            AND NOT EXISTS(SELECT 1 FROM cases WHERE cases.user_id=users.id)
            AND NOT EXISTS(SELECT 1 FROM mail_senders WHERE mail_senders.user_id=users.id)''')

    def invite(self,name,role):
        code=secrets.token_urlsafe(32)
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            if c.execute("SELECT count(*) FROM users WHERE role!='guest'").fetchone()[0]>=100: raise ValueError('Pilot participant limit reached')
            if c.execute('SELECT count(*) FROM invites').fetchone()[0]>=100:raise ValueError('Invite limit reached')
            c.execute('INSERT INTO invites VALUES(?,?,?,?)',(digest(code),name,role,time.time()+86400))
        return code

    def _login_admit(self,c,key,now,per_code=15):
        globalrow=c.execute("SELECT count FROM login_buckets WHERE key='global'").fetchone()
        localrow=c.execute('SELECT count FROM login_buckets WHERE key=?',(key,)).fetchone()
        if (globalrow and globalrow[0]>=300) or (localrow and localrow[0]>=per_code):
            raise RateLimited('Sign-in rate limit reached. Please wait five minutes.')
        if not localrow and c.execute('SELECT count(*) FROM login_buckets').fetchone()[0]>=301:
            raise RateLimited('Sign-in rate limit reached. Please wait five minutes.')
        for bucket in ('global',key):
            c.execute('INSERT INTO login_buckets VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1',(bucket,now))

    def redeem(self,code,ip=None):
        # Identity-independent global + code buckets: do not trust client-supplied
        # forwarding headers or lock an office behind one shared proxy IP.
        now=time.time();key=digest(code)
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            self._login_admit(c,key,now)
            row=c.execute('SELECT * FROM invites WHERE hash=?',(key,)).fetchone()
            if not row:return None
            if c.execute("SELECT count(*) FROM users WHERE role!='guest'").fetchone()[0]>=100:
                raise RateLimited('Pilot participant limit reached. Ask your reviewer for help.')
            c.execute('DELETE FROM invites WHERE hash=?',(key,))
            uid=secrets.token_hex(16);token=secrets.token_urlsafe(32)
            c.execute('INSERT INTO users VALUES(?,?,?)',(uid,row['name'],row['role']))
            c.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(token),uid,now+43200))
            return token

    def user(self,token):
        if not token or len(token)>100:return None
        with self.db() as c:
            r=c.execute('SELECT users.* FROM users JOIN sessions ON user_id=users.id WHERE hash=? AND sessions.expires>?',(digest(token),time.time())).fetchone()
            return dict(r) if r else None

    def logout(self,token):
        with self.db() as c:c.execute('DELETE FROM sessions WHERE hash=?',(digest(token),))

    def revoke_agent(self,uid):
        with self.db() as c:c.execute('DELETE FROM agent_tokens WHERE user_id=?',(uid,))

    def revoke(self,kind,value):
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            if kind=='user':
                c.execute('DELETE FROM sessions WHERE user_id=?',(value,))
                c.execute('DELETE FROM agent_tokens WHERE user_id=?',(value,))
            elif kind=='invite':c.execute('DELETE FROM invites WHERE hash=?',(digest(value),))
            else:raise ValueError('Invalid revocation')
            # Preserve cases; only future access is revoked.
            c.execute('INSERT INTO events(at,user_id,case_id,action) VALUES(?,?,?,?)',(time.time(),'operator',None,'revoke_'+kind))

    def reserve(self,uid):
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            usern=c.execute('SELECT count(*) FROM attempts WHERE user_id=? AND at>?',(uid,time.time()-3600)).fetchone()[0]
            globaln=c.execute('SELECT count(*) FROM attempts WHERE at>?',(time.time()-86400,)).fetchone()[0]
            # Reviewers are exempt from the per-person hourly cap; everyone counts toward the daily cap.
            role=(c.execute('SELECT role FROM users WHERE id=?',(uid,)).fetchone() or [None])[0]
            hourly=role!='reviewer' and usern>=int(os.environ.get('USER_HOURLY_LIMIT','10'))
            if hourly or globaln>=int(os.environ.get('DAILY_ANALYSIS_LIMIT','100')):return False
            c.execute('INSERT INTO attempts VALUES(?,?)',(uid,time.time()));return True

    def record_usage(self,model,u):
        with self.db() as c:c.execute('INSERT INTO usage VALUES(?,?,?,?,?)',(time.time(),model,int(u.get('input_tokens',u.get('prompt_tokens',0))),int(u.get('output_tokens',u.get('completion_tokens',0))),float(u.get('cost',0))))

    def save(self,uid,payload):
        cid=secrets.token_hex(12);now=time.time()
        with self.db() as c:
            c.execute('INSERT INTO cases VALUES(?,?,?,?,?,?)',(cid,uid,now,now+86400,0,self.encrypt(payload)))
            c.execute('INSERT INTO events(at,user_id,case_id,action) VALUES(?,?,?,?)',(now,uid,cid,'created'))
        return cid

    def get(self,cid,user):
        with self.db() as c:
            r=c.execute('SELECT * FROM cases WHERE id=? AND expires>?',(cid,time.time())).fetchone()
            if not r or not (r['user_id']==user['id'] or (r['shared'] and user['role']=='reviewer')):return None
            return dict(r)|{'payload':self.decrypt(r['payload'])}

    def list(self,user):
        with self.db() as c:
            rs=c.execute('SELECT * FROM cases WHERE expires>? AND (user_id=? OR (shared=1 AND ?=\'reviewer\')) ORDER BY created DESC LIMIT 100',(time.time(),user['id'],user['role'])).fetchall()
            return [{'id':r['id'],'created':r['created'],'shared':bool(r['shared']),'risk':self.decrypt(r['payload'])['assessment']['risk'],'reviewed':bool(self.decrypt(r['payload']).get('review'))} for r in rs]

    def change(self,cid,user,action,note=''):
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            r=c.execute('SELECT * FROM cases WHERE id=?',(cid,)).fetchone()
            if not r:return False
            if action in ('share','delete') and r['user_id']!=user['id']:return False
            if action=='review' and (user['role']!='reviewer' or not r['shared']):return False
            if action=='share':c.execute('UPDATE cases SET shared=1 WHERE id=?',(cid,))
            elif action=='delete':c.execute('DELETE FROM cases WHERE id=?',(cid,))
            elif action=='review':
                p=self.decrypt(r['payload']);p['review']={'reviewer':user['name'],'note':note,'at':time.time()}
                c.execute('UPDATE cases SET payload=? WHERE id=?',(self.encrypt(p),cid))
            else:return False
            c.execute('INSERT INTO events(at,user_id,case_id,action) VALUES(?,?,?,?)',(time.time(),user['id'],cid,action))
            return True

    def agent_token(self,name):
        token=secrets.token_urlsafe(40);uid=secrets.token_hex(16)
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            if c.execute("SELECT count(*) FROM users WHERE role!='guest'").fetchone()[0]>=100:raise ValueError('Pilot participant limit reached')
            if c.execute('SELECT count(*) FROM agent_tokens').fetchone()[0]>=10:raise ValueError('Agent limit reached')
            c.execute('INSERT INTO users VALUES(?,?,?)',(uid,name,'agent'))
            c.execute('INSERT INTO agent_tokens VALUES(?,?,?)',(digest(token),uid,time.time()+7*86400))
        return token,uid

    def agent_user(self,token):
        with self.db() as c:
            r=c.execute('SELECT users.* FROM users JOIN agent_tokens ON user_id=users.id WHERE hash=? AND agent_tokens.expires>?',(digest(token),time.time())).fetchone()
            return dict(r) if r else None

    def create_enrollment(self,label):
        now=time.time();code=secrets.token_urlsafe(32);lid=secrets.token_hex(16)
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            if c.execute('SELECT count(*) FROM enrollment_links').fetchone()[0]>=10:raise RateLimited('Shared-link limit reached. Existing links remain usable until expiry.')
            c.execute('INSERT INTO enrollment_links VALUES(?,?,?,?,?,?,1,0)',(lid,digest(code),self.encrypt({'code':code}),label,now,now+7*86400))
        return {'id':lid,'code':code,'label':label,'expires':now+7*86400,'enabled':True,'joins':0}

    def enrollment_list(self):
        with self.db() as c:
            rows=c.execute('SELECT * FROM enrollment_links WHERE expires>? ORDER BY created DESC',(time.time(),)).fetchall()
            return [{'id':r['id'],'label':r['label'],'expires':r['expires'],'enabled':bool(r['enabled']),'joins':r['joins'],**({'code':self.decrypt(r['secret'])['code']} if r['enabled'] else {})} for r in rows]

    def revoke_enrollment(self,lid):
        with self.db() as c:
            return c.execute('UPDATE enrollment_links SET enabled=0 WHERE id=?',(lid,)).rowcount>0

    def join_enrollment(self,code,name,existing_token=''):
        now=time.time();key=digest(code)
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            row=c.execute('SELECT * FROM enrollment_links WHERE hash=? AND enabled=1 AND expires>?',(key,now)).fetchone()
            # Shared links intentionally permit many joins; invalid codes retain the
            # tighter per-code limit. Both use the same bounded global login budget.
            self._login_admit(c,digest('join:'+code),now,300 if row else 15)
            if not row:return None
            if existing_token and len(existing_token)<=100:
                old=c.execute('SELECT user_id FROM sessions WHERE hash=? AND expires>?',(digest(existing_token),now)).fetchone()
                if old:return {'token':existing_token,'created':False}
            if c.execute("SELECT count(*) FROM users WHERE role!='guest'").fetchone()[0]>=100:raise RateLimited('The pilot is at capacity. Please try again later; no registration was created.')
            uid=secrets.token_hex(16);token=secrets.token_urlsafe(32)
            c.execute('INSERT INTO users VALUES(?,?,?)',(uid,name,'submitter'))
            c.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(token),uid,now+43200))
            c.execute('UPDATE enrollment_links SET joins=joins+1 WHERE id=?',(row['id'],))
            c.execute('INSERT INTO events(at,user_id,case_id,action) VALUES(?,?,?,?)',(now,uid,None,'joined_shared_link'))
            return {'token':token,'created':True}

    # Forward-to-check mailbox. A sender address is linked to a pilot user only when a
    # DMARC-verified message from that address carries a short-lived code the user created.
    MAIL_CODE_ALPHABET='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

    def create_mail_link(self,uid):
        body=''.join(secrets.choice(self.MAIL_CODE_ALPHABET) for _ in range(8))
        code='IC-'+body[:4]+'-'+body[4:]
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            c.execute('DELETE FROM mail_link_codes WHERE user_id=?',(uid,))
            c.execute('INSERT INTO mail_link_codes VALUES(?,?,?)',(digest(code),uid,time.time()+900))
        return code

    def claim_mail_link(self,code,email):
        email=email.strip().lower()
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            row=c.execute('SELECT user_id FROM mail_link_codes WHERE hash=?',(digest(code),)).fetchone()
            if not row:return None
            c.execute('DELETE FROM mail_link_codes WHERE hash=?',(digest(code),))
            u=c.execute('SELECT * FROM users WHERE id=?',(row['user_id'],)).fetchone()
            if not u:return None
            c.execute('INSERT INTO mail_senders VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET user_id=excluded.user_id,created=excluded.created',(email,u['id'],time.time()))
            c.execute('INSERT INTO events(at,user_id,case_id,action) VALUES(?,?,?,?)',(time.time(),u['id'],None,'mail_linked'))
            return dict(u)

    def mail_user(self,email):
        with self.db() as c:
            r=c.execute('SELECT users.* FROM users JOIN mail_senders ON user_id=users.id WHERE email=?',(email.strip().lower(),)).fetchone()
            return dict(r) if r else None

    def mail_addresses(self,uid):
        with self.db() as c:return [r['email'] for r in c.execute('SELECT email FROM mail_senders WHERE user_id=? ORDER BY created',(uid,))]

    def unlink_mail(self,uid,email):
        with self.db() as c:return c.execute('DELETE FROM mail_senders WHERE user_id=? AND email=?',(uid,email.strip().lower())).rowcount>0

    GUEST_LIMIT=5000

    def start_guest(self,existing_token=''):
        """Open access: a private, invitation-free session. Returns the existing session when still valid."""
        now=time.time()
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE');self.purge(c)
            if existing_token and len(existing_token)<=100:
                old=c.execute('SELECT user_id FROM sessions WHERE hash=? AND expires>?',(digest(existing_token),now)).fetchone()
                if old:return {'token':existing_token,'created':False}
            self._login_admit(c,digest('guest'),now,300)
            if c.execute("SELECT count(*) FROM users WHERE role='guest'").fetchone()[0]>=self.GUEST_LIMIT:
                raise RateLimited('Inbox Check is busy right now. Please try again later.')
            uid=secrets.token_hex(16);token=secrets.token_urlsafe(32)
            c.execute('INSERT INTO users VALUES(?,?,?)',(uid,'Guest','guest'))
            c.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(token),uid,now+43200))
            return {'token':token,'created':True}

    def mail_user_or_create(self,email):
        """A verified sender with no linked account gets its own guest identity for email checks."""
        email=email.strip().lower();now=time.time()
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            r=c.execute('SELECT users.* FROM users JOIN mail_senders ON user_id=users.id WHERE email=?',(email,)).fetchone()
            if r:return dict(r)
            if c.execute("SELECT count(*) FROM users WHERE role='guest'").fetchone()[0]>=self.GUEST_LIMIT:return None
            uid=secrets.token_hex(16)
            c.execute('INSERT INTO users VALUES(?,?,?)',(uid,'Email user','guest'))
            c.execute('INSERT INTO mail_senders VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET user_id=excluded.user_id',(email,uid,now))
            return {'id':uid,'name':'Email user','role':'guest'}

    def mail_first_seen(self,message_key):
        """Record a mailbox message once; False means it was already handled (no duplicate replies)."""
        with self.db() as c:
            return c.execute('INSERT OR IGNORE INTO mail_seen VALUES(?,?)',(digest(message_key),time.time())).rowcount==1

    def mail_claim(self, key):
        """Single-worker leased work. Ambiguous sends never replay automatically."""
        hashed=digest(key);now=time.time()
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM mail_seen WHERE hash=?',(hashed,)).fetchone():return 'done',None
            row=c.execute('SELECT state,attempts,updated,payload FROM mail_work WHERE hash=?',(hashed,)).fetchone()
            if row:
                state,attempts,updated,payload=row
                if state in ('sending','uncertain','failed'):return 'held',None
                if state=='working' and now-updated<300:return 'busy',None
                if state=='retry' and now-updated<min(300,30*2**(attempts-1)):return 'busy',None
                if attempts>=3:
                    c.execute("UPDATE mail_work SET state='failed' WHERE hash=?",(hashed,));return 'held',None
                c.execute("UPDATE mail_work SET state='working',attempts=attempts+1,updated=? WHERE hash=?",(now,hashed))
                return 'claimed',self.decrypt(payload) if payload else None
            c.execute('INSERT INTO mail_work VALUES(?,?,?,?,NULL)',(hashed,'working',1,now))
            return 'claimed',None

    def mail_state(self,key,state,payload=None):
        with self.db() as c:
            if payload is None:
                c.execute('UPDATE mail_work SET state=?,updated=? WHERE hash=?',(state,time.time(),digest(key)))
            else:
                c.execute('UPDATE mail_work SET state=?,updated=?,payload=? WHERE hash=?',(state,time.time(),self.encrypt(payload),digest(key)))

    def mail_complete(self,key):
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('INSERT OR IGNORE INTO mail_seen VALUES(?,?)',(digest(key),time.time()))
            c.execute('DELETE FROM mail_work WHERE hash=?',(digest(key),))
