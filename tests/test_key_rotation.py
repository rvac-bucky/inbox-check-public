import sqlite3
from cryptography.fernet import Fernet
from app.store import Store


def test_rotation_reencrypts_rows_and_retires_old_key(tmp_path, monkeypatch):
    db = tmp_path / 'cases.db'
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setenv('DB_PATH', str(db))
    monkeypatch.setenv('DATA_ENCRYPTION_KEY', old)
    monkeypatch.delenv('DATA_ENCRYPTION_KEY_PREVIOUS', raising=False)
    s = Store()
    cid = s.save('u1', {'assessment': {'risk': 'suspicious'}, 'text': 'hello'})
    s.create_enrollment('pilot')
    s.mail_claim('pending');s.mail_state('pending','retry',{'body':'synthetic reply'})
    # Switch keys: new primary, old only for decryption; startup rotates.
    monkeypatch.setenv('DATA_ENCRYPTION_KEY', new)
    monkeypatch.setenv('DATA_ENCRYPTION_KEY_PREVIOUS', old)
    Store()
    # With ONLY the new key, every row still decrypts: the old key is retired.
    monkeypatch.delenv('DATA_ENCRYPTION_KEY_PREVIOUS')
    s3 = Store()
    with sqlite3.connect(db) as c:
        blob = c.execute('SELECT payload FROM cases WHERE id=?', (cid,)).fetchone()[0]
    assert s3.decrypt(blob)['assessment']['risk'] == 'suspicious'
    for (b,) in sqlite3.connect(db).execute('SELECT payload FROM mail_work'):
        assert s3.decrypt(b)['body']=='synthetic reply'
    for (b,) in sqlite3.connect(db).execute('SELECT secret FROM enrollment_links'):
        Fernet(new.encode()).decrypt(b)


def test_unreadable_rows_do_not_block_startup(tmp_path, monkeypatch):
    db = tmp_path / 'cases.db'
    monkeypatch.setenv('DB_PATH', str(db))
    monkeypatch.setenv('DATA_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.delenv('DATA_ENCRYPTION_KEY_PREVIOUS', raising=False)
    Store().save('u1', {'x': 1})
    monkeypatch.setenv('DATA_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('DATA_ENCRYPTION_KEY_PREVIOUS', Fernet.generate_key().decode())
    s = Store()
    assert s.rotate_keys() == (0, 1)
