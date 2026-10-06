from cryptography.fernet import Fernet
from app.store import Store


def make(tmp_path, monkeypatch):
    monkeypatch.setenv('DB_PATH', str(tmp_path / 'cases.db'))
    monkeypatch.setenv('DATA_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.delenv('DATA_ENCRYPTION_KEY_PREVIOUS', raising=False)
    monkeypatch.setenv('USER_HOURLY_LIMIT', '3')
    monkeypatch.setenv('DAILY_ANALYSIS_LIMIT', '6')
    s = Store()
    with s.db() as c:
        c.execute("INSERT INTO users VALUES('rev','Reviewer','reviewer')")
        c.execute("INSERT INTO users VALUES('sub','Submitter','submitter')")
        c.execute("INSERT INTO users VALUES('gst','Guest','guest')")
        for u in ('rev', 'sub', 'gst'):
            c.execute('INSERT INTO sessions VALUES(?,?,?)', ('h-' + u, u, 9e9))
    return s


def test_reviewer_skips_hourly_cap_but_not_daily(tmp_path, monkeypatch):
    s = make(tmp_path, monkeypatch)
    assert all(s.reserve('rev') for _ in range(5))
    assert s.reserve('sub')
    assert not s.reserve('rev')  # daily cap of 6 reached


def test_non_reviewers_keep_hourly_cap(tmp_path, monkeypatch):
    s = make(tmp_path, monkeypatch)
    assert [s.reserve('gst') for _ in range(4)] == [True, True, True, False]
