"""Durable OAuth grants; bearer credentials are stored only as SHA-256 digests.

This database is separate from telemetry. Rotation and replay revocation are
serialized by SQLite, including when multiple processes share the database.
"""
import hashlib
import base64
import hmac
import json
import os
import secrets
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def digest(value: str) -> str:
    return hashlib.sha256(value.encode('ascii')).hexdigest()


class GrantStore:
    def __init__(self, path: Path, *, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if os.name != 'nt' and self.path.stat().st_mode & 0o077:
            raise ValueError('oauth_database_must_be_private')
        with self.transaction() as db:
            application_id = db.execute('PRAGMA application_id').fetchone()[0]
            version = db.execute('PRAGMA user_version').fetchone()[0]
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if ((application_id, version) != (0x504d4f41, 1)
                    and (application_id != 0 or version != 0 or tables)):
                raise ValueError('foreign_or_unsupported_oauth_database')
            db.execute('PRAGMA application_id=1347243841')
            db.execute('PRAGMA user_version=1')
            db.execute('CREATE TABLE IF NOT EXISTS grants ('
                       'id TEXT PRIMARY KEY, client TEXT NOT NULL, resource TEXT NOT NULL, '
                       'scopes TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE TABLE IF NOT EXISTS tokens ('
                       'hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id), '
                       'kind TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, '
                       'scopes TEXT NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS tokens_grant ON tokens(grant_id)')
            db.execute('CREATE TABLE IF NOT EXISTS codes ('
                       'hash TEXT PRIMARY KEY, client TEXT NOT NULL, resource TEXT NOT NULL, '
                       'redirect TEXT NOT NULL, challenge TEXT NOT NULL, scopes TEXT NOT NULL, '
                       'expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, grant_id TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS pending ('
                       'hash TEXT PRIMARY KEY, payload TEXT NOT NULL, browser_hash TEXT, expires INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS limits ('
                       'name TEXT PRIMARY KEY, started INTEGER NOT NULL, count INTEGER NOT NULL)')

    def register_client(self, metadata):
        client = secrets.token_urlsafe(24)
        with self.transaction() as db:
            if db.execute('SELECT count(*) FROM clients').fetchone()[0] >= 1000:
                return None
            db.execute('INSERT INTO clients VALUES (?, ?)', (client, json.dumps(metadata)))
        return client

    def client(self, client):
        with self.transaction() as db:
            row = db.execute('SELECT metadata FROM clients WHERE id=?', (client,)).fetchone()
            return json.loads(row[0]) if row else None

    def allow(self, name, maximum, seconds):
        """Persistent bounded global rate buckets, never keyed by attacker input."""
        now = int(self.clock())
        with self.transaction() as db:
            row = db.execute('SELECT started, count FROM limits WHERE name=?', (name,)).fetchone()
            if not row or row['started'] + seconds <= now:
                db.execute('INSERT OR REPLACE INTO limits VALUES (?, ?, 1)', (name, now))
                return True
            if row['count'] >= maximum:
                return False
            db.execute('UPDATE limits SET count=count+1 WHERE name=?', (name,))
            return True

    def pending(self, payload):
        token = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute('DELETE FROM pending WHERE expires<=?', (int(self.clock()),))
            if db.execute('SELECT count(*) FROM pending').fetchone()[0] >= 1000:
                return None
            db.execute('INSERT INTO pending VALUES (?, ?, NULL, ?)',
                       (digest(token), json.dumps(payload), int(self.clock()) + 300))
        return token

    def bind_pending(self, token, browser):
        """Bind once on the first login page view; subsequent viewers cannot rebind."""
        with self.transaction() as db:
            row = db.execute('SELECT * FROM pending WHERE hash=? AND expires>?',
                             (digest(token), int(self.clock()))).fetchone()
            if not row or row['browser_hash'] is not None:
                return None
            db.execute('UPDATE pending SET browser_hash=? WHERE hash=?', (digest(browser), row['hash']))
            return json.loads(row['payload'])

    def consume_pending(self, token, browser):
        with self.transaction() as db:
            row = db.execute('SELECT * FROM pending WHERE hash=? AND expires>?',
                             (digest(token), int(self.clock()))).fetchone()
            if not row or not row['browser_hash'] or not hmac.compare_digest(row['browser_hash'], digest(browser)):
                return None
            db.execute('DELETE FROM pending WHERE hash=?', (row['hash'],))
            return json.loads(row['payload'])

    def approve_pending(self, token, browser):
        # Atomic with revoke_all: a pending authorization cannot turn into a
        # fresh code after an administrator has revoked it during password work.
        with self.transaction() as db:
            row = db.execute('SELECT * FROM pending WHERE hash=? AND expires>?',
                             (digest(token), int(self.clock()))).fetchone()
            if not row or not row['browser_hash'] or not hmac.compare_digest(row['browser_hash'], digest(browser)):
                return None
            payload = json.loads(row['payload'])
            code = secrets.token_urlsafe(32)
            db.execute('INSERT INTO codes VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)',
                (digest(code), payload['client_id'], payload['resource'], payload['redirect_uri'],
                 payload['code_challenge'], json.dumps(payload['scopes']), int(self.clock()) + 60))
            db.execute('DELETE FROM pending WHERE hash=?', (row['hash'],))
            return payload, code

    def authorization_code(self, client, resource, redirect, challenge, scopes):
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', challenge):
            raise ValueError('invalid_pkce_challenge')
        code = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute('DELETE FROM codes WHERE expires <= ?', (int(self.clock()),))
            db.execute('INSERT INTO codes VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)',
                       (digest(code), client, resource, redirect, challenge,
                        json.dumps(sorted(set(scopes))), int(self.clock()) + 60))
        return code

    def exchange_code(self, code, client, resource, redirect, verifier):
        if not isinstance(verifier, str) or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier):
            return None
        try:
            code_hash = digest(code)
        except (UnicodeError, AttributeError):
            return None
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode()
        with self.transaction() as db:
            row = db.execute('SELECT * FROM codes WHERE hash=?', (code_hash,)).fetchone()
            if (not row or row['expires'] <= self.clock()
                    or row['client'] != client or row['resource'] != resource or row['redirect'] != redirect
                    or not hmac.compare_digest(row['challenge'], challenge)):
                return None
            if row['consumed']:
                db.execute('UPDATE grants SET revoked=1 WHERE id=?', (row['grant_id'],))
                return None
            scopes = json.loads(row['scopes'])
            refresh = 'offline_access' in scopes
            expires = int(self.clock()) + (30 * 86400 if refresh else 600)
            grant_id = secrets.token_urlsafe(24)
            db.execute('UPDATE codes SET consumed=1, grant_id=? WHERE hash=?', (grant_id, code_hash))
            db.execute('INSERT INTO grants VALUES (?, ?, ?, ?, ?, 0)',
                       (grant_id, client, resource, row['scopes'], expires))
            result = self._mint(db, grant_id, expires, refresh, scopes)
            result['scope'] = ' '.join(scopes)
            return result

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _mint(self, db, grant_id, expires, refresh, scopes):
        now = int(self.clock())
        access = secrets.token_urlsafe(32)
        access_expiry = min(now + 600, expires)
        encoded_scopes = json.dumps(sorted(set(scopes)))
        db.execute('INSERT INTO tokens VALUES (?, ?, ?, ?, 0, ?)',
                   (digest(access), grant_id, 'access', access_expiry, encoded_scopes))
        result = dict(access_token=access, token_type='Bearer', expires_in=access_expiry - now,
                      scope=' '.join(sorted(set(scopes))))
        if refresh:
            token = secrets.token_urlsafe(32)
            db.execute('INSERT INTO tokens VALUES (?, ?, ?, ?, 0, ?)',
                       (digest(token), grant_id, 'refresh', expires, encoded_scopes))
            result['refresh_token'] = token
        return result

    def issue(self, client, resource, scopes, *, refresh=False):
        grant_id = secrets.token_urlsafe(24)
        expires = int(self.clock()) + (30 * 86400 if refresh else 600)
        with self.transaction() as db:
            db.execute('INSERT INTO grants VALUES (?, ?, ?, ?, ?, 0)',
                       (grant_id, client, resource, json.dumps(sorted(set(scopes))), expires))
            return self._mint(db, grant_id, expires, refresh, scopes)

    def _lookup(self, db, token):
        try:
            token_hash = digest(token)
        except (UnicodeError, AttributeError):
            return None
        return db.execute('SELECT t.*, g.client, g.resource, g.revoked, '
                          'g.expires AS grant_expires FROM tokens t JOIN grants g '
                          'ON g.id=t.grant_id WHERE t.hash=?', (token_hash,)).fetchone()

    def access(self, token):
        with self.transaction() as db:
            row = self._lookup(db, token)
            if not row or row['kind'] != 'access' or row['revoked'] or row['expires'] <= self.clock():
                return None
            return dict(client_id=row['client'], resource=row['resource'],
                        scopes=json.loads(row['scopes']), expires_at=row['expires'])

    def rotate(self, token, client, resource, scopes=None):
        # Return failures instead of raising inside the transaction: reuse must
        # commit revocation of every token belonging to this authorization.
        with self.transaction() as db:
            row = self._lookup(db, token)
            if not row or row['kind'] != 'refresh' or row['client'] != client or row['resource'] != resource:
                return None
            if row['used']:
                db.execute('UPDATE grants SET revoked=1 WHERE id=?', (row['grant_id'],))
                return None
            if row['revoked'] or row['expires'] <= self.clock():
                return None
            original = set(json.loads(row['scopes']))
            if scopes is not None and not set(scopes).issubset(original):
                return None
            db.execute('UPDATE tokens SET used=1 WHERE hash=?', (row['hash'],))
            return self._mint(db, row['grant_id'], row['grant_expires'], True,
                              original if scopes is None else scopes)

    def revoke(self, token, client):
        with self.transaction() as db:
            row = self._lookup(db, token)
            if row and row['client'] == client:
                db.execute('UPDATE grants SET revoked=1 WHERE id=?', (row['grant_id'],))

    def revoke_all(self):
        with self.transaction() as db:
            db.execute('UPDATE grants SET revoked=1')
            db.execute('DELETE FROM codes')
            db.execute('DELETE FROM pending')

    def prune(self):
        """Keep consumed refresh hashes until grant expiry to detect replay."""
        now = int(self.clock())
        with self.transaction() as db:
            db.execute('DELETE FROM pending WHERE expires<=?', (now,))
            db.execute('DELETE FROM codes WHERE expires<=?', (now,))
            db.execute("DELETE FROM tokens WHERE kind='access' AND expires<=?", (now,))
            db.execute('DELETE FROM tokens WHERE grant_id IN (SELECT id FROM grants WHERE expires<=?)', (now,))
            db.execute('DELETE FROM grants WHERE expires<=?', (now,))
