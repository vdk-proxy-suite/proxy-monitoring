import concurrent.futures
import base64
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from proxy_monitoring.oauth_store import GrantStore


class GrantStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'auth.db'
        self.now = 100000
        self.store = GrantStore(self.path, clock=lambda: self.now)
        self.tokens = self.store.issue('client', 'https://monitor.example/mcp',
                                       ['monitor:read'], refresh=True)

    def rotate(self):
        return self.store.rotate(self.tokens['refresh_token'], 'client', 'https://monitor.example/mcp')

    def test_credentials_are_not_in_database_and_survive_restart(self):
        content = self.path.read_bytes()
        for key in ('access_token', 'refresh_token'):
            self.assertNotIn(self.tokens[key].encode(), content)
        reopened = GrantStore(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.access(self.tokens['access_token'])['scopes'], ['monitor:read'])

    def test_rotation_replay_revokes_family(self):
        replacement = self.rotate()
        self.assertIsNotNone(self.store.access(replacement['access_token']))
        self.assertIsNone(self.rotate())
        self.assertIsNone(self.store.access(replacement['access_token']))
        self.assertIsNone(self.store.access(self.tokens['access_token']))
        self.assertIsNone(self.store.rotate(replacement['refresh_token'], 'client', 'https://monitor.example/mcp'))

    def test_binding_mismatch_does_not_consume_refresh(self):
        for client, resource, scopes in [('other', 'https://monitor.example/mcp', None),
                                        ('client', 'https://attacker.example/mcp', None),
                                        ('client', 'https://monitor.example/mcp', ['write'])]:
            self.assertIsNone(self.store.rotate(self.tokens['refresh_token'], client, resource, scopes))
        self.assertIsNotNone(self.rotate())

    def test_expiry_and_revocation(self):
        self.now += 600
        self.assertIsNone(self.store.access(self.tokens['access_token']))
        replacement = self.rotate()
        self.assertIsNotNone(replacement)
        self.store.revoke(replacement['access_token'], 'other')
        self.assertIsNotNone(self.store.access(replacement['access_token']))
        self.store.revoke(replacement['access_token'], 'client')
        self.assertIsNone(self.store.access(replacement['access_token']))

    def test_refresh_lifetime_is_not_extended(self):
        self.now += 30 * 86400 - 1
        replacement = self.rotate()
        self.assertEqual(replacement['expires_in'], 1)
        self.now += 1
        self.assertIsNone(self.store.rotate(replacement['refresh_token'], 'client', 'https://monitor.example/mcp'))

    def test_concurrent_rotation_has_one_winner_and_revokes_family(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.rotate(), range(2)))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertIsNone(self.store.access(winners[0]['access_token']))

    def test_non_ascii_and_unknown_credentials(self):
        for token in ('unknown', '\u2603', ''):
            self.assertIsNone(self.store.access(token))
            self.assertIsNone(self.store.rotate(token, 'client', 'https://monitor.example/mcp'))
            self.store.revoke(token, 'client')

    def code(self, scopes=None):
        verifier = 'v' * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        return self.store.authorization_code('client', 'https://monitor.example/mcp',
                                             'https://client.example/callback', challenge,
                                             scopes or ['monitor:read']), verifier

    def exchange(self, code, verifier, **overrides):
        params = dict(code=code, client='client', resource='https://monitor.example/mcp',
                      redirect='https://client.example/callback', verifier=verifier)
        params.update(overrides)
        return self.store.exchange_code(**params)

    def test_code_bindings_and_pkce(self):
        code, verifier = self.code()
        for change in [dict(client='other'), dict(resource='https://other.example/mcp'),
                       dict(redirect='https://client.example/other')]:
            self.assertIsNone(self.exchange(code, verifier, **change))
        for invalid in ('x' * 43, 'v' * 42, 'v' * 129, '\u2603' * 43):
            self.assertIsNone(self.exchange(code, invalid))
        result = self.exchange(code, verifier)
        self.assertIsNotNone(self.store.access(result['access_token']))
        self.assertNotIn('refresh_token', result)
        self.assertIsNone(self.exchange(code, verifier))

    def test_code_expiry(self):
        code, verifier = self.code()
        self.now += 60
        self.assertIsNone(self.exchange(code, verifier))

    def test_code_exchange_is_atomic(self):
        code, verifier = self.code(['monitor:read', 'offline_access'])
        self.assertNotIn(code.encode(), self.path.read_bytes())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.exchange(code, verifier), range(2)))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertIn('refresh_token', winners[0])

    def test_pending_bound_to_browser_once_and_consumed_once(self):
        token = self.store.pending({'client': 'fixture'})
        self.assertIsNone(self.store.consume_pending(token, 'browser'))
        self.assertEqual(self.store.bind_pending(token, 'browser'), {'client': 'fixture'})
        self.assertIsNone(self.store.bind_pending(token, 'attacker'))
        self.assertIsNone(self.store.consume_pending(token, 'attacker'))
        self.assertEqual(self.store.consume_pending(token, 'browser'), {'client': 'fixture'})
        self.assertIsNone(self.store.consume_pending(token, 'browser'))

    def test_pending_expiry(self):
        token = self.store.pending({'client': 'fixture'})
        self.store.bind_pending(token, 'browser')
        self.now += 300
        self.assertIsNone(self.store.consume_pending(token, 'browser'))

    def test_client_persistence_and_rate_limit(self):
        metadata = {'redirect_uris': ['https://client.example/callback']}
        client = self.store.register_client(metadata)
        reopened = GrantStore(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.client(client), metadata)
        self.assertIsNone(reopened.client('unknown'))
        self.assertTrue(self.store.allow('login', 2, 60))
        self.assertTrue(reopened.allow('login', 2, 60))
        self.assertFalse(self.store.allow('login', 2, 60))
        self.now += 60
        self.assertTrue(reopened.allow('login', 2, 60))

    def test_scope_can_only_narrow_and_admin_revokes_pending(self):
        tokens = self.store.issue('client', 'https://monitor.example/mcp',
                                  ['monitor:read', 'offline_access'], refresh=True)
        narrowed = self.store.rotate(tokens['refresh_token'], 'client', 'https://monitor.example/mcp', ['monitor:read'])
        self.assertEqual(narrowed['scope'], 'monitor:read')
        self.assertIsNone(self.store.rotate(narrowed['refresh_token'], 'client', 'https://monitor.example/mcp',
                                            ['monitor:read', 'offline_access']))
        code, verifier = self.code()
        pending = self.store.pending({'client': 'fixture'})
        self.store.revoke_all()
        self.assertIsNone(self.store.access(narrowed['access_token']))
        self.assertIsNone(self.exchange(code, verifier))
        self.assertIsNone(self.store.bind_pending(pending, 'browser'))

    def test_foreign_database_unchanged(self):
        path = self.path.parent / 'foreign.db'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE telemetry (value INTEGER)')
        db.close()
        path.chmod(0o600)
        before = path.read_bytes()
        with self.assertRaises(ValueError):
            GrantStore(path)
        self.assertEqual(path.read_bytes(), before)

    def test_prune_keeps_refresh_replay_detection_until_expiry(self):
        replacement = self.rotate()
        self.now += 601
        self.store.prune()
        self.assertIsNone(self.rotate())
        self.assertIsNone(self.store.rotate(replacement['refresh_token'], 'client', 'https://monitor.example/mcp'))
        self.now += 30 * 86400
        self.store.prune()
        with self.store.transaction() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grants').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM tokens').fetchone()[0], 0)
