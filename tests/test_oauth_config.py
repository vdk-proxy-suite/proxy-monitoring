import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

from proxy_monitoring.oauth_config import OAuthConfig, https_url, password_hash, verify_password, redirect_url, redirect_allowed
from proxy_monitoring.cli import main
from proxy_monitoring.oauth_store import GrantStore


class OAuthConfigTests(unittest.TestCase):
    def test_loopback_redirect_validation_and_port_matching(self):
        for host in ('127.0.0.1', '[::1]'):
            base = f'http://{host}/callback'
            self.assertEqual(redirect_url(base), base)
            self.assertTrue(redirect_allowed(f'http://{host}:54321/callback', [base]))
            self.assertTrue(redirect_allowed(f'http://{host}:54322/callback', [f'http://{host}:54321/callback']))
            self.assertFalse(redirect_allowed(f'http://{host}:54321/callback/other', [base]))
            self.assertFalse(redirect_allowed(f'http://{host}:54321/callback?extra=1', [base]))
        self.assertFalse(redirect_allowed('http://[::1]:54321/callback', ['http://127.0.0.1/callback']))
        self.assertFalse(redirect_allowed('https://example.com:123/callback', ['https://example.com/callback']))
        for uri in ('http://localhost/callback', 'http://127.0.0.2/callback',
                    'http://127.1/callback', 'http://2130706433/callback',
                    'http://127.0.0.1.evil.example/callback', 'http://127.0.0.1@evil.example/callback',
                    'http://evil.example@127.0.0.1/callback', 'http://[::ffff:127.0.0.1]/callback',
                    'http://0.0.0.0/callback', 'http://10.0.0.1/callback', 'http://example.com/callback',
                    'http://127.0.0.1:0/callback', 'http://127.0.0.1:65536/callback',
                    'http://127.0.0.1:/callback', 'http://127.0.0.1/callback#',
                    'http://127.0.0.1/callback?code=bad', 'http://127.0.0.1/callback?%73tate=bad',
                    'http://127.0.0.1\\@evil.example/callback'):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                redirect_url(uri)
        with self.assertRaises(ValueError):
            https_url('http://127.0.0.1', origin=True)

    def test_cli_initialization_no_overwrite_and_revoke(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'oauth.json'
            config.write_text(json.dumps(dict(issuer='https://monitor.example', database='auth.db',
                owner_password_file='owner.hash', redirect_uris=['https://client.example/callback'])))
            args = ['oauth-init-owner', '--oauth-config', str(config)]
            output = StringIO()
            password = 'fixture owner password for CLI test'
            with patch('getpass.getpass', return_value=password), redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(main(args), 0)
                before = (root / 'owner.hash').read_bytes()
                self.assertEqual(main(args), 2)
                self.assertEqual((root / 'owner.hash').read_bytes(), before)
            self.assertNotIn(password, output.getvalue())
            store = GrantStore(root / 'auth.db')
            token = store.issue('client', 'https://monitor.example/mcp', ['monitor:read'])['access_token']
            with redirect_stdout(output):
                self.assertEqual(main(['oauth-revoke-all', '--oauth-config', str(config)]), 0)
            self.assertIsNone(store.access(token))

    def test_password_hash_salted_and_verified(self):
        password = 'fixture password for testing only'
        first = password_hash(password)
        self.assertNotEqual(first, password_hash(password))
        self.assertNotIn(password, first)
        self.assertTrue(verify_password(password, first))
        self.assertFalse(verify_password(password + 'wrong', first))
        self.assertFalse(verify_password(password, 'broken'))
        self.assertFalse(verify_password('x' * 1025, first))
        with self.assertRaises(ValueError):
            password_hash('short')

    def test_reject_unsafe_urls(self):
        for url in ['http://monitor.example', 'https://user@monitor.example',
                    'https://monitor.example/#fragment', 'https://monitor.example:bad',
                    'https://monitor.example\\@evil.example', 'https://monitor.example\n',
                    'https://monitor.example:99999']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                https_url(url)
        self.assertEqual(https_url('https://monitor.example', origin=True), 'https://monitor.example')
        with self.assertRaises(ValueError):
            https_url('https://monitor.example/path', origin=True)

    def test_config_and_private_owner_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'oauth.json'
            config = dict(issuer='https://monitor.example', database='state/auth.db',
                          owner_password_file='owner.hash', redirect_uris=['https://client.example/callback'])
            path.write_text(json.dumps(config))
            parsed = OAuthConfig.load(path)
            self.assertEqual(parsed.database, (root / 'state' / 'auth.db').resolve())
            self.assertEqual(parsed.resource, 'https://monitor.example/mcp')
            encoded = password_hash('fixture password for testing only')
            parsed.owner_password_file.write_text(encoded)
            parsed.owner_password_file.chmod(0o600)
            self.assertEqual(parsed.read_owner_hash(), encoded)
            config['unexpected'] = True
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                OAuthConfig.load(path)
