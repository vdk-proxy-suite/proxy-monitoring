import base64
import hashlib
import re
import asyncio
import json
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from starlette.testclient import TestClient
import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientMetadata, AuthorizationCodeResult

from proxy_monitoring.mcp_server import oauth_app
from proxy_monitoring.oauth_config import OAuthConfig, password_hash
from proxy_monitoring.oauth_store import GrantStore
from test_analytics import AnalyticsFixture


class OAuthHTTPTests(AnalyticsFixture):
    def setUp(self):
        super().setUp()
        self.password = 'fixture owner password not for deployment'
        owner = self.root / 'owner.hash'
        owner.write_text(password_hash(self.password))
        owner.chmod(0o600)
        self.config = OAuthConfig('https://monitor.example', self.root / 'auth.db', owner,
                                  ('https://client.example/callback',))
        self.client = self.enterContext(TestClient(oauth_app(self.path, self.config),
                                                   base_url=self.config.issuer, follow_redirects=False))
        response = self.client.post('/register', json=dict(client_name='Fixture <client>',
            redirect_uris=list(self.config.redirect_uris), token_endpoint_auth_method='none',
            grant_types=['authorization_code', 'refresh_token'], response_types=['code']))
        self.assertEqual(response.status_code, 201, response.text)
        self.client_id = response.json()['client_id']
        self.verifier = 'v' * 43
        self.challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b'=').decode()

    def authorize(self, **overrides):
        params = dict(client_id=self.client_id, redirect_uri=self.config.redirect_uris[0], response_type='code',
                      code_challenge=self.challenge, code_challenge_method='S256', resource=self.config.resource,
                      scope='monitor:read offline_access', state='fixture state')
        params.update(overrides)
        return self.client.get('/authorize', params=params)

    def consent(self, **overrides):
        response = self.authorize()
        self.assertEqual(response.status_code, 302, response.text)
        response = self.client.get(response.headers['location'])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn('Fixture &lt;client&gt;', response.text)
        self.assertIn('HttpOnly', response.headers['set-cookie'])
        self.assertIn('Secure', response.headers['set-cookie'])
        data = {name: re.search(f'name="{name}" value="([^"]+)"', response.text)[1] for name in ['request', 'csrf']}
        data.update(password=self.password, decision='approve')
        data.update(overrides)
        return self.client.post('/login', data=data, headers={'Origin': self.config.issuer})

    def exchange(self, code, **overrides):
        data = dict(grant_type='authorization_code', client_id=self.client_id, code=code,
                    redirect_uri=self.config.redirect_uris[0], code_verifier=self.verifier, resource=self.config.resource)
        data.update(overrides)
        return self.client.post('/token', data=data)

    def tokens(self):
        response = self.consent()
        self.assertEqual(response.status_code, 302, response.text)
        args = parse_qs(urlsplit(response.headers['location']).query)
        self.assertEqual(args['state'], ['fixture state'])
        self.assertEqual(args['iss'], [self.config.issuer])
        response = self.exchange(args['code'][0])
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def rpc(self, token, method, params=None):
        return self.client.post('/mcp', headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/json, text/event-stream'}, json=dict(jsonrpc='2.0', id=1,
                                                                    method=method, params=params or {}))

    def test_discovery_challenge_and_authenticated_tools(self):
        response = self.client.get('/mcp')
        self.assertEqual(response.status_code, 401)
        self.assertIn('/.well-known/oauth-protected-resource/mcp', response.headers['www-authenticate'])
        resource = self.client.get('/.well-known/oauth-protected-resource/mcp').json()
        self.assertEqual(resource['resource'], self.config.resource)
        discovery = self.client.get('/.well-known/oauth-authorization-server').json()
        self.assertEqual(discovery['code_challenge_methods_supported'], ['S256'])
        self.assertEqual(discovery['token_endpoint_auth_methods_supported'], ['none'])
        token = self.tokens()['access_token']
        response = self.rpc(token, 'tools/list')
        self.assertEqual(response.status_code, 200, response.text)
        tools = response.json()['result']['tools']
        self.assertEqual(len(tools), 10)
        self.assertEqual(tools[0]['_meta']['securitySchemes'][0]['scopes'], ['monitor:read'])
        response = self.rpc(token, 'tools/call', dict(name='list_inventory', arguments={}))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()['result'].get('isError', False))

    def test_code_replay_pkce_and_resource(self):
        response = self.consent()
        code = parse_qs(urlsplit(response.headers['location']).query)['code'][0]
        self.assertEqual(self.exchange(code, resource='https://other.example/mcp').json()['error'], 'invalid_target')
        self.assertEqual(self.exchange(code, code_verifier='w' * 43).json()['error'], 'invalid_grant')
        self.assertEqual(self.exchange(code).status_code, 200)
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')

    def test_refresh_reuse_and_revoke(self):
        tokens = self.tokens()
        data = dict(grant_type='refresh_token', client_id=self.client_id, resource=self.config.resource,
                    refresh_token=tokens['refresh_token'])
        response = self.client.post('/token', data=data)
        self.assertEqual(response.status_code, 200, response.text)
        replacement = response.json()
        self.assertEqual(self.rpc(replacement['access_token'], 'tools/list').status_code, 200)
        self.assertEqual(self.client.post('/token', data=data).status_code, 400)
        self.assertEqual(self.rpc(replacement['access_token'], 'tools/list').status_code, 401)
        tokens = self.tokens()
        response = self.client.post('/revoke', data=dict(client_id=self.client_id, token=tokens['refresh_token']))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.rpc(tokens['access_token'], 'tools/list').status_code, 401)

    def test_redirect_and_scope_attacks(self):
        self.assertEqual(self.authorize(redirect_uri='https://evil.example').status_code, 400)
        for override in [dict(scope='write'), dict(code_challenge_method='plain'), dict(resource='https://evil.example')]:
            response = self.authorize(**override)
            args = parse_qs(urlsplit(response.headers['location']).query)
            self.assertIn('error', args)
            self.assertEqual(args['iss'], [self.config.issuer])
        response = self.client.post('/register', json={'redirect_uris': ['https://evil.example']})
        self.assertEqual(response.json()['error'], 'invalid_redirect_uri')

    def test_login_denial_wrong_password_csrf_and_limits(self):
        response = self.consent(decision='deny')
        self.assertIn('error=access_denied', response.headers['location'])
        self.assertEqual(self.consent(password='wrong').status_code, 403)
        self.assertEqual(self.consent(csrf='x' * 43).status_code, 403)
        for _ in range(8):
            self.consent(password='wrong')
        self.assertEqual(self.consent().status_code, 429)

    def test_malformed_requests_host_body_and_cache(self):
        response = self.client.post('/token', content='client_id=a&client_id=b',
                                    headers={'content-type': 'application/x-www-form-urlencoded'})
        self.assertEqual(response.status_code, 400)
        response = self.client.post('/register', content='{bad json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('no-store', response.headers['cache-control'])
        self.assertEqual(self.client.get('/authorize', headers={'host': 'evil.example'}).status_code, 421)
        self.assertEqual(self.client.post('/register', content=b'x' * 65537).status_code, 413)

    def test_scope_audience_expiry_and_cross_origin_login_rejected(self):
        store = GrantStore(self.config.database)
        wrong_scope = store.issue(self.client_id, self.config.resource, ['offline_access'])
        self.assertEqual(self.rpc(wrong_scope['access_token'], 'tools/list').status_code, 403)
        wrong_resource = store.issue(self.client_id, 'https://other.example/mcp', ['monitor:read'])
        self.assertEqual(self.rpc(wrong_resource['access_token'], 'tools/list').status_code, 401)
        store.clock = lambda: 1000
        expired = store.issue(self.client_id, self.config.resource, ['monitor:read'])
        self.assertEqual(self.rpc(expired['access_token'], 'tools/list').status_code, 401)
        response = self.client.post('/login', data={'password': self.password}, headers={'Origin': 'https://evil.example'})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(self.password, response.text)

    def test_real_cli_process_accepts_persisted_oauth_token(self):
        tokens = self.tokens()
        config = self.root / 'collector.json'
        config.write_text(json.dumps(self.cfg))
        oauth_config = self.root / 'oauth.json'
        oauth_config.write_text(json.dumps(dict(issuer=self.config.issuer, database=str(self.config.database),
            owner_password_file=str(self.config.owner_password_file), redirect_uris=list(self.config.redirect_uris))))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        stderr_path = self.root / 'oauth-stderr'
        with stderr_path.open('wb') as stderr:
            process = subprocess.Popen([sys.executable, '-m', 'proxy_monitoring', '--config', str(config),
                'mcp', '--transport', 'streamable-http', '--oauth-config', str(oauth_config), '--port', str(port)],
                cwd=Path(__file__).resolve().parents[1], stdout=subprocess.DEVNULL, stderr=stderr)
            try:
                async def exercise():
                    url = f'http://127.0.0.1:{port}/mcp'
                    async with httpx2.AsyncClient(trust_env=False) as http:
                        for _ in range(100):
                            self.assertIsNone(process.poll(), 'OAuth CLI exited before readiness')
                            try:
                                response = await http.get(url, timeout=0.2)
                                if response.status_code == 401:
                                    break
                            except httpx2.HTTPError:
                                pass
                            await asyncio.sleep(0.1)
                        else:
                            self.fail('OAuth CLI readiness timeout')
                    async with httpx2.AsyncClient(trust_env=False,
                        headers={'Authorization': 'Bearer ' + tokens['access_token']}) as http:
                        async with streamable_http_client(url, http_client=http) as (read, write):
                            async with ClientSession(read, write) as session:
                                await session.initialize()
                                tools = await session.list_tools()
                                self.assertEqual(len(tools.tools), 10)
                                result = await session.call_tool('list_inventory', {})
                                self.assertFalse(result.is_error)
                asyncio.run(exercise())
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                self.assertIsNotNone(process.poll())
        logs = stderr_path.read_text(errors='replace')
        for secret in [self.password, tokens['access_token'], tokens['refresh_token']]:
            self.assertNotIn(secret, logs)

    def test_official_sdk_drives_discovery_registration_pkce_and_issuer_validation(self):
        browser = self.client
        password = self.password

        class Storage:
            tokens = None
            info = None

            async def get_tokens(self):
                return self.tokens

            async def set_tokens(self, value):
                self.tokens = value

            async def get_client_info(self):
                return self.info

            async def set_client_info(self, value):
                self.info = value

        class Transport(httpx2.AsyncBaseTransport):
            async def handle_async_request(self, request):
                body = await request.aread()
                response = await asyncio.to_thread(browser.request, request.method, str(request.url),
                    headers=dict(request.headers), content=body)
                return httpx2.Response(response.status_code, headers=dict(response.headers),
                                       content=response.content, request=request)

        storage = Storage()
        callback = {}

        async def redirect(url):
            response = browser.get(url)
            self.assertEqual(response.status_code, 302, response.text)
            page = browser.get(response.headers['location'])
            data = {name: re.search(f'name="{name}" value="([^"]+)"', page.text)[1] for name in ['request', 'csrf']}
            response = browser.post('/login', data=dict(data, password=password, decision='approve'),
                                    headers={'Origin': self.config.issuer})
            self.assertEqual(response.status_code, 302, response.text)
            callback.update({key: value[0] for key, value in parse_qs(urlsplit(response.headers['location']).query).items()})

        async def result():
            return AuthorizationCodeResult(**callback)

        async def exercise():
            auth = OAuthClientProvider(self.config.resource, OAuthClientMetadata(
                redirect_uris=list(self.config.redirect_uris), token_endpoint_auth_method='none',
                grant_types=['authorization_code', 'refresh_token'], response_types=['code'],
                scope='monitor:read offline_access'), storage, redirect, result)
            async with httpx2.AsyncClient(transport=Transport(), auth=auth, trust_env=False) as http:
                response = await http.post(self.config.resource,
                    headers={'Accept': 'application/json, text/event-stream'},
                    json=dict(jsonrpc='2.0', id=1, method='tools/list', params={}))
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(len(response.json()['result']['tools']), 10)
            self.assertIsNotNone(storage.tokens.refresh_token)
            self.assertEqual(storage.info.token_endpoint_auth_method, 'none')
        asyncio.run(exercise())
