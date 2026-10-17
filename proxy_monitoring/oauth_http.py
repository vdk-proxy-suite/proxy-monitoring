"""Single-owner OAuth authorization server for a read-only MCP resource.

Public clients use Authorization Code + S256 PKCE. Redirect URIs must be
allowlisted by the operator; registering a client never authorizes it.
"""
import asyncio
import html
import json
import re
import secrets
import sqlite3
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mcp.server.auth.provider import AccessToken
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .oauth_config import verify_password, redirect_allowed
from .oauth_store import GrantStore

SCOPES = ['monitor:read', 'offline_access']
TOKEN_PATTERN = re.compile(r'[A-Za-z0-9_-]{43}')


def error(code, status=400):
    return JSONResponse({'error': code}, status_code=status)


def parameters(raw):
    pairs = parse_qsl(raw, keep_blank_values=True, max_num_fields=30, strict_parsing=True)
    if len({key for key, value in pairs}) != len(pairs):
        raise ValueError('duplicate_parameter')
    return dict(pairs)


class OAuthHTTP:
    def __init__(self, config, store=None):
        self.config = config
        self.store = store or GrantStore(config.database)
        self.owner_hash = config.read_owner_hash()

    async def verify_token(self, token):
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        data = self.store.access(token)
        if not data or data['resource'] != self.config.resource:
            return None
        return AccessToken(token=token, subject='owner', **data)

    def routes(self):
        routes = [Route('/.well-known/oauth-authorization-server', self.metadata, methods=['GET']),
                Route('/register', self.register, methods=['POST']),
                Route('/authorize', self.authorize, methods=['GET']),
                Route('/login', self.login, methods=['GET', 'POST']),
                Route('/token', self.token, methods=['POST']),
                Route('/revoke', self.revoke, methods=['POST'])]
        # Catch errors inside Starlette's exception middleware, before a 500
        # response can be sent. Never echo submitted passwords or token forms.
        from starlette.routing import request_response
        for route in routes:
            endpoint = route.endpoint

            async def guarded(request, endpoint=endpoint):
                try:
                    return await endpoint(request)
                except (ValueError, UnicodeError, TypeError):
                    return error('invalid_request')
                except (sqlite3.Error, OSError):
                    return error('temporarily_unavailable', 503)
            route.app = request_response(guarded)
        return routes

    async def metadata(self, request):
        issuer = self.config.issuer
        return JSONResponse(dict(issuer=issuer, authorization_endpoint=issuer + '/authorize',
            token_endpoint=issuer + '/token', registration_endpoint=issuer + '/register',
            revocation_endpoint=issuer + '/revoke', scopes_supported=SCOPES,
            response_types_supported=['code'], grant_types_supported=['authorization_code', 'refresh_token'],
            token_endpoint_auth_methods_supported=['none'], revocation_endpoint_auth_methods_supported=['none'],
            code_challenge_methods_supported=['S256'], authorization_response_iss_parameter_supported=True))

    async def resource_metadata(self, request):
        return JSONResponse(dict(resource=self.config.resource, authorization_servers=[self.config.issuer],
                                 scopes_supported=SCOPES, bearer_methods_supported=['header']))

    async def form(self, request):
        if request.headers.get('content-type', '').split(';')[0] != 'application/x-www-form-urlencoded':
            raise ValueError('form_required')
        return parameters((await request.body()).decode('utf-8'))

    async def register(self, request):
        if not self.store.allow('registration', 20, 3600):
            return error('temporarily_unavailable', 429)
        raw = json.loads(await request.body())
        if not isinstance(raw, dict):
            return error('invalid_client_metadata')
        redirects = raw.get('redirect_uris')
        if (not isinstance(redirects, list) or not 1 <= len(redirects) <= 20
                or any(not redirect_allowed(uri, self.config.redirect_uris) for uri in redirects)):
            return error('invalid_redirect_uri')
        if raw.get('token_endpoint_auth_method', 'none') != 'none':
            return error('invalid_client_metadata')
        grants = raw.get('grant_types', ['authorization_code'])
        if (not isinstance(grants, list) or 'authorization_code' not in grants
                or any(grant not in ['authorization_code', 'refresh_token'] for grant in grants)
                or raw.get('response_types', ['code']) != ['code']):
            return error('invalid_client_metadata')
        name = raw.get('client_name', 'MCP client')
        scope = raw.get('scope', 'monitor:read offline_access')
        if (not isinstance(name, str) or not 1 <= len(name) <= 100 or any(ord(c) < 32 for c in name)
                or not isinstance(scope, str) or not set(scope.split()).issubset(SCOPES)
                or 'monitor:read' not in scope.split()):
            return error('invalid_client_metadata')
        metadata = dict(redirect_uris=redirects, token_endpoint_auth_method='none', grant_types=grants,
                        response_types=['code'], client_name=name, scope=' '.join(sorted(set(scope.split()))))
        client = self.store.register_client(metadata)
        if not client:
            return error('temporarily_unavailable', 503)
        return JSONResponse(dict(metadata, client_id=client, client_id_issued_at=int(self.store.clock())), status_code=201)

    def redirect(self, payload, **values):
        uri = urlsplit(payload['redirect_uri'])
        query = list(parse_qsl(uri.query, keep_blank_values=True))
        query.extend(values.items())
        query.append(('iss', self.config.issuer))
        if 'state' in payload:
            query.append(('state', payload['state']))
        return RedirectResponse(urlunsplit((uri.scheme, uri.netloc, uri.path, urlencode(query), '')), status_code=302)

    async def authorize(self, request):
        if not self.store.allow('authorize', 60, 60):
            return error('temporarily_unavailable', 429)
        self.store.prune()
        data = parameters(request.url.query)
        client = self.store.client(data.get('client_id', ''))
        if (not client or not redirect_allowed(data.get('redirect_uri'), client['redirect_uris'])
                or not redirect_allowed(data.get('redirect_uri'), self.config.redirect_uris)):
            return error('invalid_request')
        if data.get('response_type') != 'code':
            return self.redirect(data, error='unsupported_response_type')
        if data.get('resource') != self.config.resource:
            return self.redirect(data, error='invalid_target')
        if data.get('code_challenge_method') != 'S256' or not TOKEN_PATTERN.fullmatch(data.get('code_challenge', '')):
            return self.redirect(data, error='invalid_request')
        scopes = data.get('scope', client['scope']).split()
        if 'monitor:read' not in scopes or not set(scopes).issubset(client['scope'].split()):
            return self.redirect(data, error='invalid_scope')
        if 'offline_access' in scopes and 'refresh_token' not in client['grant_types']:
            scopes.remove('offline_access')
        data['scopes'] = sorted(set(scopes))
        data['client_name'] = client['client_name']
        pending = self.store.pending(data)
        if not pending:
            return error('temporarily_unavailable', 503)
        return RedirectResponse(self.config.issuer + '/login?request=' + pending, status_code=302)

    async def login(self, request):
        if request.method == 'GET':
            params = parameters(request.url.query)
            pending = params.get('request', '')
            if not TOKEN_PATTERN.fullmatch(pending):
                return error('invalid_request')
            browser = secrets.token_urlsafe(32)
            data = self.store.bind_pending(pending, browser)
            if not data:
                return error('invalid_or_expired_request')
            name = html.escape(data['client_name'])
            callback = html.escape(data['redirect_uri'])
            body = ('<!doctype html><html lang="en"><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width, initial-scale=1">'
                    '<title>Proxy monitoring — authorize access</title><body>'
                    '<h1>Authorize read-only monitoring access</h1>'
                    f'<p>Client: <strong>{name}</strong> (client-supplied name)</p>'
                    f'<p>Return address: <code>{callback}</code></p>'
                    '<p>This client can read all collected proxy telemetry, including user labels and traffic. '
                    'It cannot change proxy settings.</p>'
                    + ('<p>Access can be renewed for up to 30 days until revoked.</p>'
                       if 'offline_access' in data['scopes'] else '<p>Access expires after 10 minutes.</p>') +
                    '<form method="post" action="/login">'
                    f'<input type="hidden" name="request" value="{pending}">'
                    f'<input type="hidden" name="csrf" value="{browser}">'
                    '<label>Owner password <input type="password" name="password" '
                    'autocomplete="current-password" maxlength="1024" required></label>'
                    '<button name="decision" value="approve">Authorize</button>'
                    '<button name="decision" value="deny" formnovalidate>Deny</button></form></body></html>')
            response = HTMLResponse(body)
            response.set_cookie('__Host-proxy-oauth', browser, max_age=300, secure=True, httponly=True,
                                samesite='lax', path='/')
            return response
        if request.headers.get('origin') != self.config.issuer:
            return error('invalid_request', 403)
        data = await self.form(request)
        pending, csrf = data.get('request', ''), data.get('csrf', '')
        cookie = request.cookies.get('__Host-proxy-oauth', '')
        if (not TOKEN_PATTERN.fullmatch(pending) or not TOKEN_PATTERN.fullmatch(csrf)
                or not secrets.compare_digest(csrf, cookie)):
            return error('invalid_request', 403)
        if not self.store.allow('login', 10, 300):
            return error('temporarily_unavailable', 429)
        if data.get('decision') == 'deny':
            payload = self.store.consume_pending(pending, cookie)
            if not payload:
                return error('invalid_or_expired_request')
            response = self.redirect(payload, error='access_denied')
        elif (data.get('decision') == 'approve'
              and await asyncio.to_thread(verify_password, data.get('password', ''), self.owner_hash)):
            approved = self.store.approve_pending(pending, cookie)
            if not approved:
                return error('invalid_or_expired_request')
            payload, code = approved
            response = self.redirect(payload, code=code)
        else:
            self.store.consume_pending(pending, cookie)
            response = error('authentication_failed_restart_authorization', 403)
        response.delete_cookie('__Host-proxy-oauth', path='/', secure=True, httponly=True, samesite='lax')
        return response

    async def token(self, request):
        if not self.store.allow('token', 120, 60):
            return error('temporarily_unavailable', 429)
        data = await self.form(request)
        client_id = data.get('client_id', '')
        client = self.store.client(client_id)
        if not client or 'authorization' in request.headers or data.get('client_secret'):
            return error('invalid_client', 401)
        if data.get('resource') != self.config.resource:
            return error('invalid_target')
        grant_type = data.get('grant_type')
        if grant_type not in client['grant_types']:
            return error('unauthorized_client')
        if grant_type == 'authorization_code':
            result = self.store.exchange_code(data.get('code', ''), client_id, data['resource'],
                                              data.get('redirect_uri', ''), data.get('code_verifier', ''))
        elif grant_type == 'refresh_token':
            result = self.store.rotate(data.get('refresh_token', ''), client_id, data['resource'],
                                       data['scope'].split() if 'scope' in data else None)
        else:
            return error('unsupported_grant_type')
        return JSONResponse(result) if result else error('invalid_grant')

    async def revoke(self, request):
        if not self.store.allow('revoke', 120, 60):
            return error('temporarily_unavailable', 429)
        data = await self.form(request)
        client_id = data.get('client_id', '')
        if not self.store.client(client_id) or 'authorization' in request.headers or data.get('client_secret'):
            return error('invalid_client', 401)
        self.store.revoke(data.get('token', ''), client_id)
        return Response(status_code=200)


class OAuthBoundary:
    """Bound request bodies and sanitize OAuth errors before SDK/resource routing."""
    def __init__(self, app, hosts, origin):
        self.app, self.hosts, self.origin = app, set(hosts), origin

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = scope.get('headers', [])
        hosts = [value.decode('latin1') for key, value in headers if key.lower() == b'host']
        if len(hosts) != 1 or hosts[0] not in self.hosts:
            return await error('invalid_host', 421)(scope, receive, send)
        for name in (b'authorization', b'origin', b'content-type'):
            if sum(key.lower() == name for key, value in headers) > 1:
                return await error('invalid_request')(scope, receive, send)
        if len(scope.get('query_string', b'')) > 8192:
            return await error('request_too_large', 413)(scope, receive, send)
        parts, size = [], 0
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=10)
            except TimeoutError:
                return await error('request_timeout', 408)(scope, receive, send)
            if message['type'] == 'http.disconnect':
                return
            chunk = message.get('body', b'')
            size += len(chunk)
            if size > 65536:
                return await error('request_too_large', 413)(scope, receive, send)
            parts.append(chunk)
            if not message.get('more_body'):
                break
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {'type': 'http.request', 'body': b''.join(parts), 'more_body': False}
            return await receive()

        async def secure_send(message):
            if message['type'] == 'http.response.start':
                message['headers'] = list(message.get('headers', [])) + [
                    (b'cache-control', b'no-store'), (b'pragma', b'no-cache'),
                    (b'referrer-policy', b'no-referrer'), (b'x-content-type-options', b'nosniff'),
                    (b'x-frame-options', b'DENY'),
                    (b'content-security-policy', b"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")]
            await send(message)

        await self.app(scope, replay, secure_send)
