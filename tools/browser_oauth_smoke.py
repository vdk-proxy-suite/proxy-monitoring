"""Real browser consent regression using only synthetic, intercepted HTTPS.

Install the optional playwright test dependency and its Chromium browser first.
No production endpoint, owner password, browser profile or live credentials are
used. Requests are routed to the same ASGI application as the HTTP tests.
"""
import argparse
import sys
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]

from playwright.sync_api import sync_playwright
from starlette.testclient import TestClient
from proxy_monitoring.mcp_server import oauth_app
from test_oauth_http import OAuthHTTPTests


def scenario(browser, callback, decision, password_ok=True):
    fixture = OAuthHTTPTests('test_discovery_challenge_and_authenticated_tools')
    fixture.setUp()
    try:
        fixture.config = replace(fixture.config, redirect_uris=(callback,))
        with TestClient(oauth_app(fixture.path, fixture.config), base_url=fixture.config.issuer,
                        follow_redirects=False) as http, browser.new_context() as context:
            fixture.client = http
            registered = http.post('/register', json=dict(client_name='Browser fixture',
                redirect_uris=[callback], token_endpoint_auth_method='none',
                grant_types=['authorization_code', 'refresh_token']))
            assert registered.status_code == 201
            fixture.client_id = registered.json()['client_id']
            start = fixture.authorize().headers['location']
            page = context.new_page()
            observations = {}

            def route(handler):
                request = handler.request
                headers = request.all_headers()
                if not request.url.startswith(fixture.config.issuer + '/'):
                    assert request.url.startswith(callback + '?'), 'unexpected callback'
                    observations['callback'] = parse_qs(urlsplit(request.url).query)
                    observations['callback_referrer'] = headers.get('referer')
                    handler.fulfill(status=200, body='Callback reached')
                    return
                # Do not let TestClient supply a cookie missing from the browser.
                http.cookies.clear()
                response = http.request(request.method, request.url, headers=headers,
                                        content=request.post_data_buffer)
                if request.method == 'POST':
                    observations['origin'] = headers.get('origin')
                    observations['referrer'] = headers.get('referer')
                    observations['cookie'] = 'cookie' in headers
                    observations['status'] = response.status_code
                    observations['redirect_policy'] = response.headers.get('referrer-policy')
                handler.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)

            page.route('**/*', route)
            page.goto(start)
            page.locator('input[name=password]').fill(fixture.password if password_ok else 'wrong fixture password')
            page.locator(f'button[value={decision}]').click()
            if password_ok or decision == 'deny':
                page.wait_for_url(lambda url: str(url).startswith(callback + '?'), wait_until='domcontentloaded')
                assert page.locator('body').inner_text() == 'Callback reached'
                result = observations['callback']
                assert result['iss'] == [fixture.config.issuer]
                assert result['state'] == ['fixture state']
                assert observations['callback_referrer'] is None, 'callback leaked referrer'
                assert observations['status'] == 200
                if decision == 'approve':
                    tokens = fixture.exchange(result['code'][0])
                    assert tokens.status_code == 200
                    assert fixture.rpc(tokens.json()['access_token'], 'tools/list').status_code == 200
                else:
                    assert result['error'] == ['access_denied'] and 'code' not in result
            else:
                page.wait_for_url(fixture.config.issuer + '/login', wait_until='domcontentloaded')
                assert observations['status'] == 403
                assert 'authentication_failed_restart_authorization' in page.locator('body').inner_text()
                assert 'callback' not in observations
            assert observations['origin'] == fixture.config.issuer, 'browser sent an unusable Origin'
            assert observations['referrer'] == fixture.config.issuer + '/', 'login URL leaked in Referer'
            assert observations['cookie']
            assert observations['redirect_policy'] == 'no-referrer'
    finally:
        fixture.tearDown()
        fixture.doCleanups()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--channel', default=None)
    args = parser.parse_args()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel=args.channel)
        try:
            for callback, decision, password_ok in [
                    ('https://client.example/callback', 'approve', True),
                    ('http://127.0.0.1:54321/callback', 'approve', True),
                    ('http://[::1]:54321/callback', 'approve', True),
                    ('http://127.0.0.1:54321/callback', 'deny', True),
                    ('https://client.example/callback', 'approve', False)]:
                scenario(browser, callback, decision, password_ok)
                print('Browser OAuth scenario passed:', decision, 'correct password' if password_ok else 'wrong password', flush=True)
        finally:
            browser.close()
    print('Browser contexts/process closed; fixture databases removed')


if __name__ == '__main__':
    main()
