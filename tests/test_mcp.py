import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

import httpx2
import jsonschema
from mcp import Client
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from proxy_monitoring.analytics import utc
from proxy_monitoring.mcp_server import create_server, http_app
from test_analytics import AnalyticsFixture


class MCPTests(AnalyticsFixture, unittest.IsolatedAsyncioTestCase):
    async def test_all_tools_schemas_and_structured_results(self):
        args = {'start': utc(self.a), 'end': utc(self.b), 'target': {'source_ids': ['t']}}
        calls = {
            'list_inventory': {}, 'get_metric_catalog': {}, 'get_collection_health': {}, 'get_current': {},
            'get_summary': args, 'get_timeseries': dict(args, metrics=['sessions.active'], resolution_seconds=15),
            'get_top_consumers': dict(args, group_by='user'), 'get_events': args,
            'get_anomalies': args, 'get_report_context': args,
        }
        async with Client(create_server(self.path)) as client:
            listing = await client.list_tools()
            self.assertEqual(set(calls), {t.name for t in listing.tools})
            for tool in listing.tools:
                with self.subTest(tool=tool.name):
                    self.assertTrue(tool.annotations.read_only_hint)
                    self.assertFalse(tool.annotations.destructive_hint)
                    result = await client.call_tool(tool.name, calls[tool.name])
                    self.assertFalse(result.is_error, result.content)
                    self.assertIsNotNone(result.structured_content)
                    jsonschema.validate(result.structured_content, tool.output_schema)

    async def test_validation_errors_and_no_arbitrary_queries(self):
        async with Client(create_server(self.path)) as client:
            for name, args in [('get_current', {'max_age_seconds': 0}),
                               ('get_current', {'target': {'sql': 'DROP TABLE sources'}}),
                               ('get_summary', {'start': 'yesterday', 'end': 'now'}),
                               ('execute_sql', {'query': 'SELECT * FROM samples'}),
                               ('get_current', {'metrics': ['not.real']})]:
                with self.subTest(name=name, args=args):
                    result = await client.call_tool(name, args)
                    self.assertTrue(result.is_error)
            self.assertGreater(self.db.conn.execute('SELECT count(*) FROM samples').fetchone()[0], 0)

    async def test_missing_database_error_does_not_leak_path(self):
        path = self.root / 'private-path.db'
        async with Client(create_server(path)) as client:
            result = await client.call_tool('list_inventory', {})
            self.assertTrue(result.is_error)
            self.assertNotIn('private-path', str(result))
        self.assertFalse(path.exists())

    async def test_real_stdio_subprocess(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps(self.cfg), encoding='utf-8')
        params = StdioServerParameters(command=sys.executable,
            args=['-m', 'proxy_monitoring', '--config', str(config), 'mcp'],
            cwd=Path(__file__).resolve().parents[1])
        async with Client(params, read_timeout_seconds=10) as client:
            result = await client.call_tool('get_current', {'target': {'source_ids': ['t']}})
            self.assertFalse(result.is_error)
            self.assertEqual(len(result.structured_content['data']), 5)
        # SDK context closes and waits for the child, including Windows process handling.


class HTTPMCPTests(AnalyticsFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.token = secrets.token_urlsafe(32)
        token_file = self.root / 'token'
        token_file.write_text(self.token, encoding='ascii')
        os.chmod(token_file, 0o600)
        config = self.root / 'config.json'
        config.write_text(json.dumps(self.cfg), encoding='utf-8')
        self.stderr = (self.root / 'stderr').open('wb')
        self.process = subprocess.Popen([sys.executable, '-m', 'proxy_monitoring', '--config', str(config),
            'mcp', '--transport', 'streamable-http', '--port', str(self.port), '--token-file', str(token_file)],
            cwd=Path(__file__).resolve().parents[1], stdout=subprocess.DEVNULL, stderr=self.stderr)
        self.url = f'http://127.0.0.1:{self.port}/mcp'
        try:
            async with httpx2.AsyncClient(trust_env=False) as client:
                for _ in range(100):
                    if self.process.poll() is not None:
                        self.fail('MCP HTTP process exited before readiness')
                    try:
                        response = await client.get(self.url, timeout=0.2)
                        if response.status_code == 401:
                            return
                    except httpx2.HTTPError:
                        pass
                    await asyncio.sleep(0.1)
            self.fail('MCP HTTP startup timeout')
        except BaseException:
            self.stop_process()
            raise

    def stop_process(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.stderr.close()
        self.assertIsNotNone(self.process.poll())

    async def asyncTearDown(self):
        self.stop_process()
        self.assertNotIn(self.token, (self.root / 'stderr').read_text(errors='replace'))

    async def test_authenticated_streamable_http_client(self):
        async with httpx2.AsyncClient(headers={'Authorization': 'Bearer ' + self.token}, trust_env=False) as http:
            async with streamable_http_client(self.url, http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listing = await session.list_tools()
                    self.assertEqual(len(listing.tools), 10)
                    result = await session.call_tool('get_summary', {
                        'target': {'source_ids': ['t']}, 'start': utc(self.a), 'end': utc(self.b),
                        'metrics': ['traffic.client_upload_bytes_total']})
                    self.assertFalse(result.is_error)
                    self.assertEqual(result.structured_content['data'][0]['value'], 20)

    async def test_http_auth_origin_host_and_body_limits(self):
        async with httpx2.AsyncClient(trust_env=False) as client:
            for method in ('GET', 'POST', 'DELETE'):
                response = await client.request(method, self.url)
                self.assertEqual(response.status_code, 401)
            headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json, text/event-stream'}
            response = await client.post(self.url, headers=dict(headers, Origin='https://evil.invalid'), json={})
            self.assertEqual(response.status_code, 403)
            response = await client.post(self.url, headers=dict(headers, Host='evil.invalid'), json={})
            self.assertEqual(response.status_code, 421)
            response = await client.post(self.url, headers=dict(headers, **{'Content-Type': 'application/json'}), content=b' ' * 70000)
            self.assertEqual(response.status_code, 413)

    def test_public_bind_and_weak_token_rejected(self):
        server = create_server(self.path)
        with self.assertRaises(ValueError):
            http_app(server, self.token, host='0.0.0.0')
        with self.assertRaises(ValueError):
            http_app(server, 'short')
