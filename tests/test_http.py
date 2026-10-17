import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from proxy_monitoring.model import CollectionError
from proxy_monitoring.telemt import collect, fetch


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://example.invalid/metrics')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        body = b'telemt_connections_total 42\ntelemt_uptime_seconds 10\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive())

    def test_actual_http_scrape_ignores_proxy_environment(self):
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:1', 'http_proxy': 'http://127.0.0.1:1'}), \
             patch('proxy_monitoring.telemt.process_epoch', return_value='boot:process'):
            snapshot = collect({'unit': 'test.service', 'metrics_url': self.url + '/metrics'})
        self.assertEqual(snapshot.metrics[0].value, 42)

    def test_redirect_is_not_followed(self):
        with self.assertRaisesRegex(CollectionError, 'metrics_redirect_rejected'):
            fetch(self.url + '/redirect')
