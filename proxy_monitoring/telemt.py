import json
import re
import time
import urllib.request
from decimal import Decimal, InvalidOperation

from .linux import process_epoch, socket_metrics
from .model import CollectionError, Metric, Snapshot

# Explicit allowlist: no arbitrary labels, secrets, endpoints or unbounded metric families.
# Candidate names in preference order; never sum aliases.
DEFINITIONS = (
    (('telemt_connections_total',), 'tcp.accepted_total', 'counter', 'connections', ()),
    (('telemt_user_connections_total',), 'sessions.started_total', 'counter', 'sessions', ('user',)),
    (('telemt_user_connections_current',), 'sessions.active', 'gauge', 'sessions', ('user',)),
    (('telemt_user_octets_from_client_total', 'telemt_user_octets_from_client'), 'traffic.client_upload_bytes_total', 'counter', 'bytes', ('user',)),
    (('telemt_user_octets_to_client_total', 'telemt_user_octets_to_client'), 'traffic.client_download_bytes_total', 'counter', 'bytes', ('user',)),
    (('telemt_connections_bad_total',), 'connections.bad_total', 'counter', 'events', ()),
    (('telemt_handshake_timeouts_total',), 'handshake.timeouts_total', 'counter', 'events', ()),
    (('telemt_upstream_connect_success_total',), 'upstream.connect_success_total', 'counter', 'events', ()),
    (('telemt_upstream_connect_fail_total',), 'upstream.connect_fail_total', 'counter', 'events', ()),
    (('telemt_uptime_seconds',), 'process.uptime_seconds', 'gauge', 'seconds', ()),
)
LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\d+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\[\\"n])*)"(?:,\s*|$)')


def labels(text: str) -> dict:
    result = {}
    pos = 0
    while pos < len(text):
        match = LABEL.match(text, pos)
        if not match or match[1] in result:
            raise CollectionError('invalid_metric_labels')
        result[match[1]] = json.loads('"' + match[2] + '"')
        pos = match.end()
    return result


def parse(text: str) -> tuple[list[Metric], list[str]]:
    accepted = {name for aliases, *_ in DEFINITIONS for name in aliases}
    records = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        match = LINE.fullmatch(line)
        if not match:
            if line.split('{', 1)[0].split(' ', 1)[0] in accepted:
                raise CollectionError('invalid_metric_line')
            continue
        if match[1] not in accepted:
            continue
        if sum(len(v) for v in records.values()) >= 5000:
            raise CollectionError('metric_cardinality_limit')
        records.setdefault(match[1], []).append((labels(match[2] or ''), match[3]))
    metrics, warnings = [], []
    for aliases, name, kind, unit, dimension_keys in DEFINITIONS:
        selected = next((alias for alias in aliases if alias in records), None)
        if selected is None:
            warnings.append('missing:' + name)
            continue
        seen = set()
        for dims, raw in records[selected]:
            if set(dims) != set(dimension_keys):
                warnings.append('unsupported_labels:' + name)
                continue
            if any(len(v) > 128 or any(ord(c) < 32 for c in v) for v in dims.values()):
                raise CollectionError('invalid_metric_labels')
            identity = tuple(sorted(dims.items()))
            if identity in seen:
                raise CollectionError('duplicate_metric')
            seen.add(identity)
            try:
                value = Decimal(raw)
                if not value.is_finite() or value < 0 or value > 2**63 - 1:
                    raise InvalidOperation
                if kind == 'counter' and value != value.to_integral_value():
                    raise InvalidOperation
            except InvalidOperation:
                raise CollectionError('invalid_metric_value') from None
            metrics.append(Metric(name, kind, unit, int(value) if value == value.to_integral_value() else float(value), dims))
    if not metrics:
        raise CollectionError('no_supported_metrics')
    return metrics, warnings


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectionError('metrics_redirect_rejected')


def fetch(url: str) -> str:
    # Ignore workstation/service HTTP_PROXY; analytics must stay on loopback.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 5
    with opener.open(url, timeout=2) as response:
        chunks, total = [], 0
        while True:
            chunk = response.read1(65536)
            if time.monotonic() > deadline:
                raise CollectionError('metrics_timeout')
            if not chunk:
                break
            total += len(chunk)
            if total > 2_000_000:
                raise CollectionError('metrics_response_limit')
            chunks.append(chunk)
    return b''.join(chunks).decode('utf-8')


def collect(source: dict) -> Snapshot:
    before = process_epoch(source['unit'])
    metrics, warnings = parse(fetch(source['metrics_url']))
    after = process_epoch(source['unit'])
    if before != after:
        raise CollectionError('restart_during_scrape')
    try:
        metrics.extend(socket_metrics(source.get('ports', [])))
    except OSError:
        warnings.append('sockets_unavailable')
    return Snapshot(before, metrics, warnings)
