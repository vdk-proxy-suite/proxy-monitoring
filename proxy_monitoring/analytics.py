"""Bounded, snapshot-consistent, read-only analytics for MCP and other interfaces."""
import base64
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path


class QueryError(Exception):
    """Messages are public machine codes, never database paths or SQL."""


LOG_METRICS = {
    'log.events': ('events', None),
    'log.error_events': ('events', 'result_code'),
    'log.upload_bytes': ('bytes', 'bytes_up'),
    'log.download_bytes': ('bytes', 'bytes_down'),
}


def utc(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def parse_window(start: str, end: str):
    try:
        dates = [datetime.fromisoformat(s.replace('Z', '+00:00')) for s in (start, end)]
        if any(d.tzinfo is None for d in dates):
            raise ValueError
        a, b = [int(d.timestamp() * 1000) for d in dates]
        if a < 0 or not 0 < b - a <= 31 * 86_400_000:
            raise ValueError
        return a, b
    except (TypeError, ValueError, OverflowError):
        raise QueryError('invalid_window_max_31_days') from None


class Analytics:
    def __init__(self, path: Path, now=None):
        self.now = int(time.time() * 1000) if now is None else now
        self.deadline = time.monotonic() + 4
        self.remaining = 50_000
        self.conn = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=1)
        try:
            self.conn.row_factory = sqlite3.Row
            self.conn.execute('PRAGMA query_only=ON')
            self.conn.set_progress_handler(lambda: int(time.monotonic() > self.deadline), 1000)
            self.conn.execute('BEGIN')
            if self.conn.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise QueryError('unsupported_schema')
        except BaseException:
            self.conn.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.conn.close()

    def rows(self, sql, args=()):
        if time.monotonic() > self.deadline:
            raise QueryError('query_timeout')
        rows = self.conn.execute(sql, args).fetchmany(self.remaining + 1)
        self.remaining -= len(rows)
        if self.remaining < 0:
            raise QueryError('query_too_large_narrow_window_or_target')
        return [dict(row) for row in rows]

    def sources(self, target):
        conditions, args = ['1=1'], []
        for key, column in [('host_id', 'host_id'), ('kind', 'kind')]:
            if target.get(key) is not None:
                conditions.append(column + '=?')
                args.append(target[key])
        for key, column in [('source_ids', 'id'), ('instance_ids', 'instance')]:
            values = target.get(key, [])
            if values:
                conditions.append(column + ' IN (' + ','.join('?' for _ in values) + ')')
                args.extend(values)
        if not target.get('include_disabled', False):
            conditions.append('enabled=1')
        result = self.rows('SELECT id,host_id,kind,instance,unit,poll_ms,enabled FROM sources WHERE '
                           + ' AND '.join(conditions) + ' ORDER BY id', args)
        if not result:
            raise QueryError('target_not_found')
        if target.get('source_ids') and set(target['source_ids']) != {s['id'] for s in result}:
            raise QueryError('target_not_found')
        if target.get('instance_ids') and set(target['instance_ids']) != {s['instance'] for s in result}:
            raise QueryError('target_not_found')
        if len(result) > 100:
            raise QueryError('too_many_sources')
        if target.get('user') is not None and any(s['kind'] == '3proxy' for s in result):
            raise QueryError('3proxy_user_dimension_not_collected')
        return result

    @staticmethod
    def placeholders(sources):
        return ','.join('?' for _ in sources), [s['id'] for s in sources]

    def selected_series(self, target, metrics=None):
        sources = self.sources(target)
        marks, ids = self.placeholders(sources)
        series = self.rows(f'SELECT * FROM series WHERE source_id IN ({marks}) ORDER BY id', ids)
        selected = []
        for row in series:
            row['dimensions'] = json.loads(row['dimensions'])
            if target.get('user') is not None and row['dimensions'].get('user') != target['user']:
                continue
            if target.get('port') is not None and row['dimensions'].get('port') != str(target['port']):
                continue
            if not metrics or row['name'] in metrics:
                selected.append(row)
        for src in sources:
            if src['kind'] != '3proxy':
                continue
            ports = self.rows('SELECT DISTINCT port FROM log_records WHERE source_id=? ORDER BY port', (src['id'],))
            for port in ports:
                if target.get('port') is not None and target['port'] != port['port']:
                    continue
                for name, (unit, _) in LOG_METRICS.items():
                    if not metrics or name in metrics:
                        selected.append(dict(id=f"log:{src['id']}:{port['port']}:{name}", source_id=src['id'],
                                             name=name, kind='log', unit=unit, dimensions={'port': str(port['port'])}))
        if len(selected) > 200:
            raise QueryError('too_many_series_narrow_target')
        if metrics and set(metrics) - {s['name'] for s in selected}:
            raise QueryError('metric_not_available_for_target')
        return sources, selected

    def inventory(self, target):
        sources, series = self.selected_series(target)
        return [dict(src, available_series=[s for s in series if s['source_id'] == src['id']],
                     capabilities={'routes': False, 'listener_inventory': False,
                                   'history': True, 'anomaly_lifecycle': False}) for src in sources]

    def catalog(self, target):
        _, series = self.selected_series(target)
        unique = {}
        for s in series:
            unique[s['name']] = dict(name=s['name'], unit=s['unit'], kind=s['kind'],
                                    time_basis='log_event_time' if s['kind'] == 'log' else 'observation_time',
                                    aggregation='per_source_and_dimensions_only',
                                    note='Log records are not sessions' if s['kind'] == 'log' else
                                    'Counters need intervals; gauges use sample_mean, not time-weighted mean')
        return list(unique.values())

    def health(self, target):
        sources = self.sources(target)
        result = []
        for source in sources:
            last = self.rows('SELECT id,finished_at,status,error_code,warnings FROM runs WHERE source_id=? ORDER BY id DESC LIMIT 1',
                             (source['id'],))
            row = last[0] if last else dict(id=None, finished_at=None, status='unknown', error_code=None, warnings='[]')
            age = None if row['finished_at'] is None else self.now - row['finished_at']
            result.append(dict(source_id=source['id'], **row, age_ms=age,
                               stale=age is None or age < 0 or age > source['poll_ms'] * 3))
            result[-1]['warnings'] = json.loads(row['warnings'])
        return result

    def current(self, target, metrics=None, max_age_seconds=30):
        _, series = self.selected_series(target, metrics)
        health = {r['source_id']: r for r in self.health(target)}
        result = []
        for s in series:
            if s['kind'] == 'log':
                result.append(dict(s, value=None, observed_at=None, age_ms=None, quality='not_a_live_metric'))
                continue
            rows = self.rows('SELECT * FROM samples WHERE series_id=? ORDER BY run_id DESC LIMIT 1', (s['id'],))
            row = rows[0] if rows else None
            age = self.now - row['observed_at'] if row else None
            quality = ('missing' if row is None else 'stale' if age < 0 or age > max_age_seconds * 1000 else
                       'not_observed_in_latest_run' if row['run_id'] != health[s['source_id']]['id'] else 'ok')
            value = None if row is None else row['value_integer'] if row['value_integer'] is not None else row['value_real']
            result.append(dict(s, value=value, observed_at=utc(row['observed_at']) if row else None,
                               age_ms=age, quality=quality, source_status=health[s['source_id']]['status']))
        return result

    def observations(self, s, a, b):
        if s['kind'] == 'counter':
            return self.rows('''SELECT start_at,end_at,delta,quality FROM intervals WHERE series_id=?
                AND ((end_at>? AND start_at<?) OR (end_at>=? AND end_at<?)) ORDER BY start_at,end_at''', (s['id'], a, b, a, b))
        if s['kind'] == 'gauge':
            return self.rows('SELECT observed_at,value_integer,value_real FROM samples WHERE series_id=? AND observed_at>=? AND observed_at<? ORDER BY observed_at',
                             (s['id'], a, b))
        return self.rows('''SELECT event_at,bytes_up,bytes_down,result_code,quality FROM log_records
            WHERE source_id=? AND port=? AND event_at>=? AND event_at<? ORDER BY event_at''',
                         (s['source_id'], int(s['dimensions']['port']), a, b))

    @staticmethod
    def aggregate(s, rows, a, b):
        warnings = set()
        if s['kind'] == 'counter':
            total, valid, covered, last_end = 0, 0, 0, None
            for r in rows:
                if r['end_at'] <= a or r['start_at'] >= b:
                    continue
                if r['quality'] not in {'ok', 'gap'} or r['end_at'] <= r['start_at']:
                    warnings.add(r['quality'])
                    continue
                if r['start_at'] < a or r['end_at'] > b:
                    warnings.add('boundary_interval_excluded')
                    continue
                if last_end is not None and r['start_at'] < last_end:
                    warnings.add('overlapping_intervals')
                last_end = max(last_end or r['end_at'], r['end_at'])
                total += r['delta']
                valid += 1
                if r['quality'] == 'ok':
                    covered += r['end_at'] - r['start_at']
                else:
                    warnings.add('gap')
            overlap = 'overlapping_intervals' in warnings
            covered = 0 if overlap else min(covered, b - a)
            if covered < b - a:
                warnings.add('incomplete_coverage')
            value = total if valid and not overlap else None
            return dict(value=value, aggregation='observed_delta', covered_ms=covered,
                        coverage_ratio=covered / (b - a), valid_intervals=valid,
                        rate_per_second=value * 1000 / (b - a) if value is not None and not warnings else None,
                        warnings=sorted(warnings))
        if s['kind'] == 'gauge':
            values = [r['value_integer'] if r['value_integer'] is not None else r['value_real']
                      for r in rows if a <= r['observed_at'] < b]
            return dict(value=sum(values) / len(values) if values else None, aggregation='sample_mean',
                        min=min(values) if values else None, max=max(values) if values else None,
                        last=values[-1] if values else None, sample_count=len(values), coverage_ratio=None,
                        warnings=['sampled_not_continuous'] if values else ['no_observations'])
        rows = [r for r in rows if a <= r['event_at'] < b]
        field = LOG_METRICS[s['name']][1]
        if not rows:
            value = None
            warnings.add('no_log_records_unknown_coverage')
        elif field is None:
            value = len(rows)
        elif field == 'result_code':
            value = sum(r[field] != '00000' for r in rows)
        elif any(r[field] is None for r in rows):
            value = None
            warnings.add('unknown_byte_semantics')
        else:
            value = sum(r[field] for r in rows)
        return dict(value=value, aggregation='log_event_sum', record_count=len(rows), coverage_ratio=None,
                    warnings=sorted(warnings | {'log_accounting_delay', 'log_coverage_unknown'}))

    def summary(self, target, a, b, metrics=None):
        _, series = self.selected_series(target, metrics)
        return [dict(s, **self.aggregate(s, self.observations(s, a, b), a, b)) for s in series]

    def timeseries(self, target, a, b, metrics, resolution_seconds):
        _, series = self.selected_series(target, metrics)
        step = resolution_seconds * 1000
        count = (b - a + step - 1) // step
        if count * len(series) > 2000:
            raise QueryError('too_many_points_increase_resolution')
        result = []
        for s in series:
            rows = self.observations(s, a, b)
            for begin in range(a, b, step):
                if time.monotonic() > self.deadline:
                    raise QueryError('query_timeout')
                end = min(begin + step, b)
                result.append(dict(s, start=utc(begin), end=utc(end), **self.aggregate(s, rows, begin, end)))
        return result

    def top(self, target, a, b, group_by, limit):
        sources = self.sources(target)
        if group_by == 'user' and any(s['kind'] == '3proxy' for s in sources):
            raise QueryError('3proxy_user_dimension_not_collected')
        if group_by == 'port' and any(s['kind'] != '3proxy' for s in sources):
            raise QueryError('application_traffic_not_attributed_to_port')
        wanted = ('traffic.client_upload_bytes_total', 'traffic.client_download_bytes_total') if group_by == 'user' else ('log.upload_bytes', 'log.download_bytes')
        # Do not require both directions: missing direction remains null.
        data = [r for r in self.summary(target, a, b) if r['name'] in wanted and group_by in r['dimensions']]
        consumers = {}
        for row in data:
            key = (row['source_id'], row['dimensions'][group_by])
            item = consumers.setdefault(key, dict(source_id=key[0], dimension=key[1], group_by=group_by,
                                                 upload_bytes=None, download_bytes=None, warnings=[]))
            item['upload_bytes' if row['name'] == wanted[0] else 'download_bytes'] = row['value']
            item['warnings'] = sorted(set(item['warnings'] + row['warnings']))
        for item in consumers.values():
            up, down = item['upload_bytes'], item['download_bytes']
            item['total_observed_bytes'] = None if up is None or down is None else up + down
            if item['total_observed_bytes'] is None:
                item['warnings'] = sorted(set(item['warnings'] + ['missing_or_unknown_direction']))
        ranked = sorted(consumers.values(), key=lambda x: (x['total_observed_bytes'] is not None,
                        x['total_observed_bytes'] or 0, x['source_id'], x['dimension']), reverse=True)
        return dict(items=ranked[:limit], omitted=len(ranked) > limit, global_total=None)

    def events(self, target, a, b, limit, cursor=None):
        sources = self.sources(target)
        marks, ids = self.placeholders(sources)
        scope = hashlib.sha256(json.dumps([target, a, b], sort_keys=True).encode()).hexdigest()
        after = [-1, '', 0]
        max_event = self.rows('SELECT coalesce(max(id),0) AS id FROM events')[0]['id']
        max_run = self.rows('SELECT coalesce(max(id),0) AS id FROM runs')[0]['id']
        if cursor:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode()))
                if decoded['scope'] != scope or not 0 <= self.now - decoded['created'] <= 600_000:
                    raise ValueError
                after = decoded['after']
                max_event, max_run = decoded['maxima']
                if (len(after) != 3 or type(after[0]) is not int or after[1] not in {'event', 'collection'}
                        or type(after[2]) is not int or type(max_event) is not int or type(max_run) is not int):
                    raise ValueError
            except (ValueError, KeyError, TypeError, UnicodeError):
                raise QueryError('invalid_or_expired_cursor') from None
        sql = f'''SELECT * FROM (
            SELECT id,source_id,observed_at AS timestamp,'event' AS origin,code FROM events
              WHERE source_id IN ({marks}) AND id<=?
            UNION ALL
            SELECT id,source_id,finished_at AS timestamp,'collection' AS origin,
              coalesce(error_code,status) AS code FROM runs
              WHERE source_id IN ({marks}) AND id<=? AND status!='ok'
            ) WHERE timestamp>=? AND timestamp<? AND (timestamp,origin,id)>(?,?,?)
            ORDER BY timestamp,origin,id LIMIT ?'''
        rows = self.rows(sql, [*ids, max_event, *ids, max_run, a, b, *after, limit + 1])
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            token = dict(scope=scope, created=self.now, maxima=[max_event, max_run],
                         after=[last['timestamp'], last['origin'], last['id']])
            next_cursor = base64.urlsafe_b64encode(json.dumps(token).encode()).decode()
        return dict(items=rows[:limit], next_cursor=next_cursor,
                    warnings=['events_only_within_retained_history'])

    def anomalies(self, target, a, b, summaries=None):
        summaries = self.summary(target, a, b) if summaries is None else summaries
        findings = []
        for row in summaries:
            if row['kind'] == 'counter' and any(w in row['warnings'] for w in ('reset', 'gap', 'clock_discontinuity', 'overlapping_intervals')):
                findings.append(dict(rule='data_quality', state='observed', severity='warning',
                                     source_id=row['source_id'], metric=row['name'], evidence=row['warnings']))
        by_source = {}
        for row in summaries:
            if row['name'] in {'upstream.connect_success_total', 'upstream.connect_fail_total'} and not row['dimensions']:
                by_source.setdefault(row['source_id'], {})[row['name']] = row
        for source, values in by_source.items():
            good, bad = values.get('upstream.connect_success_total'), values.get('upstream.connect_fail_total')
            if good and bad and not good['warnings'] and not bad['warnings']:
                attempts = good['value'] + bad['value']
                if attempts >= 20 and bad['value'] / attempts >= 0.1:
                    findings.append(dict(rule='upstream_failure_ratio', state='observed', severity='warning',
                                         source_id=source, evidence={'failures': bad['value'], 'outcomes': attempts,
                                         'ratio': bad['value'] / attempts, 'threshold': 0.1}))
        return dict(items=findings, lifecycle='not_persisted', baseline_status='not_implemented',
                    rules_version='1', warnings=['observed_window_findings_not_active_incidents'])


def envelope(now, data, window=None):
    result = dict(schema_version='1', generated_at=utc(now), data=data)
    warnings = set()
    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            warnings.update(value.get('warnings', []))
            if isinstance(value.get('quality'), str) and value['quality'] != 'ok':
                warnings.add(value['quality'])
            if value.get('stale'):
                warnings.add('stale_source')
            if value.get('status') in {'error', 'partial', 'unknown'}:
                warnings.add('collection_' + value['status'])
            for key, item in value.items():
                if key not in {'warnings', 'quality', 'dimensions'}:
                    visit(item)
    visit(data)
    if data == []:
        warnings.add('no_observed_series')
    result['quality'] = {'status': 'partial' if warnings else 'ok', 'warnings': sorted(warnings)}
    if window:
        result['requested_window'] = {'from': utc(window[0]), 'to': utc(window[1])}
    encoded = json.dumps(result, ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > 128 * 1024:
        raise QueryError('response_too_large_narrow_target')
    return result
