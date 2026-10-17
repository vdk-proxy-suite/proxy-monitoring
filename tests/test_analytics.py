import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from proxy_monitoring.analytics import Analytics, QueryError, envelope, parse_window, utc
from proxy_monitoring.model import Metric, Snapshot
from proxy_monitoring.storage import Database


class AnalyticsFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'monitor.db'
        self.a = int(time.time() * 1000) // 60000 * 60000 - 120000
        self.b = self.a + 30000
        self.db = Database(self.path)
        self.cfg = {'host_id': 'test', 'database': str(self.path), 'poll_seconds': 15,
                    'sources': [{'id': 't', 'kind': 'telemt', 'instance': 'one', 'unit': 'one.service',
                                 'metrics_url': 'http://127.0.0.1:19090/metrics'},
                                {'id': 'p', 'kind': '3proxy', 'instance': 'main', 'unit': 'p.service',
                                 'log_glob': str(self.root / '*.log'), 'ports': [1080]}]}
        self.db.register(self.cfg)
        for i in range(3):
            self.db.save('t', self.a + i * 15000, self.a + i * 15000, Snapshot('epoch', [
                Metric('traffic.client_upload_bytes_total', 'counter', 'bytes', 100 + i * 10, {'user': 'alice'}),
                Metric('traffic.client_download_bytes_total', 'counter', 'bytes', 200 + i * 20, {'user': 'alice'}),
                Metric('sessions.active', 'gauge', 'sessions', i + 1, {'user': 'alice'}),
                Metric('upstream.connect_success_total', 'counter', 'events', 100 + i * 10),
                Metric('upstream.connect_fail_total', 'counter', 'events', 100 + i * 5),
            ]))
        with self.db.conn:
            self.db.conn.execute('''INSERT INTO log_records(source_id,generation,offset,event_at,ingested_at,
                port,operation,result_code,bytes_up,bytes_down,quality) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                ('p', 'g', 0, self.a + 5000, self.a + 5000, 1080, 'CONNECT', '00000', 7, 9, 'log_event_time'))
            self.db.run('p', self.a, self.b, 'ok')

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def query(self):
        return Analytics(self.path, now=self.b)


class AnalyticsTests(AnalyticsFixture):
    def test_complete_counter_summary_and_zero(self):
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.a, self.b, ['traffic.client_upload_bytes_total'])[0]
            self.assertEqual(row['value'], 20)
            self.assertEqual(row['coverage_ratio'], 1)
            self.assertAlmostEqual(row['rate_per_second'], 20 / 30)

    def test_partial_boundaries_are_not_interpolated(self):
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.a + 1, self.b - 1, ['traffic.client_upload_bytes_total'])[0]
            self.assertIsNone(row['value'])
            self.assertEqual(row['coverage_ratio'], 0)
            self.assertIn('boundary_interval_excluded', row['warnings'])

    def test_empty_window_is_not_zero(self):
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.b + 1, self.b + 60000, ['sessions.active'])[0]
            self.assertIsNone(row['value'])

    def test_gauges_are_sample_statistics(self):
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.a, self.b, ['sessions.active'])[0]
            self.assertEqual(row['value'], 1.5)
            self.assertEqual(row['max'], 2)
            self.assertEqual(row['aggregation'], 'sample_mean')

    def test_timeseries_does_not_distribute_large_interval(self):
        with self.query() as q:
            rows = q.timeseries({'source_ids': ['t']}, self.a, self.b, ['traffic.client_upload_bytes_total'], 5)
            self.assertEqual(len(rows), 6)
            self.assertTrue(all(r['value'] is None for r in rows))

    def test_gap_keeps_total_but_not_rate(self):
        with self.db.conn:
            self.db.conn.execute("UPDATE intervals SET quality='gap' WHERE delta IS NOT NULL")
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.a, self.b, ['traffic.client_upload_bytes_total'])[0]
            self.assertEqual(row['value'], 20)
            self.assertIsNone(row['rate_per_second'])
            self.assertEqual(row['covered_ms'], 0)

    def test_reset_is_not_counted_as_traffic(self):
        with self.db.conn:
            self.db.conn.execute("UPDATE intervals SET quality='reset',delta=NULL WHERE delta IS NOT NULL")
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.a, self.b, ['traffic.client_upload_bytes_total'])[0]
            self.assertIsNone(row['value'])
            self.assertIn('reset', row['warnings'])

    def test_overlapping_clock_intervals_do_not_double_count(self):
        with self.db.conn:
            self.db.conn.execute('UPDATE intervals SET start_at=? WHERE delta IS NOT NULL', (self.a,))
        with self.query() as q:
            row = q.summary({'source_ids': ['t']}, self.a, self.b, ['traffic.client_upload_bytes_total'])[0]
            self.assertIsNone(row['value'])
            self.assertIn('overlapping_intervals', row['warnings'])

    def test_logs_unknown_bytes_and_no_false_sessions(self):
        with self.db.conn:
            self.db.conn.execute('UPDATE log_records SET bytes_up=NULL')
        with self.query() as q:
            rows = {r['name']: r for r in q.summary({'kind': '3proxy'}, self.a, self.b)}
            self.assertEqual(rows['log.events']['value'], 1)
            self.assertIsNone(rows['log.upload_bytes']['value'])
            self.assertNotIn('connections', rows)

    def test_source_and_dimension_filters(self):
        with self.query() as q:
            rows = q.current({'source_ids': ['t'], 'user': 'alice'})
            self.assertTrue(all(r['dimensions'] == {'user': 'alice'} for r in rows))
            self.assertEqual(len(rows), 3)
            with self.assertRaises(QueryError):
                q.sources({'source_ids': ["t' OR 1=1 --"]})

    def test_unknown_source_or_metric_is_error(self):
        with self.query() as q:
            with self.assertRaises(QueryError):
                q.sources({'source_ids': ['t', 'missing']})
            with self.assertRaises(QueryError):
                q.current({'source_ids': ['t']}, ['imaginary.metric'])

    def test_top_consumers_no_global_total(self):
        with self.query() as q:
            users = q.top({'kind': 'telemt'}, self.a, self.b, 'user', 10)
            self.assertEqual(users['items'][0]['total_observed_bytes'], 60)
            self.assertIsNone(users['global_total'])
            ports = q.top({'kind': '3proxy'}, self.a, self.b, 'port', 10)
            self.assertEqual(ports['items'][0]['total_observed_bytes'], 16)
            with self.assertRaises(QueryError):
                q.top({}, self.a, self.b, 'user', 10)

    def test_findings_have_evidence_not_lifecycle(self):
        with self.query() as q:
            findings = q.anomalies({'kind': 'telemt'}, self.a, self.b)
            self.assertEqual(findings['items'][0]['rule'], 'upstream_failure_ratio')
            self.assertEqual(findings['items'][0]['evidence']['failures'], 10)
            self.assertEqual(findings['lifecycle'], 'not_persisted')

    def test_events_cursor_scope_and_insert_stability(self):
        with self.db.conn:
            for i in range(3):
                self.db.conn.execute('INSERT INTO events(source_id,observed_at,code) VALUES(?,?,?)', ('t', self.a + i, 'reset'))
        with self.query() as q:
            first = q.events({'kind': 'telemt'}, self.a, self.b, 1)
        with self.db.conn:
            self.db.conn.execute('INSERT INTO events(source_id,observed_at,code) VALUES(?,?,?)', ('t', self.a + 1, 'new'))
        with self.query() as q:
            rest = q.events({'kind': 'telemt'}, self.a, self.b, 10, first['next_cursor'])
            self.assertEqual(len(rest['items']), 2)
            with self.assertRaises(QueryError):
                q.events({'kind': '3proxy'}, self.a, self.b, 1, first['next_cursor'])

    def test_query_budget_and_response_budget(self):
        with self.query() as q:
            q.remaining = 0
            with self.assertRaises(QueryError):
                q.inventory({})
        with self.assertRaises(QueryError):
            envelope(self.b, {'oversize': 'a' * 140000})
        with self.query() as q:
            with self.assertRaises(QueryError):
                q.timeseries({'kind': 'telemt'}, self.a, self.b + 3000000, ['sessions.active'], 1)

    def test_expired_query_budget_and_no_data_quality(self):
        with self.query() as q:
            q.deadline = time.monotonic() - 1
            with self.assertRaisesRegex(QueryError, 'query_timeout'):
                q.health({})
        self.assertIn('no_observed_series', envelope(self.b, [])['quality']['warnings'])

    def test_known_zero_counter_remains_zero(self):
        with self.db.conn:
            self.db.conn.execute('UPDATE intervals SET delta=0 WHERE delta IS NOT NULL')
        with self.query() as q:
            row = q.summary({'kind': 'telemt'}, self.a, self.b, ['traffic.client_upload_bytes_total'])[0]
            self.assertEqual(row['value'], 0)
            self.assertEqual(row['rate_per_second'], 0)

    def test_malformed_cursor_and_stale_metric(self):
        with self.query() as q:
            with self.assertRaises(QueryError):
                q.events({}, self.a, self.b, 10, 'not-a-cursor')
            q.now = self.b + 60000
            rows = q.current({'kind': 'telemt'}, max_age_seconds=30)
            self.assertTrue(all(row['quality'] == 'stale' for row in rows))

    def test_readonly_snapshot_and_old_schema(self):
        with self.query() as q:
            with self.assertRaises(sqlite3.OperationalError):
                q.conn.execute('DELETE FROM samples')
            self.assertEqual(q.conn.execute('PRAGMA user_version').fetchone()[0], 1)

    def test_missing_database_is_not_created(self):
        path = self.root / 'absent.db'
        with self.assertRaises(sqlite3.OperationalError):
            Analytics(path)
        self.assertFalse(path.exists())

    def test_rfc3339_window(self):
        self.assertEqual(parse_window(utc(self.a), utc(self.b)), (self.a, self.b))
        for start, end in [('2026-01-01', '2026-01-02'), ('2026-01-01T00:00:00Z', '2026-03-01T00:00:00Z')]:
            with self.assertRaises(QueryError):
                parse_window(start, end)
