from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy_monitoring import logs, telemt
from proxy_monitoring.config import load
from proxy_monitoring.model import CollectionError, Metric, Snapshot
from proxy_monitoring.queries import Reader
from proxy_monitoring.runner import WriterLock, cycle
from proxy_monitoring.storage import Database


def record(up=10, down=20):
    return f'v1|1800000000|x|x|SOCKS|1080|00000|private-user|192.0.2.1|42|192.0.2.2|443|private-target|443|private-host|{down}|{up}|100|CONNECT private-target\n'


class DatabaseFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'monitor.db'
        self.db = Database(self.path)
        self.cfg = {'host_id': 'test', 'poll_seconds': 15, 'sources': [
            {'id': 'a', 'kind': 'telemt', 'instance': 'a', 'unit': 'a.service'},
            {'id': 'b', 'kind': 'telemt', 'instance': 'b', 'unit': 'b.service'},
        ]}
        self.db.register(self.cfg)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()


class StorageTests(DatabaseFixture):

    def save(self, value, ts, epoch='boot:invocation:pid:ticks', source='a'):
        self.db.save(source, ts, ts, Snapshot(epoch, [Metric('traffic', 'counter', 'bytes', value)]))

    def intervals(self):
        return [tuple(r) for r in self.db.conn.execute('SELECT delta,quality FROM intervals ORDER BY run_id')]

    def test_baseline_delta_reset_gap(self):
        self.save(100, 1000)
        self.save(150, 16000)
        self.save(3, 31000)
        self.save(9, 100000)
        self.assertEqual(self.intervals(), [(None, 'baseline'), (50, 'ok'), (None, 'reset'), (6, 'gap')])

    def test_epoch_restart_even_when_counter_increases(self):
        self.save(10, 1000)
        self.save(100, 16000, epoch='other-boot')
        self.assertEqual(self.intervals()[-1], (None, 'reset'))

    def test_clock_backwards(self):
        self.save(10, 2000)
        self.save(15, 1000)
        self.assertEqual(self.intervals()[-1], (None, 'clock_discontinuity'))
        reader = Reader(self.path)
        try:
            self.assertEqual(reader.current(1000)['data'][0]['value'], 15)
        finally:
            reader.close()

    def test_foreign_database_rejected_without_changing_journal_mode(self):
        path = self.root / 'foreign.db'
        with closing(sqlite3.connect(path)) as conn:
            conn.execute('CREATE TABLE unrelated(value)')
        with self.assertRaises(ValueError):
            Database(path)
        with closing(sqlite3.connect(path)) as conn:
            self.assertEqual(conn.execute('PRAGMA journal_mode').fetchone()[0], 'delete')

    def test_large_integer_is_exact(self):
        self.save(2**53 + 1, 1000)
        self.save(2**53 + 4, 16000)
        self.assertEqual(self.intervals()[-1], (3, 'ok'))

    def test_instances_are_isolated(self):
        self.save(100, 1000)
        self.save(900, 1000, source='b')
        self.save(102, 16000)
        self.assertEqual(self.intervals()[-1], (2, 'ok'))

    def test_missing_not_zero(self):
        self.save(10, 1000)
        self.db.save('a', 16000, 16000, Snapshot('epoch', [], ['missing:traffic']))
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM samples').fetchone()[0], 1)
        self.assertEqual(self.db.health(16000)[0]['status'], 'partial')

    def test_failed_observation_marks_short_gap(self):
        self.save(10, 1000)
        self.db.failure('a', 16000, 16000, 'timeout')
        self.save(15, 31000)
        self.assertEqual(self.intervals()[-1], (5, 'gap'))

    def test_disabled_sources_do_not_report_stale(self):
        self.cfg['sources'] = self.cfg['sources'][:1]
        self.db.register(self.cfg)
        self.assertEqual([r['id'] for r in self.db.health(1000)], ['a'])

    def test_snapshot_transaction_rolls_back(self):
        duplicate = Metric('traffic', 'counter', 'bytes', 10)
        with self.assertRaises(ValueError):
            self.db.save('a', 0, 1000, Snapshot('e', [duplicate, duplicate]))
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM runs').fetchone()[0], 0)
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM counter_state').fetchone()[0], 0)

    def test_persisted_baseline_survives_reopen_and_retention(self):
        self.save(10, 1000)
        self.db.prune(2000)
        self.db.close()
        self.db = Database(self.path)
        self.save(12, 16000)
        self.assertEqual(self.intervals()[-1], (2, 'ok'))

    def test_reader_cannot_write_and_reports_staleness(self):
        self.save(10, 1000)
        reader = Reader(self.path)
        try:
            self.assertTrue(reader.current(100000)['data'][0]['stale'])
            with self.assertRaises(sqlite3.OperationalError):
                reader.conn.execute('DELETE FROM samples')
        finally:
            reader.close()

    def test_current_does_not_present_failed_scrape_as_fresh_success(self):
        self.save(10, 1000)
        self.db.failure('a', 16000, 16000, 'metrics_unavailable')
        reader = Reader(self.path)
        try:
            row = reader.current(16000)['data'][0]
            self.assertEqual(row['quality'], 'not_observed_in_latest_run')
            self.assertEqual(row['observed_at'], 1000)
            self.assertEqual(row['source_status'], 'error')
        finally:
            reader.close()

    def test_failure_isolated_and_sanitized(self):
        with patch('proxy_monitoring.runner.telemt.collect', side_effect=[
            RuntimeError('secret-value'), Snapshot('epoch', [Metric('active', 'gauge', 'sessions', 2)])
        ]):
            self.assertFalse(cycle(self.db, self.cfg))
        runs = [dict(r) for r in self.db.conn.execute('SELECT * FROM runs')]
        self.assertEqual([r['status'] for r in runs], ['error', 'ok'])
        self.assertNotIn('secret-value', json.dumps(runs))

    def test_reused_source_identity_rejected(self):
        self.cfg['sources'][0]['unit'] = 'other.service'
        with self.assertRaises(ValueError):
            self.db.register(self.cfg)

    def test_writer_lock(self):
        with WriterLock(self.root / 'writer.lock'):
            with self.assertRaises(CollectionError):
                with WriterLock(self.root / 'writer.lock'):
                    self.fail('second writer acquired lock')


class LogTests(DatabaseFixture):
    def setUp(self):
        super().setUp()
        self.log = self.root / 'traffic.log'
        self.source = {'id': 'log', 'kind': '3proxy', 'instance': 'main', 'unit': 'p.service',
                       'ports': [1080], 'log_glob': str(self.root / 'traffic.log*'), 'byte_semantics': 'delta'}
        self.db.register({'host_id': 'test', 'poll_seconds': 15, 'sources': [self.source]})

    def tail(self, **kwargs):
        logs.tail(self.db, self.source, 1000, 1000, **kwargs)

    def rows(self):
        return [dict(r) for r in self.db.conn.execute('SELECT * FROM log_records')]

    def test_repeat_and_reopen_no_duplicates(self):
        self.log.write_text(record(), encoding='utf-8')
        self.tail()
        self.db.close()
        self.db = Database(self.path)
        self.tail()
        self.assertEqual(len(self.rows()), 1)
        self.assertNotIn('private-', json.dumps(self.rows()))
        self.assertNotIn('192.0.2', json.dumps(self.rows()))

    def test_identical_lines_at_different_offsets_are_not_deduplicated(self):
        self.log.write_text(record() * 2, encoding='utf-8')
        self.tail()
        self.assertEqual(len(self.rows()), 2)

    def test_partial_line(self):
        self.log.write_text(record().rstrip('\n'), encoding='utf-8')
        self.tail()
        self.assertEqual(self.rows(), [])
        with self.log.open('a', encoding='utf-8') as stream:
            stream.write('\n')
        self.tail()
        self.assertEqual(len(self.rows()), 1)

    def test_rename_rotation_drains_old_file(self):
        self.log.write_text(record() * 2, encoding='utf-8')
        self.tail(max_lines=1)
        self.log.rename(self.root / 'traffic.log.1')
        self.log.write_text(record(30), encoding='utf-8')
        self.tail()
        self.assertEqual(len(self.rows()), 3)
        self.assertEqual(sum(row['bytes_up'] for row in self.rows()), 50)

    def test_truncation(self):
        self.log.write_text(record() * 2, encoding='utf-8')
        self.tail()
        self.log.write_text(record(99), encoding='utf-8')
        self.tail()
        self.assertEqual(len(self.rows()), 3)
        self.assertEqual(self.db.conn.execute('SELECT code FROM events').fetchone()[0], 'log_truncation_or_replacement')

    def test_unknown_bytes_stay_null(self):
        self.source['byte_semantics'] = 'unknown'
        self.log.write_text(record(), encoding='utf-8')
        self.tail()
        self.assertIsNone(self.rows()[0]['bytes_up'])

    def test_malformed_record_is_skipped_and_visible(self):
        self.log.write_text('private-invalid-data\n' + record(), encoding='utf-8')
        self.tail()
        self.assertEqual(len(self.rows()), 1)
        warnings = self.db.conn.execute("SELECT warnings FROM runs WHERE source_id='log'").fetchone()[0]
        self.assertIn('log_parse_error', warnings)
        self.assertNotIn('private-invalid', warnings)

    def test_failure_rolls_back_records_and_cursor(self):
        self.log.write_text(record() + 'x' * 70000, encoding='utf-8')
        with self.assertRaises(CollectionError):
            self.tail()
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM cursors').fetchone()[0], 0)

    def test_legacy_format(self):
        parsed = logs.parse_line('17-10-2026 12:00:00 SOCKS.1080 00000 user 192.0.2.1:10 192.0.2.2:443 20 10 0 CONNECT target')
        self.assertEqual((parsed['bytes_up'], parsed['bytes_down']), (10, 20))

    def test_non_utf8_text_keeps_accounting_and_offsets(self):
        raw = record().encode().replace(b'CONNECT private-target', b'CONNECT \xff\xfe')
        self.log.write_bytes(raw + record().encode())
        self.tail()
        self.tail()
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]['offset'], len(raw))
        self.assertEqual(sum(r['bytes_up'] for r in rows), 20)
        self.assertNotIn('log_parse_error', self.db.conn.execute(
            "SELECT warnings FROM runs WHERE source_id='log' ORDER BY id DESC LIMIT 1").fetchone()[0])

    def test_non_utf8_numeric_field_is_still_rejected(self):
        self.log.write_bytes(record().encode().replace(b'|20|10|100|', b'|\xff|10|100|'))
        self.tail()
        self.assertEqual(self.rows(), [])
        self.assertIn('log_parse_error', self.db.conn.execute(
            "SELECT warnings FROM runs WHERE source_id='log'").fetchone()[0])


class PrometheusTests(unittest.TestCase):
    def test_aliases_and_integer_precision(self):
        metrics, _ = telemt.parse('telemt_user_octets_from_client_total{user="Иван"} 9007199254740993\n'
                                  'telemt_user_octets_from_client{user="Иван"} 4\n')
        self.assertEqual(len(metrics), 1)
        self.assertEqual(metrics[0].value, 9007199254740993)
        self.assertEqual(metrics[0].dimensions['user'], 'Иван')

    def test_missing_fields_are_warnings(self):
        metrics, warnings = telemt.parse('telemt_connections_total 0')
        self.assertEqual(len(metrics), 1)
        self.assertIn('missing:traffic.client_upload_bytes_total', warnings)

    def test_invalid_values(self):
        for value in ('NaN', '+Inf', '-1', '1.5', '9223372036854775808'):
            with self.subTest(value=value), self.assertRaises(CollectionError):
                telemt.parse('telemt_connections_total ' + value)

    def test_unknown_labels_not_silently_summed(self):
        metrics, warnings = telemt.parse('telemt_connections_total{extra="x"} 5\ntelemt_uptime_seconds 2')
        self.assertEqual(len(metrics), 1)
        self.assertIn('unsupported_labels:tcp.accepted_total', warnings)

    def test_duplicate_metric_rejected(self):
        with self.assertRaises(CollectionError):
            telemt.parse('telemt_connections_total 1\ntelemt_connections_total 2')

    def test_restart_during_scrape_rejected(self):
        with patch('proxy_monitoring.telemt.process_epoch', side_effect=['old', 'new']), \
             patch('proxy_monitoring.telemt.fetch', return_value='telemt_connections_total 1'):
            with self.assertRaisesRegex(CollectionError, 'restart_during_scrape'):
                telemt.collect({'unit': 'x.service', 'metrics_url': 'http://127.0.0.1:1/metrics'})


class ConfigTests(unittest.TestCase):
    def test_linux_example_validates_on_all_development_platforms(self):
        cfg = load(Path(__file__).resolve().parents[1] / 'config.example.json')
        self.assertEqual(len(cfg['sources']), 3)

    def test_reject_remote_endpoint_and_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.json'
            cfg = {'host_id': 'host', 'sources': [{'id': 'a', 'kind': 'telemt', 'unit': 'a.service',
                    'instance': 'a', 'metrics_url': 'http://example.com/metrics'}]}
            path.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError):
                load(path)
            cfg['sources'][0]['metrics_url'] = 'http://127.0.0.1:9090/metrics'
            cfg['sources'].append(cfg['sources'][0])
            path.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError):
                load(path)


if __name__ == '__main__':
    unittest.main()
