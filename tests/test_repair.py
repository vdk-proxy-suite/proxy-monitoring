import json
import unittest

from proxy_monitoring.logs import tail
from proxy_monitoring.model import CollectionError
from proxy_monitoring.repair import replay
from proxy_monitoring.runner import WriterLock
from test_collector import DatabaseFixture, record


class RepairTests(DatabaseFixture):
    def setUp(self):
        super().setUp()
        self.log = self.root / 'traffic.log'
        self.source = dict(id='log', kind='3proxy', instance='main', unit='p.service',
                           ports=[1080], log_glob=str(self.log), byte_semantics='unknown')
        self.cfg = dict(host_id='test', database=str(self.path), poll_seconds=15, sources=[self.source])
        self.db.register(self.cfg)

    def test_profile_upgrade_and_replay_preserve_identity(self):
        self.log.write_bytes(record(10, 20).encode() + record(30, 70).encode().replace(b'private-target', b'\xff'))
        tail(self.db, self.source, 1, 2)
        # Emulate v0.2.0 skipping a bad UTF-8 record while advancing the cursor.
        with self.db.conn:
            self.db.conn.execute('DELETE FROM log_records WHERE offset>0')
        original = self.db.conn.execute('SELECT id,generation FROM log_records').fetchone()
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        result = replay(self.cfg, ['log'])
        self.assertEqual(result[0]['inserted_records'], 1)
        rows = self.db.conn.execute('SELECT * FROM log_records ORDER BY offset').fetchall()
        self.assertEqual(rows[0]['id'], original['id'])
        self.assertEqual(rows[0]['generation'], original['generation'])
        self.assertEqual(sum(r['bytes_up'] for r in rows), 40)
        self.assertEqual(sum(r['bytes_down'] for r in rows), 90)
        self.assertEqual(replay(self.cfg, ['log'])[0]['inserted_records'], 0)
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM log_records').fetchone()[0], 2)

    def test_other_config_changes_rejected(self):
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        self.source['ports'] = [1081]
        with self.assertRaises(ValueError):
            self.db.register(self.cfg)

    def test_missing_file_cursor_is_preserved(self):
        self.log.write_text(record())
        tail(self.db, self.source, 1, 2)
        with self.db.conn:
            self.db.conn.execute('INSERT INTO cursors VALUES(?,?,?,?,?,?)', ('log', 'missing-file', 'old-generation', 999, 0, 'hash'))
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        replay(self.cfg, ['log'])
        self.assertEqual(self.db.conn.execute("SELECT offset FROM cursors WHERE file_key='missing-file'").fetchone()[0], 999)

    def test_truncated_file_replay_does_not_rewind_or_relabel_history(self):
        self.log.write_text(record() * 3)
        tail(self.db, self.source, 1, 2)
        offset = self.db.conn.execute('SELECT offset FROM cursors').fetchone()[0]
        self.log.write_text(record())
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        with self.assertRaisesRegex(CollectionError, 'replay_file_changed'):
            replay(self.cfg, ['log'])
        self.assertEqual(self.db.conn.execute('SELECT offset FROM cursors').fetchone()[0], offset)
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM log_records WHERE bytes_up IS NULL').fetchone()[0], 3)

    def test_wrong_format_is_not_treated_as_verified_bytes(self):
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        self.db.register(self.cfg)
        self.log.write_text('17-10-2026 12:00:00 SOCKS.1080 00000 user a:1 b:2 20 10 0 CONNECT target\n')
        tail(self.db, self.source, 1, 2)
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM log_records').fetchone()[0], 0)
        self.assertIn('profile_format_mismatch', self.db.conn.execute('SELECT warnings FROM runs').fetchone()[0])

    def test_replay_cannot_run_alongside_collector(self):
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        with WriterLock(self.path.with_suffix('.db.lock')):
            with self.assertRaisesRegex(CollectionError, 'collector_already_running'):
                replay(self.cfg, ['log'])

    def test_legacy_delta_is_repaired_without_new_source(self):
        self.source['byte_semantics'] = 'delta'
        # New initial config; replace signature only to represent a preexisting delta source.
        import hashlib
        with self.db.conn:
            self.db.conn.execute('UPDATE sources SET config_signature=? WHERE id=?',
                (hashlib.sha256(json.dumps(self.source, sort_keys=True).encode()).hexdigest(), 'log'))
        self.log.write_text(record(10, 20))
        tail(self.db, self.source, 1, 2)
        with self.db.conn:
            self.db.conn.execute('UPDATE log_records SET bytes_up=20,bytes_down=10')
        self.source['byte_semantics'] = '3proxy_monitor_v1'
        replay(self.cfg, ['log'])
        row = self.db.conn.execute('SELECT bytes_up,bytes_down FROM log_records').fetchone()
        self.assertEqual(tuple(row), (10, 20))
