"""Real host acquisition and CLI smoke test, without touching production services."""
from contextlib import closing
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    if sys.platform != 'linux':
        raise SystemExit('Linux required')
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix='proxy-monitoring-smoke-') as temp:
        base = Path(temp)
        config = base / 'config.json'
        config.write_text(json.dumps({'host_id': 'smoke', 'database': str(base / 'monitor.db'),
                                     'sources': [{'id': 'host', 'kind': 'host', 'mountpoints': ['/']}]}))
        def command(*args):
            return subprocess.run([sys.executable, '-m', 'proxy_monitoring', '--config', str(config), *args],
                                  cwd=root, capture_output=True, text=True, check=True, timeout=15)
        command('validate')
        command('collect', '--once')
        command('collect', '--once')
        health = json.loads(command('health').stdout)
        current = json.loads(command('current').stdout)
        assert health[0]['status'] == 'ok'
        assert any(row['name'] == 'host.memory_bytes' for row in current['data'])
        with closing(sqlite3.connect(base / 'monitor.db')) as db:
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            assert db.execute("SELECT count(*) FROM intervals WHERE quality='ok'").fetchone()[0] > 0
        print('Linux /proc, CLI, persistence, deltas and SQLite integrity: OK; temporary state removed on exit')


if __name__ == '__main__':
    main()
