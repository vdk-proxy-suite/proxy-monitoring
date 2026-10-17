"""Read-only query boundary for CLI and future MCP/bot adapters."""
import json
import sqlite3
from pathlib import Path

from .storage import Database


class Reader:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=3)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA query_only=ON')

    def close(self):
        self.conn.close()

    def health(self, now: int):
        return Database.health(self, now)

    def current(self, now: int, limit: int = 1000):
        rows = self.conn.execute('''SELECT s.source_id,s.name,s.unit,s.kind,s.dimensions,
            p.observed_at,p.run_id,p.value_integer,p.value_real,src.poll_ms
            FROM series s JOIN sources src ON src.id=s.source_id JOIN samples p
            ON p.series_id=s.id AND p.run_id=(SELECT run_id FROM samples WHERE series_id=s.id
            ORDER BY run_id DESC LIMIT 1)
            WHERE src.enabled=1 ORDER BY s.source_id,s.name,s.dimensions LIMIT ?''', (limit + 1,)).fetchall()
        latest_runs = {r['source_id']: dict(r) for r in self.conn.execute('''SELECT r.* FROM runs r
            WHERE r.id=(SELECT max(id) FROM runs WHERE source_id=r.source_id)''')}
        result = []
        for row in rows[:limit]:
            item = dict(row)
            item['value'] = item.pop('value_integer')
            real = item.pop('value_real')
            if item['value'] is None:
                item['value'] = real
            item['dimensions'] = json.loads(item['dimensions'])
            item['age_ms'] = now - item['observed_at']
            item['stale'] = item['age_ms'] < 0 or item['age_ms'] > item.pop('poll_ms') * 3
            latest = latest_runs[item['source_id']]
            item['source_status'] = latest['status']
            item['quality'] = ('stale' if item['stale'] else
                               'not_observed_in_latest_run' if item.pop('run_id') != latest['id'] else 'ok')
            item.pop('run_id', None)
            result.append(item)
        return {'data': result, 'truncated': len(rows) > limit}
