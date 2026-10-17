"""Explicit offline replay of retained plain logs, preserving event identity."""
from pathlib import Path
import json
import glob
import hashlib
import os

from .logs import tail
from .model import CollectionError
from .runner import WriterLock, now_ms
from .storage import Database


def replay(cfg: dict, source_ids: list[str]):
    sources = [s for s in cfg['sources'] if s['id'] in source_ids]
    if not source_ids or set(source_ids) != {s['id'] for s in sources}:
        raise CollectionError('select_existing_3proxy_sources')
    if any(s['kind'] != '3proxy' or s.get('byte_semantics') != '3proxy_monitor_v1' for s in sources):
        raise CollectionError('replay_requires_3proxy_monitor_v1_profile')
    path = Path(cfg['database'])
    if not path.is_file():
        raise CollectionError('database_missing')
    with WriterLock(path.with_suffix(path.suffix + '.lock')):
        db = Database(path)
        try:
            db.register(cfg)
            results = []
            for source in sources:
                ident = source['id']
                paths = [Path(p) for p in glob.glob(source['log_glob']) if not p.endswith('.gz')]
                if not paths:
                    raise CollectionError('logs_missing')
                if len(paths) > 256:
                    raise CollectionError('log_file_limit')
                available_keys = set()
                # Validate before rewinding: otherwise resetting offset would hide
                # a truncation that the normal tailer can detect by file size.
                for log in paths:
                    with log.open('rb') as stream:
                        stat = os.fstat(stream.fileno())
                        key = f'{stat.st_dev}:{stat.st_ino}'
                        available_keys.add(key)
                        old = db.conn.execute('SELECT * FROM cursors WHERE source_id=? AND file_key=?', (ident, key)).fetchone()
                        if old and (stat.st_size < old['offset'] or
                            hashlib.sha256(stream.read(old['prefix_len'])).hexdigest() != old['prefix_hash']):
                            raise CollectionError('replay_file_changed_run_collection_first')
                before = db.conn.execute('SELECT count(*) FROM log_records WHERE source_id=?', (ident,)).fetchone()[0]
                with db.conn:
                    # Keep generation and prefix fingerprints: unique offsets prevent
                    # duplicate events, while UPSERT repairs old NULL/swapped bytes.
                    for key in available_keys:
                        db.conn.execute('UPDATE cursors SET offset=0 WHERE source_id=? AND file_key=?', (ident, key))
                completed = False
                warnings = set()
                for _ in range(10000):
                    previous = list(db.conn.execute('SELECT file_key,generation,offset FROM cursors WHERE source_id=? ORDER BY file_key', (ident,)))
                    stamp = now_ms()
                    tail(db, source, stamp, stamp, repair=True)
                    run = db.conn.execute('SELECT warnings FROM runs WHERE source_id=? ORDER BY id DESC LIMIT 1', (ident,)).fetchone()
                    warnings.update(set(json.loads(run['warnings'])) - {'log_pending_bytes', 'log_backlog'})
                    current = list(db.conn.execute('SELECT file_key,generation,offset FROM cursors WHERE source_id=? ORDER BY file_key', (ident,)))
                    if [tuple(r) for r in current] == [tuple(r) for r in previous]:
                        completed = True
                        break
                if not completed:
                    raise CollectionError('replay_batch_limit_rerun_replay')
                after = db.conn.execute('SELECT count(*) FROM log_records WHERE source_id=?', (ident,)).fetchone()[0]
                last = db.conn.execute('SELECT status,warnings FROM runs WHERE source_id=? ORDER BY id DESC LIMIT 1', (ident,)).fetchone()
                warnings.update(json.loads(last['warnings']))
                unknown = db.conn.execute('SELECT count(*) FROM log_records WHERE source_id=? AND (bytes_up IS NULL OR bytes_down IS NULL)', (ident,)).fetchone()[0]
                results.append(dict(source_id=ident, inserted_records=after-before,
                                    remaining_unknown_records=unknown,
                                    status='partial' if warnings or unknown else 'ok', warnings=sorted(warnings)))
            return results
        finally:
            db.close()
