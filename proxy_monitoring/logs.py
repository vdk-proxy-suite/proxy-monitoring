import datetime as dt
import glob
import hashlib
import uuid
from pathlib import Path

from .model import CollectionError


def parse_line(line: str) -> dict:
    """Keep no IPs, usernames, requested URLs or free-form service text."""
    if line.startswith('v1|'):
        fields = line.strip().split('|', 18)
        if len(fields) != 19:
            raise ValueError('invalid monitor_v1 record')
        timestamp, port, code = int(fields[1]) * 1000, int(fields[5]), fields[6]
        down, up = int(fields[15]), int(fields[16])
        operation = fields[18].split(' ', 1)[0]
    else:
        fields = line.strip().split(maxsplit=10)
        if len(fields) != 11:
            raise ValueError('invalid legacy record')
        timestamp = int(dt.datetime.strptime(' '.join(fields[:2]), '%d-%m-%Y %H:%M:%S')
                        .replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
        port, code = int(fields[2].rsplit('.', 1)[1]), fields[3]
        down, up = int(fields[7]), int(fields[8])
        operation = fields[10].split(' ', 1)[0]
    if not 1 <= port <= 65535 or len(code) != 5 or not code.isascii() or not code.isdigit():
        raise ValueError('invalid port/code')
    if not 0 <= min(up, down, timestamp) or max(up, down, timestamp) > 2**63 - 1:
        raise ValueError('invalid numeric value')
    if operation not in {'CONNECT', 'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'UDPASSOC', 'UDPMAP', 'BIND'}:
        operation = 'other'
    return dict(event_at=timestamp, port=port, result_code=code, bytes_up=up, bytes_down=down, operation=operation)


def tail(db, source: dict, started: int, now: int, max_lines: int = 2000):
    paths = sorted(Path(p) for p in glob.glob(source['log_glob']))
    if not paths:
        raise CollectionError('logs_missing')
    if len(paths) > 256:
        raise CollectionError('log_file_limit')
    warnings, remaining, files_read = [], max_lines, 0
    with db.conn:
        for path in paths:
            if path.suffix == '.gz':
                warnings.append('compressed_log_not_imported')
                continue
            if remaining <= 0:
                warnings.append('log_backlog')
                break
            with path.open('rb') as stream:
                import os
                stat = os.fstat(stream.fileno())
                key = f'{stat.st_dev}:{stat.st_ino}'
                old = db.conn.execute('SELECT * FROM cursors WHERE source_id=? AND file_key=?', (source['id'], key)).fetchone()
                prefix_len = old['prefix_len'] if old else min(stat.st_size, 256)
                prefix = stream.read(prefix_len)
                digest = hashlib.sha256(prefix).hexdigest()
                reset = old and (stat.st_size < old['offset'] or len(prefix) != prefix_len or digest != old['prefix_hash'])
                if reset:
                    db.conn.execute('INSERT INTO events(source_id,observed_at,code) VALUES(?,?,?)',
                                    (source['id'], now, 'log_truncation_or_replacement'))
                    warnings.append('possible_log_loss')
                generation = str(uuid.uuid4()) if not old or reset else old['generation']
                offset = 0 if not old or reset else old['offset']
                if not old or reset or prefix_len == 0:
                    prefix_len = min(stat.st_size, 256)
                    stream.seek(0)
                    digest = hashlib.sha256(stream.read(prefix_len)).hexdigest()
                stream.seek(offset)
                while remaining > 0:
                    position = stream.tell()
                    raw = stream.readline(65537)
                    if not raw:
                        break
                    if len(raw) > 65536:
                        raise CollectionError('log_line_too_large')
                    if not raw.endswith(b'\n'):
                        break  # Leave incomplete tail at its original offset.
                    remaining -= 1
                    offset = stream.tell()
                    try:
                        record = parse_line(raw.decode('utf-8'))
                    except (ValueError, IndexError, UnicodeError):
                        warnings.append('log_parse_error')
                        continue
                    if record['port'] not in source['ports']:
                        continue
                    known = source.get('byte_semantics') == 'delta'
                    db.conn.execute('''INSERT OR IGNORE INTO log_records
                        (source_id,generation,offset,event_at,ingested_at,port,operation,result_code,bytes_up,bytes_down,quality)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                        (source['id'], generation, position, record['event_at'], now, record['port'], record['operation'],
                         record['result_code'], record['bytes_up'] if known else None, record['bytes_down'] if known else None,
                         'log_event_time' if known else 'unknown_byte_semantics'))
                if offset < stat.st_size:
                    warnings.append('log_pending_bytes')
                db.conn.execute('INSERT OR REPLACE INTO cursors VALUES(?,?,?,?,?,?)',
                                (source['id'], key, generation, offset, prefix_len, digest))
                files_read += 1
        if not files_read:
            raise CollectionError('no_readable_plain_logs')
        if source.get('byte_semantics') != 'delta':
            warnings.append('unknown_byte_semantics')
        db.run(source['id'], started, now, 'partial' if warnings else 'ok', warnings=warnings)
