import os
import signal
import time
from pathlib import Path

from . import linux, logs, telemt
from .model import CollectionError
from .storage import Database


def now_ms():
    return time.time_ns() // 1_000_000


class WriterLock:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open('a+b')

    def __enter__(self):
        try:
            if os.name == 'nt':
                import msvcrt
                self.stream.seek(0)
                if not self.stream.read(1):
                    self.stream.write(b'0')
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise CollectionError('collector_already_running') from None
        return self

    def __exit__(self, *args):
        self.stream.close()


def cycle(db: Database, cfg: dict) -> bool:
    success = True
    for source in cfg['sources']:
        started = now_ms()
        try:
            if source['kind'] == '3proxy':
                logs.tail(db, source, started, now_ms())
            else:
                snapshot = linux.collect_host(source) if source['kind'] == 'host' else telemt.collect(source)
                db.save(source['id'], started, now_ms(), snapshot)
        except Exception as exc:
            # Do not expose URLs, raw log lines, usernames, paths or exception strings.
            code = exc.code if isinstance(exc, CollectionError) else {
                'PermissionError': 'permission_denied', 'FileNotFoundError': 'source_missing',
                'TimeoutExpired': 'command_timeout', 'TimeoutError': 'source_timeout',
                'URLError': 'metrics_unavailable', 'HTTPError': 'metrics_http_error',
            }.get(type(exc).__name__, 'collection_failed')
            db.failure(source['id'], started, now_ms(), code)
            success = False
    return success


def run(cfg: dict, once: bool) -> int:
    if os.name != 'nt':
        os.umask(0o077)
    path = Path(cfg['database'])
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    with WriterLock(path.with_suffix(path.suffix + '.lock')):
        db = Database(path)
        try:
            db.register(cfg)
            if not once:
                signal.signal(signal.SIGTERM, stop)
                signal.signal(signal.SIGINT, stop)
            maintenance = 0.0
            while not stopping:
                started = time.monotonic()
                success = cycle(db, cfg)
                if started >= maintenance:
                    db.prune(now_ms() - int(cfg['retention_days'] * 86_400_000))
                    maintenance = started + 3600
                if once:
                    return 0 if success else 1
                deadline = started + cfg['poll_seconds']
                while not stopping and time.monotonic() < deadline:
                    time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        finally:
            db.close()
    return 0
