import hashlib
import json
import math
import sqlite3
from pathlib import Path

from .model import Snapshot

SCHEMA = """
CREATE TABLE sources (
 id TEXT PRIMARY KEY, host_id TEXT NOT NULL, kind TEXT NOT NULL,
 instance TEXT, unit TEXT, poll_ms INTEGER NOT NULL,
 config_signature TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE runs (
 id INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id),
 started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL,
 status TEXT NOT NULL, error_code TEXT, warnings TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX runs_source_time ON runs(source_id, finished_at);
CREATE TABLE series (
 id INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id),
 name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('counter','gauge')),
 unit TEXT NOT NULL, dimensions TEXT NOT NULL,
 UNIQUE(source_id, name, dimensions)
);
CREATE TABLE samples (
 series_id INTEGER NOT NULL REFERENCES series(id), run_id INTEGER NOT NULL REFERENCES runs(id),
 observed_at INTEGER NOT NULL, epoch TEXT NOT NULL,
 value_integer INTEGER, value_real REAL,
 CHECK((value_integer IS NULL) != (value_real IS NULL)),
 PRIMARY KEY(series_id,run_id)
);
CREATE INDEX samples_series_time ON samples(series_id, observed_at);
CREATE TABLE intervals (
 series_id INTEGER NOT NULL REFERENCES series(id), run_id INTEGER NOT NULL REFERENCES runs(id),
 start_at INTEGER NOT NULL, end_at INTEGER NOT NULL,
 delta INTEGER, quality TEXT NOT NULL,
 PRIMARY KEY(series_id,run_id)
);
CREATE INDEX intervals_series_time ON intervals(series_id,end_at);
CREATE TABLE counter_state (
 series_id INTEGER PRIMARY KEY REFERENCES series(id), observed_at INTEGER NOT NULL,
 epoch TEXT NOT NULL, value INTEGER NOT NULL
);
CREATE TABLE cursors (
 source_id TEXT NOT NULL REFERENCES sources(id), file_key TEXT NOT NULL,
 generation TEXT NOT NULL, offset INTEGER NOT NULL,
 prefix_len INTEGER NOT NULL, prefix_hash TEXT NOT NULL,
 PRIMARY KEY(source_id,file_key)
);
CREATE TABLE log_records (
 id INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id),
 generation TEXT NOT NULL, offset INTEGER NOT NULL,
 event_at INTEGER NOT NULL, ingested_at INTEGER NOT NULL,
 port INTEGER NOT NULL, operation TEXT NOT NULL, result_code TEXT NOT NULL,
 bytes_up INTEGER, bytes_down INTEGER, quality TEXT NOT NULL,
 UNIQUE(source_id,generation,offset)
);
CREATE INDEX logs_source_time ON log_records(source_id,event_at);
CREATE TABLE events (
 id INTEGER PRIMARY KEY, source_id TEXT NOT NULL REFERENCES sources(id),
 observed_at INTEGER NOT NULL, code TEXT NOT NULL
);
PRAGMA user_version=1;
"""


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=5)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            if self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                self.conn.close()
                raise ValueError("refusing to initialize a nonempty foreign database")
        elif version != 1:
            self.conn.close()
            raise ValueError("unsupported schema version")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        if version == 0:
            self.conn.executescript("BEGIN;" + SCHEMA + "COMMIT;")

    def close(self):
        self.conn.close()

    def register(self, cfg: dict):
        with self.conn:
            self.conn.execute('UPDATE sources SET enabled=0')
            for src in cfg["sources"]:
                row = self.conn.execute("SELECT * FROM sources WHERE id=?", (src["id"],)).fetchone()
                identity = (cfg["host_id"], src["kind"], src.get("instance"), src.get("unit"))
                signature = hashlib.sha256(json.dumps(src, sort_keys=True).encode()).hexdigest()
                if row and tuple(row[k] for k in ("host_id", "kind", "instance", "unit")) != identity:
                    raise ValueError("source identity changed; use a new source id")
                if row and row['config_signature'] != signature:
                    raise ValueError('source configuration changed; use a new source id')
                self.conn.execute(
                    "INSERT INTO sources VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET poll_ms=excluded.poll_ms,enabled=1",
                    (src["id"], *identity, int(cfg["poll_seconds"] * 1000), signature),
                )

    def run(self, source: str, started: int, finished: int, status: str, error=None, warnings=()):
        return self.conn.execute(
            "INSERT INTO runs(source_id,started_at,finished_at,status,error_code,warnings) VALUES(?,?,?,?,?,?)",
            (source, started, finished, status, error, json.dumps(sorted(set(warnings)))),
        ).lastrowid

    def failure(self, source: str, started: int, finished: int, code: str):
        with self.conn:
            self.run(source, started, finished, "error", code)

    def save(self, source: str, started: int, now: int, snapshot: Snapshot):
        with self.conn:
            run_id = self.run(source, started, now, "partial" if snapshot.warnings else "ok", warnings=snapshot.warnings)
            poll = self.conn.execute("SELECT poll_ms FROM sources WHERE id=?", (source,)).fetchone()[0]
            seen = set()
            for metric in snapshot.metrics:
                if not math.isfinite(metric.value) or metric.value < 0:
                    raise ValueError("invalid metric value")
                if metric.kind == "counter" and type(metric.value) is not int:
                    raise ValueError("counter must be an integer")
                dims = json.dumps(metric.dimensions, sort_keys=True, separators=(",", ":"))
                if (metric.name, dims) in seen:
                    raise ValueError("duplicate metric")
                seen.add((metric.name, dims))
                self.conn.execute(
                    "INSERT OR IGNORE INTO series(source_id,name,kind,unit,dimensions) VALUES(?,?,?,?,?)",
                    (source, metric.name, metric.kind, metric.unit, dims),
                )
                series = self.conn.execute("SELECT * FROM series WHERE source_id=? AND name=? AND dimensions=?",
                                           (source, metric.name, dims)).fetchone()
                if (series["kind"], series["unit"]) != (metric.kind, metric.unit):
                    raise ValueError("metric definition changed")
                sid = series["id"]
                self.conn.execute("INSERT INTO samples VALUES(?,?,?,?,?,?)", (
                    sid, run_id, now, snapshot.epoch,
                    metric.value if type(metric.value) is int else None,
                    metric.value if type(metric.value) is float else None,
                ))
                if metric.kind != "counter":
                    continue
                old = self.conn.execute("SELECT * FROM counter_state WHERE series_id=?", (sid,)).fetchone()
                quality, delta, begin = "baseline", None, now
                if old:
                    begin = old["observed_at"]
                    if now <= begin:
                        quality = "clock_discontinuity"
                    elif old["epoch"] != snapshot.epoch or metric.value < old["value"]:
                        quality = "reset"
                    else:
                        delta = metric.value - old["value"]
                        missed = self.conn.execute('''SELECT 1 FROM runs r WHERE source_id=?
                            AND finished_at>? AND id<? AND NOT EXISTS
                            (SELECT 1 FROM samples p WHERE p.run_id=r.id AND p.series_id=?) LIMIT 1''',
                            (source, begin, run_id, sid)).fetchone()
                        quality = "gap" if missed or now - begin > poll * 3 else "ok"
                self.conn.execute("INSERT INTO intervals VALUES(?,?,?,?,?,?)", (sid, run_id, begin, now, delta, quality))
                if quality in {"reset", "clock_discontinuity"}:
                    self.conn.execute("INSERT INTO events(source_id,observed_at,code) VALUES(?,?,?)", (source, now, quality))
                self.conn.execute("INSERT OR REPLACE INTO counter_state VALUES(?,?,?,?)", (sid, now, snapshot.epoch, metric.value))

    def health(self, now: int):
        rows = self.conn.execute("""SELECT s.*, r.finished_at,r.status,r.error_code,r.warnings
            FROM sources s LEFT JOIN runs r ON r.id=(SELECT id FROM runs WHERE source_id=s.id ORDER BY id DESC LIMIT 1)
            WHERE s.enabled=1 ORDER BY s.id""")
        result = []
        for row in rows:
            item = dict(row)
            age = None if row["finished_at"] is None else now - row["finished_at"]
            item["age_ms"] = age
            item["stale"] = age is None or age < 0 or age > row["poll_ms"] * 3
            item["warnings"] = json.loads(row["warnings"] or "[]")
            result.append(item)
        return result

    def prune(self, cutoff: int):
        # Preserve baselines/cursors, so retention cannot create duplicate log ingestion.
        with self.conn:
            self.conn.execute("DELETE FROM samples WHERE observed_at<?", (cutoff,))
            self.conn.execute("DELETE FROM intervals WHERE end_at<?", (cutoff,))
            self.conn.execute("DELETE FROM log_records WHERE ingested_at<?", (cutoff,))
            self.conn.execute("DELETE FROM events WHERE observed_at<?", (cutoff,))
            self.conn.execute("""DELETE FROM runs WHERE finished_at<?
                AND id NOT IN (SELECT max(id) FROM runs GROUP BY source_id)
                AND id NOT IN (SELECT run_id FROM samples)
                AND id NOT IN (SELECT run_id FROM intervals)""", (cutoff,))
