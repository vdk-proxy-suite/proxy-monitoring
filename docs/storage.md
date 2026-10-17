# SQLite schema v1

Authoritative DDL: `proxy_monitoring/storage.py`, `SCHEMA`. `PRAGMA user_version=1`.
Foreign nonempty databases and unknown schema versions are rejected. This schema
is a deliberate first subset of the larger monitoring design, not a bot DB migration.

| Table | Key | Purpose |
|---|---|---|
| sources | id | Host, kind, instance, unit, configured cadence, config signature, enabled flag |
| runs | id | Per-source acquisition status, start/end UTC ms, safe error code and warnings |
| series | id; unique source_id/name/dimensions | Metric definition and canonical JSON labels |
| samples | series_id/run_id | Observed value and epoch; exactly one integer/real field |
| intervals | series_id/run_id | Counter delta over start/end, quality and nullable delta |
| counter_state | series_id | Last committed baseline, preserved across retention |
| cursors | source_id/file_key | File generation, committed byte offset and prefix fingerprint |
| log_records | id; unique source_id/generation/offset | Sanitized log event; no full client or destination details |
| events | id | Reset, clock discontinuity and detected log truncation events |

Each snapshot/run and all its series samples, deltas and baselines commit together.
Each log batch/run, cursor advancement and normalized records commit together.
Acquisition failures create an error run without replacing successful metric values.
Readers use mode=ro and query_only; they never initialize or migrate the database.

Counter qualities: `baseline`, `ok`, `gap`, `reset`, `clock_discontinuity`.
Only `ok` and `gap` carry delta. `gap` is a total over the observed interval,
not evidence of uniform traffic or uninterrupted service. A decrease or new epoch
discards the cross-reset delta; the pre-restart tail remains unknown.
Telemetry disabled/reset without a process restart can still be undetectable if
the next counter exceeds its previous value; no collector can infer this from
two samples alone.

Log qualities: `log_event_time`, `unknown_byte_semantics` (NULL bytes).
Rows are observations, not sessions. No global traffic SUM is exposed because
Telemt-to-3proxy chains can account for the same payload at multiple layers.

Future migrations must preserve these semantics and data, adding listeners,
route inventory, validated metric mappings and rollups separately. Do not reinterpret
old log rows as completed connections or manufacture values for absent metrics.
