# MCP v0.2.0

Official Python SDK 2.3.0. Transports: stdio (OS/SSH access), stateless Streamable
HTTP `/mcp` with JSON responses (mandatory bearer header, loopback binding).
All tools are read-only, non-destructive, idempotent and closed-world. There is no
SQL, shell, URL-fetch or service-control tool. Tool inputs are validated, output
has an outputSchema and structuredContent. Tool failures use safe machine codes.

## Common contract

`target`: optional object with `host_id`, `kind` (`host`, `telemt`, `3proxy`),
`source_ids`, `instance_ids` (instance names from inventory), `user`, `port`,
`include_disabled=false`. Filters are AND-combined. Source/instance lists are OR
within each list. Unknown explicit sources or metrics return an error, not zero.
The schema does not store route edges or a complete listener inventory; inventory
returns known sources and observed series, clearly advertising those limitations.

Historical calls take `start`, `end`: timezone-aware RFC3339 strings, interval
`[start,end)`, max 31 days. UTC is used internally; e.g. Moscow midnight can be
passed as `2026-10-17T00:00:00+03:00`. Timezone-free dates and natural-language
periods are rejected. Windows larger than available retention remain partial.
`metrics` is an optional list of 1–20 exact metric names from the catalog.

Responses: `schema_version`, `generated_at`, `data`, `quality` and, for history,
`requested_window`. Row-level warnings, observation time and source identity are
preserved. Top-level quality summarizes caveats rather than guaranteeing service
health. Empty observed series are explicitly flagged. No source secrets or paths
are returned; Telemt user labels are visible and must not contain credentials.

## Tools

| Tool | Additional arguments | Output |
|---|---|---|
| list_inventory | target | Sources and observed series, capabilities |
| get_metric_catalog | target | Types, units, accounting/time semantics |
| get_collection_health | target | Last run, source status, age, stale, safe errors |
| get_current | target, metrics, max_age_seconds=30 | Last committed values; does not scrape |
| get_summary | start, end, target, metrics | Per-series deltas or gauge sample statistics |
| get_timeseries | start, end, metrics, target, resolution_seconds=60 | Per-series buckets aligned to requested start |
| get_top_consumers | start, end, target, group_by, limit=10 | Observed byte ranking by Telemt user or 3proxy port |
| get_events | start, end, target, limit=50, cursor | Reset/truncation and collection error/partial events |
| get_anomalies | start, end, target | Deterministic observed-window findings with evidence |
| get_report_context | start, end, target, metrics, compare_previous=true | Summary, previous equal window, current collection health, findings, first 20 events |

## Accounting rules

- Counter summaries include only intervals fully inside the requested window.
  Crossing intervals are excluded with `boundary_interval_excluded`. A zero is
  returned only for a known observed zero, never for absent intervals
- `gap` can retain an observed total but contributes no continuous coverage;
  it is not distributed among minute buckets. Rates require complete good coverage
- Overlapping intervals after clock changes invalidate the total instead of
  counting overlapping measurements twice. Reset/baseline deltas remain unknown
- Gauges expose `sample_mean`, min/max/last and sample_count. These are observed
  samples, not continuous maxima or time-weighted averages; coverage is null
- Log metrics: `log.events`, `log.error_events`, `log.upload_bytes`,
  `log.download_bytes`. They are event-time sums, not live traffic, accepted TCP
  or authenticated sessions. Unknown byte semantics yield null; no log rows do
  not prove zero traffic or complete collection coverage
- Top consumers are independent `(source,user)` or `(source,port)` rows. No global
  total is produced. Telemt process totals cannot be allocated to a port, and
  3proxy usernames were not stored by v0.1.0, so these unsupported requests fail
- Summaries remain per-series. Filtering by port does not silently assign
  instance-wide Telemt metrics to that port
- Findings v1: reset/gap/clock/overlap data-quality evidence and an upstream failure
  ratio >=10% over >=20 observed success/fail outcomes with complete coverage.
  No causal diagnosis is asserted. Lifecycle is `not_persisted`, state `observed`;
  no seasonal baseline, active/resolved lifecycle or restart automation
- A report's collection_health is current at generated_at, while summary/findings
  concern the requested history. Prior-period values are returned separately;
  incomplete periods are not presented as a reliable percentage comparison

## Limits and read isolation

One SQLite `mode=ro`, `query_only` connection and read transaction per tool call;
no writer initialization or migration. Schema version 1 remains supported.
Max 100 sources, 200 series, 2000 timeseries points, 50,000 fetched database rows,
4-second query budget, 128 KiB structured payload (text compatibility duplication
can make the MCP wire response larger), HTTP request body 64 KiB.
Limits return errors with guidance rather than silently truncating.

Events use keyset cursors bound to filters/window and high-water IDs, expiring
after 10 minutes. Concurrent new inserts are excluded from later pages; retention
can still remove old rows. A cursor is not an authorization grant. Top-consumer
responses report whether the requested top-N omitted other rows.

Typical error codes: `target_not_found`, `metric_not_available_for_target`,
`invalid_window_max_31_days`, `window_in_future`, `query_timeout`,
`query_too_large_narrow_window_or_target`, `too_many_series_narrow_target`,
`too_many_points_increase_resolution`, `response_too_large_narrow_target`,
`invalid_or_expired_cursor`, `database_unavailable`, `unsupported_schema`.

## Example call

```json
{
  "name": "get_summary",
  "arguments": {
    "target": {"kind": "telemt", "instance_ids": ["direct"]},
    "start": "2026-10-17T10:00:00+03:00",
    "end": "2026-10-17T11:00:00+03:00",
    "metrics": ["traffic.client_upload_bytes_total", "traffic.client_download_bytes_total"]
  }
}
```

Protocol/reference sources: [official SDK](https://github.com/modelcontextprotocol/python-sdk),
[MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
OAuth is available through `--oauth-config` in v0.3.0; see [oauth.md](oauth.md).
The static bearer endpoint remains a separate mode without OAuth discovery.
Public HTTPS/DNS deployment is an operator step, not performed by the collector.
