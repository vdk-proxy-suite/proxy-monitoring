import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

ID = re.compile(r"^[a-zA-Z0-9_.-]{1,80}$")
UNIT = re.compile(r"^[a-zA-Z0-9_@.:-]+\.service$")


def load(path: Path) -> dict:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict) or not ID.fullmatch(cfg.get("host_id", "")):
        raise ValueError("invalid host_id")
    cfg.setdefault("poll_seconds", 15)
    cfg.setdefault("retention_days", 7)
    if not 1 <= cfg["poll_seconds"] <= 3600 or not 1 <= cfg["retention_days"] <= 365:
        raise ValueError("invalid interval or retention")
    database = Path(cfg.get("database", "state/monitor.db"))
    cfg["database"] = str(database if database.is_absolute() else path.resolve().parent / database)
    sources = cfg.get("sources", [])
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise ValueError("sources must contain 1..100 entries")
    ids = set()
    for source in sources:
        ident = source.get("id", "")
        if not ID.fullmatch(ident) or ident in ids:
            raise ValueError("invalid or duplicate source id")
        ids.add(ident)
        if source.get("kind") not in {"host", "telemt", "3proxy"}:
            raise ValueError("unsupported source kind")
        if source["kind"] != "host":
            if not ID.fullmatch(source.get("instance", "")) or not UNIT.fullmatch(source.get("unit", "")):
                raise ValueError("invalid instance or systemd unit")
        if source["kind"] == "telemt":
            url = urlsplit(source.get("metrics_url", ""))
            if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}
                    or url.username or url.password or url.query or url.fragment or url.path != "/metrics"):
                raise ValueError("metrics_url must be a literal loopback HTTP /metrics endpoint")
            if not url.port:
                raise ValueError("metrics_url requires a port")
        if source["kind"] == "3proxy":
            log_glob = source.get("log_glob", "")
            if not (Path(log_glob).is_absolute() or PurePosixPath(log_glob).is_absolute()):
                raise ValueError("log_glob must be absolute")
            if source.get("byte_semantics", "unknown") not in {"unknown", "delta"}:
                raise ValueError("unsupported byte semantics")
            if source.get("log_timezone", "UTC") != "UTC":
                raise ValueError("only UTC legacy logs are supported")
        ports = source.get("ports", [])
        if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise ValueError("invalid ports")
        if source["kind"] == "3proxy" and not ports:
            raise ValueError("3proxy requires an explicit port allowlist")
    return cfg
