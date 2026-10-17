import argparse
import json
import sys
from pathlib import Path

from .config import load
from .model import CollectionError
from .queries import Reader
from .runner import now_ms, run


def main(argv=None):
    parser = argparse.ArgumentParser(description='Proxy telemetry collector (Linux runtime)')
    parser.add_argument('--config', type=Path, default=Path('config.json'))
    parser.add_argument('command', choices=['validate', 'collect', 'health', 'current', 'mcp'])
    parser.add_argument('--once', action='store_true', help='one collection cycle')
    parser.add_argument('--transport', choices=['stdio', 'streamable-http'], default='stdio')
    parser.add_argument('--host', choices=['127.0.0.1', '::1'], default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--public-origin')
    args = parser.parse_args(argv)
    try:
        cfg = load(args.config)
        if args.command == 'mcp':
            from .mcp_server import serve
            serve(Path(cfg['database']), args.transport, args.host, args.port, args.token_file, args.public_origin)
            return 0
        if args.command == 'validate':
            print(json.dumps({'valid': True, 'sources': len(cfg['sources'])}))
            return 0
        if args.command == 'collect':
            return run(cfg, args.once)
        reader = Reader(Path(cfg['database']))
        try:
            if args.command == 'health':
                data = reader.health(now_ms())
                print(json.dumps(data, ensure_ascii=False, indent=2))
                return int(any(row['stale'] or row['status'] != 'ok' for row in data))
            print(json.dumps(reader.current(now_ms()), ensure_ascii=False, indent=2))
        finally:
            reader.close()
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, CollectionError) else 'command_failed'
        print(json.dumps({'error': code, 'exception_type': type(exc).__name__}), file=sys.stderr)
        return 2
