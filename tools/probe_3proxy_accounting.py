"""Verify real 3proxy monitor_v1 directions and logdump segment sums on loopback."""
import argparse
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from proxy_monitoring.logs import parse_line

FORMAT = '-|+_Gv1|%t|%.|%D|%N|%p|%E|%U|%C|%c|%R|%r|%Q|%q|%n|%O|%I|%h|%T'


def probe(binary, logdump):
    upload, download = b'u' * 513, b'd' * 2049
    target = socket.socket()
    target.bind(('127.0.0.1', 0))
    target.listen()
    target.settimeout(0.2)
    stopped = threading.Event()
    failures = []

    def backend():
        try:
            while not stopped.is_set():
                try:
                    conn, _ = target.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(3)
                    data = b''
                    while len(data) < len(upload):
                        block = conn.recv(1024)
                        if not block:
                            break
                        data += block
                    if not data:  # Readiness probe; no accounting payload.
                        continue
                    if data != upload:
                        raise AssertionError('backend upload mismatch')
                    for offset in range(0, len(download), 127):
                        conn.sendall(download[offset:offset+127])
                        time.sleep(0.005)
        except BaseException as exc:
            failures.append(type(exc).__name__)

    thread = threading.Thread(target=backend)
    thread.start()
    proc = None
    try:
        with tempfile.TemporaryDirectory(prefix='proxy-accounting-') as temp:
            base = Path(temp)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            config = base / 'proxy.cfg'
            log = base / 'traffic.log'
            config.write_text(f'log {log}\nlogformat "{FORMAT}"\nauth none\n'
                              + ('logdump 64 64\n' if logdump else '')
                              + f'tcppm -i127.0.0.1 {port} 127.0.0.1 {target.getsockname()[1]}\n')
            proc = subprocess.Popen([str(binary), str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for attempt in range(100):
                if proc.poll() is not None:
                    raise AssertionError('3proxy exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError('3proxy startup timeout')
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                for offset in range(0, len(upload), 73):
                    client.sendall(upload[offset:offset+73])
                    time.sleep(0.005)
                received = b''
                while len(received) < len(download):
                    block = client.recv(4096)
                    if not block:
                        raise AssertionError('premature EOF')
                    received += block
                assert received == download
            for _ in range(100):
                rows = [parse_line(line) for line in log.read_text(errors='replace').splitlines()]
                up, down = sum(r['bytes_up'] for r in rows), sum(r['bytes_down'] for r in rows)
                if up == len(upload) and down == len(download):
                    break
                time.sleep(0.03)
            else:
                raise AssertionError(f'accounting mismatch: upload={up}, download={down}')
            nonempty = [r for r in rows if r['bytes_up'] or r['bytes_down']]
            assert len(nonempty) > 1 if logdump else len(nonempty) == 1
            assert not failures, failures
            print(f'logdump={logdump}: upload={up}, download={down}, segments={len(nonempty)}: OK')
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            proc = None
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        stopped.set()
        thread.join(timeout=4)
        target.close()
        assert not thread.is_alive(), 'backend thread left running'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    for enabled in (False, True):
        probe(args.binary.resolve(), enabled)
