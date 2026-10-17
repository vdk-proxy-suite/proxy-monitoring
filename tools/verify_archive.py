"""Check release manifest, bytes, modes and checksum; scan or test isolated contents."""
import argparse
import hashlib
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('--scan', action='store_true')
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    expected = set(filter(None, subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')))
    checksum = args.archive.with_suffix('.zip.sha256').read_text().split()[0]
    assert hashlib.sha256(args.archive.read_bytes()).hexdigest() == checksum
    prefix = 'proxy-monitoring-' + (root / 'VERSION').read_text().strip() + '/'
    with tempfile.TemporaryDirectory(prefix='proxy-monitoring-release-') as temp:
        with zipfile.ZipFile(args.archive) as archive:
            assert archive.testzip() is None
            assert len(archive.namelist()) == len(expected)
            assert {name.removeprefix(prefix) for name in archive.namelist()} == expected
            for info in archive.infolist():
                assert info.filename.startswith(prefix)
                assert info.external_attr >> 16 == 0o100644
                relative = info.filename.removeprefix(prefix)
                assert archive.read(info) == (root / relative).read_bytes()
            archive.extractall(temp)
        extracted = Path(temp) / prefix.rstrip('/')
        if args.scan:
            subprocess.run(['gitleaks', 'dir', '--redact', '--no-banner', str(extracted)], check=True)
        if args.test:
            subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'], cwd=extracted, check=True)
            subprocess.run([sys.executable, 'tools/smoke_linux.py'], cwd=extracted, check=True)
            subprocess.run(['systemd-analyze', 'verify', 'systemd/proxy-monitoring.service'], cwd=extracted, check=True)
    print('Archive manifest, source bytes, 0644 modes and SHA256 verified; extracted temporary directory removed')


if __name__ == '__main__':
    main()
