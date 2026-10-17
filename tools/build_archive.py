"""Build a deterministic, allowlisted archive from the Git index paths."""
import argparse
import hashlib
import subprocess
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = (root / 'VERSION').read_text().strip()
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    allowed_roots = {'proxy_monitoring', 'tests', 'tools', 'docs', 'systemd', '.github'}
    allowed_files = {'.gitignore', '.gitattributes', '.gitleaks.toml', 'README.md', 'VERSION', 'pyproject.toml', 'config.example.json', 'requirements-mcp.lock'}
    selected = []
    for name in filter(None, paths):
        p = Path(name)
        if (name not in allowed_files and p.parts[0] not in allowed_roots) or any(
                part in {'__pycache__', 'AGENTS.md', 'state', '.venv'} for part in p.parts):
            raise ValueError('unexpected tracked path in release input')
        if p.suffix in {'.pyc', '.db', '.log'} or name.startswith('config.') and name != 'config.example.json':
            raise ValueError('runtime or private file in release input')
        selected.append(name)
    if 'README.md' not in selected or not any(p.startswith('proxy_monitoring/') for p in selected):
        raise ValueError('incomplete index')
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f'proxy-monitoring-{version}.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        for name in sorted(selected):
            info = zipfile.ZipInfo(f'proxy-monitoring-{version}/{name}', date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, (root / name).read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    with zipfile.ZipFile(archive) as check:
        assert check.testzip() is None
        assert len(check.namelist()) == len(selected)
    print(f'{archive}: {len(selected)} files, sha256={digest}')


if __name__ == '__main__':
    main()
