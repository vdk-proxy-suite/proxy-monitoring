"""Reject deployment URL hosts and non-example IPv4 literals in public files.

Complements secret scanning and manual privacy review; it is not a general
detector for arbitrary hostnames, encoded addresses or identifying prose.
"""
import ipaddress
import re
import subprocess
from pathlib import Path


REFERENCES = {'github.com', 'codeload.github.com', 'developers.openai.com',
              'modelcontextprotocol.io', 'chatgpt.com'}
EXAMPLES = {'example.com', 'example.net', 'example.org', 'localhost', '127.1', '2130706433'}
URL_HOST = re.compile(r'https?://([a-zA-Z0-9][a-zA-Z0-9.-]*)(?=[:/\s\'"`])')
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
DOC_NETS = [ipaddress.ip_network(net) for net in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]


def allowed_ip(value):
    ip = ipaddress.ip_address(value)
    return ip.is_loopback or value in {'0.0.0.0', '10.0.0.1'} or any(ip in net for net in DOC_NETS)


def check(root, names):
    errors = []
    for name in names:
        for number, line in enumerate((root / name).read_text(encoding='utf-8').splitlines(), 1):
            bad = False
            for value in IPV4.findall(line):
                try:
                    bad |= not allowed_ip(value)
                except ValueError:
                    pass
            for host in URL_HOST.findall(line):
                try:
                    allowed = allowed_ip(host)
                except ValueError:
                    allowed = (host in REFERENCES or host in EXAMPLES
                               or host.endswith(('.example', '.invalid', '.test'))
                               or any(host.endswith('.' + domain) for domain in ('example.com', 'example.net', 'example.org')))
                bad |= not allowed
            if bad:
                errors.append(f'{name}:{number}: non-example address; value redacted')
    if errors:
        raise ValueError('\n'.join(errors))
    print(f'Public URL/IPv4 examples checked: {len(names)} files')


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    names = list(filter(None, subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')))
    check(root, names)
