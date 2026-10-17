"""Deployment configuration and owner password hashing for OAuth."""
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


def password_hash(password: str) -> str:
    if not 16 <= len(password) <= 1024:
        raise ValueError('owner_password_length_must_be_16_to_1024')
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024)
    return 'scrypt-v1:' + salt.hex() + ':' + key.hex()


def verify_password(password: str, encoded: str) -> bool:
    if not isinstance(password, str) or not 16 <= len(password) <= 1024:
        return False
    try:
        algorithm, salt, expected = encoded.split(':')
        if algorithm != 'scrypt-v1' or len(salt) != 32 or len(expected) != 128:
            return False
        salt_bytes, expected_bytes = bytes.fromhex(salt), bytes.fromhex(expected)
        key = hashlib.scrypt(password.encode('utf-8'), salt=salt_bytes, n=32768, r=8, p=1,
                             maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(key, expected_bytes)
    except (ValueError, UnicodeError):
        return False


def https_url(value: str, *, origin=False) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError('invalid_oauth_url')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or '\\' in value
            or (origin and (parsed.path or parsed.query))):
        raise ValueError('oauth_requires_https_url')
    # Validate the port too; urlsplit alone accepts non-numeric/out-of-range ports.
    parsed.port
    return value


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    database: Path
    owner_password_file: Path
    redirect_uris: tuple[str, ...]

    @property
    def resource(self):
        return self.issuer + '/mcp'

    @classmethod
    def load(cls, path: Path):
        raw = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict) or set(raw) != {'issuer', 'database', 'owner_password_file', 'redirect_uris'}:
            raise ValueError('invalid_oauth_config_keys')
        issuer = https_url(raw['issuer'], origin=True)
        redirects = raw['redirect_uris']
        if not isinstance(redirects, list) or not 1 <= len(redirects) <= 20:
            raise ValueError('oauth_redirect_allowlist_required')
        redirects = tuple(https_url(uri) for uri in redirects)
        reserved = {'code', 'state', 'iss', 'error', 'error_description', 'error_uri'}
        if any(reserved.intersection(key for key, value in parse_qsl(urlsplit(uri).query)) for uri in redirects):
            raise ValueError('oauth_redirect_contains_reserved_parameter')
        if len(set(redirects)) != len(redirects):
            raise ValueError('duplicate_oauth_redirect')
        paths = []
        for key in ('database', 'owner_password_file'):
            if not isinstance(raw[key], str) or not raw[key]:
                raise ValueError('invalid_oauth_path')
            paths.append((path.parent / raw[key]).resolve())
        if paths[0] == paths[1]:
            raise ValueError('oauth_paths_must_differ')
        return cls(issuer, *paths, redirects)

    def read_owner_hash(self):
        if os.name != 'nt' and self.owner_password_file.stat().st_mode & 0o077:
            raise ValueError('owner_password_file_must_be_private')
        if self.owner_password_file.stat().st_size > 256:
            raise ValueError('invalid_owner_password_hash')
        encoded = self.owner_password_file.read_text(encoding='ascii').strip()
        parts = encoded.split(':')
        if (len(parts) != 3 or parts[0] != 'scrypt-v1' or len(parts[1]) != 32 or len(parts[2]) != 128):
            raise ValueError('invalid_owner_password_hash')
        bytes.fromhex(parts[1])
        bytes.fromhex(parts[2])
        return encoded
