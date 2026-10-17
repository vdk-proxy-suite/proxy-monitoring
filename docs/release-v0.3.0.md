# v0.3.0 — OAuth for remote MCP

Remote MCP clients can now discover the authorization server, register a public
client and request read-only access through an owner login and explicit consent.
The flow uses Authorization Code with S256 PKCE, exact redirect allowlists,
resource binding and issuer identification. Access tokens expire after 10 minutes;
optional rotating refresh tokens have a fixed 30-day authorization lifetime.

OAuth state lives in a separate private SQLite database. Credentials are stored
as SHA-256 digests, the owner password uses salted scrypt, and token/code exchanges
are atomic. Reuse revokes the affected authorization. `oauth-revoke-all` revokes
all grants and pending authorizations. Authentication endpoints have persistent
rate limits, bounded bodies and sanitized errors; the consent page uses a bound
Secure/HttpOnly cookie, CSRF protection and restrictive browser headers.

All ten MCP tools remain read-only and declare `monitor:read` in OAuth mode.
The collector schema and existing stdio/static-bearer modes remain compatible.
No proxy settings or production deployment are changed by this release.

See [OAuth deployment](oauth.md) for configuration, owner initialization, systemd,
HTTPS reverse proxy, client callbacks and revocation. A public HTTPS domain and
the exact client callback are deployment prerequisites. This release supports a
single owner and public-client DCR; it does not provide OIDC, multi-user SSO or
CIMD. Live connection through a particular ChatGPT account is a deployment check.

Validation includes unit/integration tests, official MCP SDK OAuth discovery/DCR/
PKCE interoperability, a real CLI HTTP subprocess, persistence/concurrency/replay
tests, Linux/Windows CI, compilation, Linux collector smoke, real 3proxy byte
accounting probe, code review and secret scans of source/history/release archive.
