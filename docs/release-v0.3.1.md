# v0.3.1 — OAuth loopback callbacks

Fix native-client OAuth registration and authorization, including Codex callbacks
such as `http://127.0.0.1:<port>/callback`. v0.3.0 accepted HTTPS callbacks only.

HTTP callbacks are restricted to literal `127.0.0.1` and `[::1]`. The operator
must allowlist the exact host, path and query. Only the port can vary during
registration/authorization, as required by RFC 8252. Code exchange still requires
the exact actual callback, including its port. HTTPS callbacks remain exact-match;
MCP issuer and resource remain HTTPS. No localhost DNS, arbitrary HTTP hosts,
userinfo, fragments, prefix matching or wildcard redirects are introduced.

The example adds `http://127.0.0.1/callback`. Existing deployment configuration is
preserved; add that entry explicitly after upgrading. No collector/auth DB
migrations, password reset, token reset or log replay are required.

Validation covers IPv4/IPv6 OAuth flow, official SDK loopback flow, changing
listener ports, wrong-port code exchange, host/path/query attacks, existing HTTPS
OAuth and collector regression tests. Release gates include Windows/Linux CI,
compilation, implementation review, secret scans and verified ZIP/SHA256.

Review: callback parsing and matching are shared by config, registration and
authorization. The exception applies only to validated HTTP literal loopback;
the existing grant store's exact URI binding is unchanged. Author review, not an
independent security audit. See [upgrade instructions](upgrade-0.3.1.md).
