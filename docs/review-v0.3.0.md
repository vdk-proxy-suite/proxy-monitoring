# v0.3.0 implementation review

Review scope: OAuth configuration, durable grant storage, HTTP endpoints,
MCP transport integration, operator CLI, deployment examples and regression tests.
This is an implementation review by the author, not an independent security audit.

## Access and authorization

- MCP uses the official SDK token verifier and mandatory `monitor:read` scope.
  The verifier reads only this instance's local opaque-token store and checks
  expiry, revocation and exact resource; SDK resource validation is also enabled
- Registration is limited to operator-allowlisted HTTPS callbacks, with no
  wildcard, CIMD fetch, userinfo or fragment. Removal from the allowlist takes
  effect for new authorizations of previously registered clients
- Owner approval shows the client-supplied name, exact return address, full
  telemetry access and renewal lifetime. Approval is bound to a random browser
  cookie and CSRF field, checks Origin, requires a password and expires
- The owner password is never supplied on CLI arguments or in configuration.
  Initialization refuses overwrite and writes mode 0600; Windows ACL handling
  is explicitly an operator prerequisite

## Replay, persistence and bounds

- SQLite serializes code exchange and refresh rotation. Replay invalidates the
  authorization; tests exercise concurrent exchanges and refresh reuse
- Approval and code creation are atomic relative to administrative revocation,
  including when revocation happens during password hashing
- Refresh scope can only narrow. Original access tokens retain their original
  scope until expiration or revocation. Rotation cannot extend absolute lifetime
- Consumed refresh hashes remain until grant expiration so pruning does not
  disable replay detection. Expired records are pruned during authorization
- A SQLite application identifier/version prevents accidental mutation of
  another database. MCP additionally rejects using the telemetry path for auth
- Body/query bounds, fixed-key rate buckets, registration/pending caps and
  sanitized endpoint errors limit abuse. Public reverse proxy limits remain
  necessary; the application is deliberately loopback-only

## Regression and deployment boundary

- Collector code and telemetry schema are unchanged. Existing stdio and bearer
  tests remain in the complete suite. OAuth cannot silently fall back to bearer
- The OAuth service has a separate writable StateDirectory and a read-only
  telemetry directory. Authentication state and owner hash are excluded from Git
- Tests cover discovery, the full official SDK OAuth client flow, HTTP MCP in a
  separate process, rejection of wrong scope/resource/expiry, callback attacks,
  CSRF, denial, wrong password, rate limits, malformed requests and body bounds
- Tests use synthetic telemetry and passwords. Child servers are terminated and
  waited for; captured stderr is checked for password/access/refresh leakage

One legacy urllib fixture intermittently receives Windows connection resets on
the development workstation, also when run independently. It has not been
skipped or weakened. Clean Windows CI is the release gate alongside Ubuntu CI.
The release does not claim a live ChatGPT account/TLS deployment test; that follows
DNS, HTTPS and callback configuration on the target host.
