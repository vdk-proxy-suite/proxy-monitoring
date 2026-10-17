# v0.3.2 — browser OAuth consent fix

Fix two browser-only failures after submitting the owner password:

- The login document's `Referrer-Policy: no-referrer` made native browser form
  submissions send `Origin: null`, which the server correctly rejected. The
  login GET now uses `strict-origin`: Origin remains usable and Referer contains
  only the origin, never the pending request identifier. Other responses,
  including the continuation page, retain `no-referrer`
- Browsers enforce CSP `form-action` across the POST redirect, with additional
  IPv6 host-source limitations. A successful/denied form POST now finishes with
  a small HTML continuation page: meta refresh performs a new navigation to the
  validated callback, with a visible link as fallback. CSP remains unchanged
  (`form-action 'self'`, scripts disabled); no callback or wildcard is added to it

Password validation, strict Origin checks, CSRF cookie/field binding, callback
allowlisting, PKCE and exact code-to-callback binding remain enabled. Existing
passwords, grants, clients and both databases remain compatible.

Author review covered login headers, escaping of the continuation URL, response
header composition and unchanged CSRF/Origin enforcement. Tests reject absent,
null and foreign Origin even with otherwise valid form data. Real browser tests
exercise HTTPS, IPv4 and IPv6 loopback callback success, denial, wrong password,
token exchange and authenticated MCP access, including absence of callback
Referer leakage. Browser requests use synthetic data and intercepted HTTPS;
this does not claim a live customer account login. CI installs Playwright only
as a test dependency; collector and MCP runtime dependencies are unchanged.

Release gates: Windows/Linux tests and browser smoke, compilation, author code
review, Linux collector/systemd/3proxy smoke, secret scans, public-address checks
and extracted archive manifest/checksum validation.

See [upgrade instructions](upgrade-0.3.2.md). Restart Authenticate after updating;
do not reuse an old consent page with its previous browser policy.
