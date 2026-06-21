# Security Policy

## Status

**socksflare is experimental software.** It has not undergone a formal security audit. Use it with care in production environments.

## Known Limitation: URL Allowlisting Required

socksflare's `proxy.fetch` accepts a destination URL and opens a SOCKS5-tunnelled connection to it.  
**Do not pass untrusted or user-controlled URLs** to `proxy.fetch` without an explicit allowlist.  
Failing to do so may allow users to reach arbitrary internal or external hosts through your proxy.

## Reporting Vulnerabilities

If you discover a security vulnerability, please open a GitHub issue in the [socksflare repository](https://github.com/EithonX/socksflare/issues).

If the issue includes sensitive exploit details, keep the public issue brief and mention that you can provide reproduction details privately if needed.

Please include:
- what component is affected
- what behavior you expected
- what happened instead
- minimal reproduction steps when safe to share
