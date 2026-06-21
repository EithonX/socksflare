# Socksflare

[![CI](https://github.com/EithonX/socksflare/actions/workflows/ci.yml/badge.svg)](https://github.com/EithonX/socksflare/actions/workflows/ci.yml)

**SOCKS5 proxy client for Cloudflare Workers with TLS via Rustls WASM.**

Route HTTP(S) requests through a SOCKS5 proxy from the Cloudflare Edge — no external relay, no `startTls()`, no JS TLS fallback. TLS is handled entirely by [Rustls](https://github.com/rustls/rustls) compiled to WebAssembly: memory-safe, constant-time, production-grade.

> [!WARNING]
> **This project is experimental and provided as-is.** It has not undergone a formal security audit. The TLS implementation relies on Rustls WASM, which may have a different fingerprint than standard browsers. **Use at your own risk.** The author(s) make no guarantees regarding security, reliability, or fitness for any particular purpose.

> [!CAUTION]
> **Disclaimer:** This software is intended for legitimate use cases such as privacy research, bypassing geo-restrictions on your own content, and building developer tools. **The author(s) are not responsible for how this software is used.** By using this software, you agree that you are solely responsible for ensuring your usage complies with all applicable laws and the terms of service of any third-party services you interact with.

> [!IMPORTANT]
> **SSRF Warning:** This library is an open proxy — it fetches any URL you pass to `proxy.fetch()`. **Never pass user-controlled URLs directly** without validating/allowlisting the target hostname first. An attacker could use your Worker to reach internal networks, cloud metadata endpoints (`169.254.169.254`), or localhost services.

## Why not `startTls()`?

Cloudflare Workers' `startTls()` enforces domain-fronting restrictions on the Edge, making it unusable for proxied HTTPS connections where the SNI hostname differs from the proxy hostname. This library bypasses that limitation entirely by performing TLS in userspace via Rustls WASM.

## Installation

```bash
npm install socksflare
```

## TypeScript

Socksflare ships with TypeScript declarations:

```ts
import { Socks5Client, type SocksflareFetchOptions } from 'socksflare';

const proxy = new Socks5Client({
  host: '127.0.0.1',
  port: 1080,
});

const options: SocksflareFetchOptions = {
  httpVersion: '1.1',
  timeoutMs: 15000,
};

const res = await proxy.fetch('https://example.com', {}, options);
```

## Testing

```bash
npm run check
npm test
npm run test:unit
npm run test:integration
npm run pack:dry
```

Integration tests use local mock HTTP and SOCKS5 servers only. No external network, Cloudflare credentials, or third-party SOCKS proxy required.

Local TLS and HTTP/2 integration coverage now runs against local HTTPS and `h2` origins over the SOCKS tunnel. In this repository snapshot, that harness uses a Node TLS shim for the test-only handshake path because the Rust/WASM rebuild toolchain is not available in the checked-in environment; the public Rustls-facing API and queue/backpressure logic remain covered by unit tests.

## Required: `wrangler.toml` Setup

Any Worker using this library **must** include the following rule in their `wrangler.toml` so the WASM binary is bundled correctly:

```toml
[[rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
fallback = true
fallthrough = true
```

## Quick Start

```javascript
import { Socks5Client } from 'socksflare';

// ⚠️ Always validate target hostnames to prevent SSRF
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

export default {
  async fetch(request, env) {
    const proxy = new Socks5Client({
      host: env.SOCKS5_HOST,
      port: env.SOCKS5_PORT,
      username: env.SOCKS5_USER,
      password: env.SOCKS5_PASS,
    });

    const raw = new URL(request.url).searchParams.get('url');
    if (!raw) return new Response('Missing ?url=', { status: 400 });

    const target = new URL(raw);
    if (!ALLOWED_HOSTS.has(target.hostname)) {
      return new Response('Hostname not allowed', { status: 403 });
    }

    // Fetch-like helper — routes through SOCKS5 + Rustls WASM TLS
    return proxy.fetch(target, {}, { timeoutMs: 15000 });
  },
};
```

## API

### `new Socks5Client(config)`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `string` | *required* | SOCKS5 proxy hostname or IP |
| `port` | `number` | `1080` | SOCKS5 proxy port |
| `username` | `string` | — | Auth username (also accepts `user`) |
| `password` | `string` | — | Auth password (also accepts `pass`) |

### `client.fetch(input, init?, options?)`

Fetch-like helper for routing requests through the SOCKS5 proxy with automatic TLS for HTTPS URLs. It does not yet match every native `fetch()` behavior.

```javascript
const response = await proxy.fetch('https://example.com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ key: 'value' }),
});
```

**Options:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `options.tlsHostname` | `string` | Override SNI hostname for TLS |
| `options.httpVersion` | `'1.1' \| 'auto' \| '2'` | HTTPS strategy: force HTTP/1.1, try HTTP/2 then fall back only if ALPN does not negotiate `h2`, or require HTTP/2 |
| `options.timeoutMs` | `number` | Abort after this many milliseconds (uses `AbortSignal.timeout()` when available, with fallback timer wiring otherwise) |
| `options.extraRootCertificates` | `Array<ArrayBuffer \| Uint8Array>` | Advanced/testing-only extra DER root certificates for local TLS or private PKI (requires a regenerated `rust-tls-wasm/pkg/` artifact) |

`tlsHostname` is advanced-only. Overriding it can intentionally create an SNI/Host mismatch, which some targets reject and some security tools flag.

**Request body support:** `string`, `Uint8Array`, `ArrayBuffer`, typed-array views, `URLSearchParams`, `Blob`, and `ReadableStream`. `FormData` is not supported yet. `GET` and `HEAD` request bodies are rejected.

**HTTP/2:** experimental single-stream implementation. Keep `httpVersion: '1.1'` for release-critical traffic until local SOCKS5/TLS/H2 integration tests pass.

### `client.connect(targetHost, targetPort, options?)`

Low-level raw tunnel for non-HTTP protocols (SMTP, custom protocols, etc.).

> [!CAUTION]
> SOCKS5 username/password authentication is sent in plaintext to the SOCKS proxy (per RFC 1929). Use only with a trusted, local, or otherwise protected proxy hop.

```javascript
const { readable, writable } = await proxy.connect('smtp.example.com', 465, {
  enableTls: true,
});

const writer = writable.getWriter();
await writer.write(new TextEncoder().encode('EHLO example.com\r\n'));
```

**Options:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `options.enableTls` | `boolean` | `false` | Upgrade tunnel with TLS via Rustls WASM |
| `options.tlsHostname` | `string` | `targetHost` | SNI hostname |
| `options.alpnProtocols` | `string[]` | — | Optional ALPN protocols (for example `['h2', 'http/1.1']`) |
| `options.signal` | `AbortSignal` | — | Abort signal for connection / handshake teardown |
| `options.timeoutMs` | `number` | — | Abort after this many milliseconds |
| `options.extraRootCertificates` | `Array<ArrayBuffer \| Uint8Array>` | — | Advanced/testing-only extra DER root certificates for local TLS or private PKI (requires a regenerated `rust-tls-wasm/pkg/` artifact) |

### Low-level Exports

For advanced usage, the underlying functions are also exported:

```javascript
import { proxyFetch, socks5Connect } from 'socksflare';
```

## Building WASM from Source

The `rust-tls-wasm/pkg/` directory ships with a pre-built WASM binary. To rebuild from source:

**Prerequisites:** [Rust](https://rustup.rs/), [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/), LLVM/clang

```bash
cd rust-tls-wasm

# Linux / macOS
wasm-pack build --target web

# Windows (PowerShell) — set CC for ring's C compilation
# $env:CC = "C:\Program Files\LLVM\bin\clang.exe"
# $env:CC_wasm32_unknown_unknown = $env:CC
# wasm-pack build --target web
```

### Building WASM without installing Rust locally

If you do not want to install Rust/wasm-pack locally, run the manual GitHub Actions workflow:

1. Go to GitHub → Actions → Build WASM pkg.
2. Click “Run workflow”.
3. Wait for it to finish.
4. Download the `rust-tls-wasm-pkg` artifact.
5. Replace the local `rust-tls-wasm/pkg/` directory with the artifact contents.
6. Run `npm run release:check`.
7. Commit the regenerated `rust-tls-wasm/pkg/` files manually.

## Project Structure

```
socksflare/
├── .github/
│   └── workflows/
│       └── ci.yml
├── scripts/
│   └── check-syntax.mjs
├── src/
│   ├── index.js             ← Main export: Socks5Client class
│   ├── socks5-client.js     ← SOCKS5 handshake engine
│   ├── proxy-fetch.js       ← Fetch dispatcher + HTTP/1.1 path
│   ├── proxy-fetch-http2.js ← Experimental single-stream HTTP/2 path
│   └── wasm-tls.js          ← JS bridge to Rustls WASM
├── tests/
│   ├── protocol.test.mjs    ← Protocol/unit coverage
│   ├── integration.test.mjs ← Local SOCKS5 + HTTP integration harness
│   └── types-smoke.test.mjs ← Package metadata smoke coverage
├── rust-tls-wasm/
│   ├── src/lib.rs           ← Rustls WasmTlsClient
│   ├── Cargo.toml           ← rustls 0.23, ring 0.17, wasm-bindgen 0.2
│   ├── Cargo.lock           ← Reproducible WASM dependency lockfile
│   └── pkg/                 ← Pre-built WASM output (committed)
├── example/
│   └── worker.js            ← Demo worker
├── index.d.ts
├── package.json
├── LICENSE                  ← GPL-3.0-or-later
└── README.md
```

## Known Limitations

- **TLS Fingerprint (JA3/JA4):** Rustls produces a different TLS ClientHello than Chrome/Firefox. Sites with aggressive bot detection may flag this. This is inherent to using a non-browser TLS stack.
- **Accept-Encoding:** Requests are sent with `Accept-Encoding: identity` to avoid decompression issues inside Workers. This is slightly unusual but not flagged by any known WAF.
- **HTTP/2:** Experimental and single-stream. Local SOCKS + TLS + ALPN integration tests now exercise the H2 path, but the committed test harness still uses a Node TLS shim rather than a rebuilt Rustls WASM artifact.
- **FormData:** Request bodies using `FormData` are rejected for now.
- **HTTP/3 Not Implemented:** HTTP/3 (QUIC/UDP) is not implemented in this library as Cloudflare Workers limit arbitrary outboard UDP.

## Contributing

This project was built by someone still learning — contributions, bug fixes, and improvements are very welcome! If you know more about TLS fingerprinting, Rust/WASM optimization, or Cloudflare Workers internals, please open a PR or issue. Every bit helps.

**Areas where help is especially needed:**

- Mimicking real browser TLS fingerprints (JA3/JA4 spoofing in Rustls)
- HTTP/3 support over SOCKS5
- Better error handling and retry logic
- Performance benchmarks and optimization

## Credits

- **[Rustls](https://github.com/rustls/rustls)** — The TLS engine powering the WASM module
- **[ring](https://github.com/briansmith/ring)** — Cryptographic primitives used by Rustls
- **[webpki-roots](https://github.com/rustls/webpki-roots)** — Mozilla's root CA certificates
- **[wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)** — Rust ↔ JavaScript WASM bridge
- Built with ❤️ by [EithonX](https://github.com/EithonX)

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

**This means:** You can use, modify, and distribute this software freely, but any derivative work must also be released under GPL-3.0. See [LICENSE](LICENSE) for full terms.
