# Socksflare

**SOCKS5 proxy client for Cloudflare Workers with TLS 1.3 via Rustls WASM.**

Route any HTTP(S) request through a SOCKS5 proxy from the Cloudflare Edge — no external relay, no `startTls()`, no JS TLS fallback. TLS is handled entirely by [Rustls](https://github.com/rustls/rustls) compiled to WebAssembly: memory-safe, constant-time, production-grade.

## Why not `startTls()`?

Cloudflare Workers' `startTls()` enforces domain-fronting restrictions on the Edge, making it unusable for proxied HTTPS connections where the SNI hostname differs from the proxy hostname. This library bypasses that limitation entirely by performing the TLS 1.3 handshake in userspace via Rustls WASM.

## Installation

```bash
npm install socksflare
```

## Required: `wrangler.toml` Setup

Any Worker using this library **must** include the following rule in their `wrangler.toml` so the WASM binary is bundled correctly:

```toml
[[rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
fallback = true
```

## Quick Start

```javascript
import { Socks5Client } from 'socksflare';

export default {
  async fetch(request, env) {
    const proxy = new Socks5Client({
      host: env.SOCKS5_HOST,
      port: env.SOCKS5_PORT,
      username: env.SOCKS5_USER,
      password: env.SOCKS5_PASS,
    });

    const url = new URL(request.url).searchParams.get('url');
    if (!url) return new Response('Missing ?url=', { status: 400 });

    // Drop-in fetch() replacement — routes through SOCKS5 + TLS 1.3
    return proxy.fetch(url);
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

Drop-in replacement for the standard `fetch()` API. Routes the request through the SOCKS5 proxy with automatic TLS for HTTPS URLs.

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

### `client.connect(targetHost, targetPort, options?)`

Low-level raw tunnel for non-HTTP protocols (SMTP, custom protocols, etc.).

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
| `options.enableTls` | `boolean` | `false` | Upgrade tunnel with TLS 1.3 |
| `options.tlsHostname` | `string` | `targetHost` | SNI hostname |

### Low-level Exports

For advanced usage, the underlying functions are also exported:

```javascript
import { proxyFetch, socks5Connect } from 'socksflare';
```

## Building WASM from Source

The `rust-tls-wasm/pkg/` directory ships with a pre-built WASM binary. To rebuild from source:

**Prerequisites:** Rust, [wasm-pack](https://rustwasm.github.io/wasm-pack/), LLVM/clang

```powershell
# Windows — set CC for ring's C compilation
$env:CC = "C:\Program Files\LLVM\bin\clang.exe"
$env:CC_wasm32_unknown_unknown = "C:\Program Files\LLVM\bin\clang.exe"

cd rust-tls-wasm
wasm-pack build --target web
```

## Project Structure

```
socksflare/
├── src/
│   ├── index.js             ← Main export: Socks5Client class
│   ├── socks5-client.js     ← SOCKS5 handshake engine
│   ├── proxy-fetch.js       ← HTTP/1.1 response parser
│   └── wasm-tls.js          ← JS bridge to Rustls WASM
├── rust-tls-wasm/
│   ├── src/lib.rs           ← Rustls WasmTlsClient
│   ├── Cargo.toml           ← rustls 0.23, ring 0.17, wasm-bindgen 0.2
│   └── pkg/                 ← Pre-built WASM output (committed)
├── example/
│   └── worker.js            ← Minimal demo worker
├── package.json
├── LICENSE                  ← GPL-3.0-or-later
└── README.md
```

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
