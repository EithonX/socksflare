# Socksflare

**SOCKS5 proxy client for Cloudflare Workers with TLS 1.3 via Rustls WASM.**

Route any HTTP(S) request through a SOCKS5 proxy from the Cloudflare Edge — no external relay, no `startTls()`, no JS TLS fallback. TLS is handled entirely by [Rustls](https://github.com/rustls/rustls) compiled to WebAssembly: memory-safe, constant-time, production-grade.

> [!WARNING]
> **This project is experimental and provided as-is.** It has not undergone a formal security audit. The TLS implementation relies on Rustls WASM, which may have a different fingerprint than standard browsers. **Use at your own risk.** The author(s) make no guarantees regarding security, reliability, or fitness for any particular purpose.

> [!CAUTION]
> **Disclaimer:** This software is intended for legitimate use cases such as privacy research, bypassing geo-restrictions on your own content, and building developer tools. **The author(s) are not responsible for how this software is used.** By using this software, you agree that you are solely responsible for ensuring your usage complies with all applicable laws and the terms of service of any third-party services you interact with.

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
fallthrough = true
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

## Known Limitations

- **TLS Fingerprint (JA3/JA4):** Rustls produces a different TLS ClientHello than Chrome/Firefox. Sites with aggressive bot detection may flag this. This is inherent to using a non-browser TLS stack.
- **Accept-Encoding:** Requests are sent with `Accept-Encoding: identity` to avoid decompression issues inside Workers. This is slightly unusual but not flagged by any known WAF.
- **HTTP/1.1 Only:** The library speaks HTTP/1.1 over the SOCKS5 tunnel. HTTP/2 and HTTP/3 are not supported.

## Contributing

This project was built by someone still learning — contributions, bug fixes, and improvements are very welcome! If you know more about TLS fingerprinting, Rust/WASM optimization, or Cloudflare Workers internals, please open a PR or issue. Every bit helps.

**Areas where help is especially needed:**

- Mimicking real browser TLS fingerprints (JA3/JA4 spoofing in Rustls)
- HTTP/2 support over SOCKS5
- Better error handling and retry logic
- Performance benchmarks and optimization

## Credits

- **[Rustls](https://github.com/rustls/rustls)** — The TLS engine powering the WASM module
- **[ring](https://github.com/briansmith/ring)** — Cryptographic primitives used by Rustls
- **[webpki-roots](https://github.com/rustls/webpki-roots)** — Mozilla's root CA certificates
- **[wasm-bindgen](https://github.com/nicedoc/llvm-builds)** — Rust ↔ JavaScript WASM bridge
- Built with ❤️ by [EithonX](https://github.com/EithonX)

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

**This means:** You can use, modify, and distribute this software freely, but any derivative work must also be released under GPL-3.0. See [LICENSE](LICENSE) for full terms.
