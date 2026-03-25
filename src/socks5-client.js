/**
 * SOCKS5 Client for Cloudflare Workers — WASM-only TLS
 *
 * For HTTP:  cloudflare:sockets → SOCKS5 → raw HTTP
 * For HTTPS: cloudflare:sockets → SOCKS5 → Rustls WASM TLS 1.3 → HTTPS
 *
 * @module socks5-client
 * @license GPL-3.0-or-later
 */

import { connect } from 'cloudflare:sockets';
import { wasmTlsHandshake } from './wasm-tls.js';

// ─── SOCKS5 Constants ───────────────────────────────────────────────

const SOCKS_VERSION = 0x05;
const AUTH_NONE = 0x00;
const AUTH_USERPASS = 0x02;
const AUTH_NO_ACCEPTABLE = 0xFF;
const AUTH_USERPASS_VERSION = 0x01;
const AUTH_USERPASS_SUCCESS = 0x00;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;
const REP_SUCCESS = 0x00;

const REPLY_MESSAGES = {
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

// ─── BufferedReader ─────────────────────────────────────────────────

class BufferedReader {
  constructor(reader) {
    this.reader = reader;
    this.chunks = [];
    this.totalBytes = 0;
    this.offset = 0;
  }

  async readExact(n) {
    while (this.totalBytes - this.offset < n) {
      const { value, done } = await this.reader.read();
      if (done || !value) throw new Error('SOCKS5: connection closed prematurely');
      this.chunks.push(value);
      this.totalBytes += value.byteLength;
    }

    // Fast path: first chunk has enough data
    if (this.chunks[0].byteLength - this.offset >= n) {
      const chunk = this.chunks[0];
      const result = chunk.subarray(this.offset, this.offset + n);
      this.offset += n;
      if (this.offset >= chunk.byteLength) {
        this.chunks.shift();
        this.totalBytes -= chunk.byteLength;
        this.offset = 0;
      }
      return result;
    }

    // Slow path: assemble across multiple chunks
    const result = new Uint8Array(n);
    let written = 0;
    while (written < n) {
      const chunk = this.chunks[0];
      const available = chunk.byteLength - this.offset;
      const needed = n - written;
      if (available <= needed) {
        result.set(chunk.subarray(this.offset), written);
        written += available;
        this.chunks.shift();
        this.totalBytes -= chunk.byteLength;
        this.offset = 0;
      } else {
        result.set(chunk.subarray(this.offset, this.offset + needed), written);
        this.offset += needed;
        written += needed;
      }
    }
    return result;
  }

  releaseLock() {
    this.reader.releaseLock();
  }
}

// ─── Address Parsing ────────────────────────────────────────────────

function parseAddress(host) {
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const bytes = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const octet = parseInt(ipv4Match[i + 1], 10);
      if (octet > 255) throw new Error(`SOCKS5: invalid IPv4 octet: ${octet}`);
      bytes[i] = octet;
    }
    return { atyp: ATYP_IPV4, addressBytes: bytes };
  }

  if (host.includes(':')) {
    return { atyp: ATYP_IPV6, addressBytes: ipv6ToBytes(host) };
  }

  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(host);
  if (domainBytes.length > 255) {
    throw new Error(`SOCKS5: domain name too long (${domainBytes.length} bytes, max 255)`);
  }
  const addressBytes = new Uint8Array(1 + domainBytes.length);
  addressBytes[0] = domainBytes.length;
  addressBytes.set(domainBytes, 1);
  return { atyp: ATYP_DOMAIN, addressBytes };
}

function ipv6ToBytes(ipv6) {
  ipv6 = ipv6.replace(/^\[|\]$/g, '');
  const parts = ipv6.split('::');
  let groups;
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  } else {
    groups = ipv6.split(':');
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    bytes[i * 2] = (val >> 8) & 0xFF;
    bytes[i * 2 + 1] = val & 0xFF;
  }
  return bytes;
}

// ─── Core SOCKS5 Connection ─────────────────────────────────────────

/**
 * Establishes a SOCKS5 tunnel to the target host through a proxy.
 *
 * **Security note:** The connection to the SOCKS5 proxy is always plain TCP.
 * Username/password authentication (RFC 1929) is sent **unencrypted**.
 * Only use with trusted/localhost proxies, or add your own encryption layer.
 *
 * @param {Object} proxyConfig - Proxy connection details.
 * @param {string} proxyConfig.hostname - SOCKS5 proxy hostname.
 * @param {number} [proxyConfig.port=1080] - SOCKS5 proxy port.
 * @param {string} [proxyConfig.username] - Auth username.
 * @param {string} [proxyConfig.password] - Auth password.
 * @param {string} targetHost - Destination hostname or IP.
 * @param {number} targetPort - Destination port.
 * @param {Object} [options] - Connection options.
 * @param {boolean} [options.enableTls=false] - Upgrade tunnel with TLS via Rustls WASM.
 * @param {string} [options.tlsHostname] - SNI hostname for TLS (defaults to targetHost).
 * @param {string[]} [options.alpnProtocols] - Optional ALPN protocols for TLS negotiation.
 * @returns {Promise<{socket: Object, readable: ReadableStream, writable: WritableStream, alpnProtocol?: string|null}>}
 */
export async function socks5Connect(proxyConfig, targetHost, targetPort, options = {}) {
  const { hostname: proxyHost, port: proxyPort = 1080, username, password } = proxyConfig;

  if (!proxyHost || typeof proxyHost !== 'string') {
    throw new Error('SOCKS5: proxy hostname is required');
  }
  if (!targetHost || typeof targetHost !== 'string') {
    throw new Error('SOCKS5: target host is required');
  }
  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    throw new Error(`SOCKS5: invalid target port: ${targetPort}`);
  }

  const useAuth = !!(username && password);
  const enableTls = options.enableTls || false;
  const tlsHostname = options.tlsHostname || targetHost;
  const alpnProtocols = Array.isArray(options.alpnProtocols) ? options.alpnProtocols : undefined;

  // Connect to SOCKS5 proxy over plain TCP — always unencrypted at this layer.
  const socket = connect({ hostname: proxyHost, port: proxyPort });
  await socket.opened;

  const writer = socket.writable.getWriter();
  const rawReader = socket.readable.getReader();
  const reader = new BufferedReader(rawReader);

  try {
    // ── Method Negotiation ──
    const methodReq = useAuth
      ? new Uint8Array([SOCKS_VERSION, 2, AUTH_NONE, AUTH_USERPASS])
      : new Uint8Array([SOCKS_VERSION, 1, AUTH_NONE]);
    await writer.write(methodReq);

    const methodResp = await reader.readExact(2);
    if (methodResp[0] !== SOCKS_VERSION) {
      throw new Error(`SOCKS5: bad version: ${methodResp[0]}`);
    }
    if (methodResp[1] === AUTH_NO_ACCEPTABLE) {
      throw new Error('SOCKS5: no acceptable auth method');
    }

    // ── Username/Password Authentication ──
    if (methodResp[1] === AUTH_USERPASS) {
      if (!username || !password) {
        throw new Error('SOCKS5: server requires auth but no credentials provided');
      }
      const encoder = new TextEncoder();
      const userBytes = encoder.encode(username);
      const passBytes = encoder.encode(password);
      const authReq = new Uint8Array(1 + 1 + userBytes.length + 1 + passBytes.length);
      let o = 0;
      authReq[o++] = AUTH_USERPASS_VERSION;
      authReq[o++] = userBytes.length;
      authReq.set(userBytes, o); o += userBytes.length;
      authReq[o++] = passBytes.length;
      authReq.set(passBytes, o);
      await writer.write(authReq);

      const authResp = await reader.readExact(2);
      if (authResp[1] !== AUTH_USERPASS_SUCCESS) {
        throw new Error('SOCKS5: authentication failed');
      }
    }

    // ── CONNECT Request ──
    const { atyp, addressBytes } = parseAddress(targetHost);
    const connReq = new Uint8Array(4 + addressBytes.length + 2);
    let o = 0;
    connReq[o++] = SOCKS_VERSION;
    connReq[o++] = CMD_CONNECT;
    connReq[o++] = 0x00; // reserved
    connReq[o++] = atyp;
    connReq.set(addressBytes, o); o += addressBytes.length;
    connReq[o++] = (targetPort >> 8) & 0xFF;
    connReq[o++] = targetPort & 0xFF;
    await writer.write(connReq);

    // ── CONNECT Response ──
    const connResp = await reader.readExact(4);
    if (connResp[0] !== SOCKS_VERSION) {
      throw new Error(`SOCKS5: bad version in reply: ${connResp[0]}`);
    }
    if (connResp[1] !== REP_SUCCESS) {
      const msg = REPLY_MESSAGES[connResp[1]] || `unknown error (0x${connResp[1].toString(16)})`;
      throw new Error(`SOCKS5: ${msg}`);
    }

    // Consume bound address (variable-length, we don't need it)
    const boundAtyp = connResp[3];
    if (boundAtyp === ATYP_IPV4) {
      await reader.readExact(6); // 4 IP + 2 port
    } else if (boundAtyp === ATYP_DOMAIN) {
      const lenBuf = await reader.readExact(1);
      await reader.readExact(lenBuf[0] + 2); // domain + 2 port
    } else if (boundAtyp === ATYP_IPV6) {
      await reader.readExact(18); // 16 IP + 2 port
    } else {
      throw new Error(`SOCKS5: unknown address type in reply: 0x${boundAtyp.toString(16)}`);
    }

    // Release locks — tunnel is now open
    reader.releaseLock();
    writer.releaseLock();

    // ── TLS Upgrade via Rustls WASM ──
    if (enableTls) {
      const tlsTunnel = await wasmTlsHandshake(socket.readable, socket.writable, tlsHostname, {
        alpnProtocols,
      });
      return { socket, ...tlsTunnel };
    }

    return { socket, readable: socket.readable, writable: socket.writable };

  } catch (err) {
    try { reader.releaseLock(); } catch (_) { /* already released */ }
    try { writer.releaseLock(); } catch (_) { /* already released */ }
    try { await socket.close(); } catch (_) { /* best-effort cleanup */ }
    throw err;
  }
}
