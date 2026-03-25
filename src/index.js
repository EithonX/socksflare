/**
 * Socksflare — SOCKS5 proxy client for Cloudflare Workers with TLS 1.3 via Rustls WASM.
 *
 * @module socksflare
 * @license GPL-3.0-or-later
 *
 * @example
 * import { Socks5Client } from 'socksflare';
 *
 * const proxy = new Socks5Client({
 *   host: '1.2.3.4',
 *   port: 1080,
 *   username: 'user',
 *   password: 'pass',
 * });
 *
 * // Drop-in fetch replacement
 * const response = await proxy.fetch('https://example.com');
 *
 * // Raw tunnel for non-HTTP protocols
 * const { readable, writable } = await proxy.connect('example.com', 443, { enableTls: true });
 */

import { socks5Connect } from './socks5-client.js';
import { proxyFetch } from './proxy-fetch.js';

export class Socks5Client {
    /**
     * Create a new SOCKS5 client instance.
     *
     * @param {Object} config - Proxy configuration.
     * @param {string} config.host - SOCKS5 proxy hostname or IP.
     * @param {number} [config.port=1080] - SOCKS5 proxy port.
     * @param {string} [config.username] - Auth username (also accepts `config.user`).
     * @param {string} [config.password] - Auth password (also accepts `config.pass`).
     */
    constructor(config = {}) {
        if (!config.host) {
            throw new Error('socksflare: host is required');
        }
        this.host = config.host;
        this.port = parseInt(config.port) || 1080;
        this.username = config.username || config.user || undefined;
        this.password = config.password || config.pass || undefined;
        this._http2Pool = new Map();
    }

    /** @internal */
    get _proxyConfig() {
        return {
            hostname: this.host,
            port: this.port,
            username: this.username,
            password: this.password,
        };
    }

    /**
     * Drop-in replacement for `fetch()` — routes through SOCKS5 + Rustls WASM TLS.
     *
     * @param {string|URL|Request} input - URL or Request object.
     * @param {RequestInit} [init] - Standard fetch init options.
     * @param {Object} [options] - Additional options.
     * @param {string} [options.tlsHostname] - Override SNI hostname for TLS.
     * @param {'1.1'|'auto'|'2'} [options.httpVersion='1.1'] - HTTP version strategy for HTTPS targets.
     * @returns {Promise<Response>}
     */
    async fetch(input, init = {}, options = {}) {
        return proxyFetch(input, init, this._proxyConfig, {
            tlsHostname: options.tlsHostname,
            httpVersion: options.httpVersion,
            http2Pool: this._http2Pool,
        });
    }

    /**
     * Low-level raw tunnel — for non-HTTP use cases (SMTP, custom protocols, etc.).
     *
     * @param {string} targetHost - Destination hostname or IP.
     * @param {number} targetPort - Destination port.
     * @param {Object} [options] - Connection options.
     * @param {boolean} [options.enableTls=false] - Upgrade tunnel with TLS 1.3.
     * @param {string} [options.tlsHostname] - SNI hostname (defaults to targetHost).
     * @param {string[]} [options.alpnProtocols] - Optional ALPN protocols for TLS negotiation.
     * @returns {Promise<{socket: Object, readable: ReadableStream, writable: WritableStream, alpnProtocol?: string|null}>}
     */
    async connect(targetHost, targetPort, options = {}) {
        return socks5Connect(this._proxyConfig, targetHost, targetPort, {
            enableTls: options.enableTls || false,
            tlsHostname: options.tlsHostname || targetHost,
            alpnProtocols: options.alpnProtocols,
        });
    }
}

// Re-export low-level functions for advanced usage
export { proxyFetch, socks5Connect };
