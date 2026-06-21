/**
 * Socksflare — SOCKS5 proxy client for Cloudflare Workers with TLS via Rustls WASM.
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
 * // Fetch-like helper routed through SOCKS5
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
        this.port = parseInt(config.port ?? 1080, 10);
        if (!Number.isInteger(this.port) || this.port < 1 || this.port > 65535) {
            throw new Error(`socksflare: invalid proxy port: ${config.port}`);
        }
        this.username = config.username ?? config.user ?? undefined;
        this.password = config.password ?? config.pass ?? undefined;
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
     * Fetch-like helper — routes through SOCKS5 + Rustls WASM TLS.
     *
     * @param {string|URL|Request} input - URL or Request object.
     * @param {RequestInit} [init] - Standard fetch init options (supports `init.signal`).
     * @param {Object} [options] - Additional options.
     * @param {string} [options.tlsHostname] - Override SNI hostname for TLS.
     * @param {'1.1'|'auto'|'2'} [options.httpVersion='1.1'] - HTTP version strategy for HTTPS targets.
     * @param {Array<ArrayBuffer|Uint8Array>} [options.extraRootCertificates] - Optional extra DER roots.
     * @param {number} [options.timeoutMs] - Abort after this many ms (merged with init.signal if present).
     * @returns {Promise<Response>}
     */
    async fetch(input, init = {}, options = {}) {
        const mergedInit = { ...init };
        const hasInitSignal = Object.prototype.hasOwnProperty.call(init, 'signal');
        const requestSignal = input instanceof Request && !hasInitSignal ? input.signal : mergedInit.signal;
        const mergedSignal = buildMergedSignal(requestSignal, options.timeoutMs);

        if (hasInitSignal || options.timeoutMs != null) {
            if (mergedSignal) mergedInit.signal = mergedSignal;
            else delete mergedInit.signal;
        } else {
            delete mergedInit.signal;
        }
        return proxyFetch(input, mergedInit, this._proxyConfig, {
            tlsHostname: options.tlsHostname,
            httpVersion: options.httpVersion,
            extraRootCertificates: options.extraRootCertificates,
        });
    }

    /**
     * Low-level raw tunnel — for non-HTTP use cases (SMTP, custom protocols, etc.).
     *
     * **Security note:** SOCKS5 proxy credentials are sent over plain TCP.
     * Only use with trusted/localhost proxies unless you add your own encryption layer.
     *
     * @param {string} targetHost - Destination hostname or IP.
     * @param {number} targetPort - Destination port.
     * @param {Object} [options] - Connection options.
     * @param {boolean} [options.enableTls=false] - Upgrade tunnel with Rustls WASM TLS.
     * @param {string} [options.tlsHostname] - SNI hostname (defaults to targetHost).
     * @param {string[]} [options.alpnProtocols] - Optional ALPN protocols for TLS negotiation.
     * @param {Array<ArrayBuffer|Uint8Array>} [options.extraRootCertificates] - Optional extra DER roots.
     * @returns {Promise<{socket: Object, readable: ReadableStream, writable: WritableStream, alpnProtocol?: string|null}>}
     */
    async connect(targetHost, targetPort, options = {}) {
        return socks5Connect(this._proxyConfig, targetHost, targetPort, {
            enableTls: options.enableTls || false,
            tlsHostname: options.tlsHostname || targetHost,
            alpnProtocols: options.alpnProtocols,
            extraRootCertificates: options.extraRootCertificates,
            signal: buildMergedSignal(options.signal, options.timeoutMs),
        });
    }
}

function buildMergedSignal(signal, timeoutMs) {
    if (timeoutMs == null) return signal || null;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
        throw new Error(`socksflare: timeoutMs must be a finite number > 0; got ${timeoutMs}`);
    }

    let timeoutSignal;
    let disposeTimeout = null;
    if (typeof AbortSignal.timeout === 'function') {
        timeoutSignal = AbortSignal.timeout(timeoutMs);
    } else {
        const ac = new AbortController();
        const timer = setTimeout(() => {
            const err = typeof DOMException === 'function'
                ? new DOMException('Timeout', 'TimeoutError')
                : Object.assign(new Error('Timeout'), { name: 'TimeoutError' });
            ac.abort(err);
        }, timeoutMs);
        disposeTimeout = () => clearTimeout(timer);
        timeoutSignal = ac.signal;
    }

    if (signal && typeof AbortSignal.any === 'function') {
        const merged = AbortSignal.any([signal, timeoutSignal]);
        if (disposeTimeout) {
            const cleanup = () => {
                disposeTimeout();
                disposeTimeout = null;
                merged.removeEventListener('abort', cleanup);
            };
            merged.addEventListener('abort', cleanup, { once: true });
        }
        return merged;
    }

    if (signal) {
        const ac = new AbortController();
        let sourceAbortHandler = null;
        let timeoutAbortHandler = null;
        const cleanup = () => {
            if (sourceAbortHandler) signal.removeEventListener('abort', sourceAbortHandler);
            if (timeoutAbortHandler) timeoutSignal.removeEventListener('abort', timeoutAbortHandler);
            if (disposeTimeout) {
                disposeTimeout();
                disposeTimeout = null;
            }
            sourceAbortHandler = null;
            timeoutAbortHandler = null;
        };
        if (signal.aborted) {
            cleanup();
            ac.abort(signal.reason);
            return ac.signal;
        }
        if (timeoutSignal.aborted) {
            cleanup();
            ac.abort(timeoutSignal.reason);
            return ac.signal;
        }
        const forward = s => {
            if (ac.signal.aborted) return;
            cleanup();
            ac.abort(s.reason);
        };
        sourceAbortHandler = () => forward(signal);
        timeoutAbortHandler = () => forward(timeoutSignal);
        signal.addEventListener('abort', sourceAbortHandler, { once: true });
        timeoutSignal.addEventListener('abort', timeoutAbortHandler, { once: true });
        return ac.signal;
    }

    if (disposeTimeout) {
        const cleanup = () => {
            disposeTimeout();
            disposeTimeout = null;
            timeoutSignal.removeEventListener('abort', cleanup);
        };
        timeoutSignal.addEventListener('abort', cleanup, { once: true });
    }
    return timeoutSignal;
}

// Re-export low-level functions for advanced usage
export { proxyFetch, socks5Connect };
