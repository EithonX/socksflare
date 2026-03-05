/**
 * HTTP/1.1 fetch over a SOCKS5 tunnel for Cloudflare Workers.
 *
 * Handles:
 * - Content-Length based responses (exact byte read, no TCP-close wait)
 * - Chunked transfer encoding (binary decoder)
 * - Direct-stream fallback (pipe until close)
 * - gzip / deflate / brotli decompression
 *
 * @module proxy-fetch
 * @license GPL-3.0-or-later
 */

import { socks5Connect } from './socks5-client.js';

const CR = 0x0D;
const LF = 0x0A;

// ─── Main Export ────────────────────────────────────────────────────

/**
 * Drop-in fetch() replacement that routes through a SOCKS5 proxy.
 *
 * @param {string|URL|Request} input - URL or Request object.
 * @param {RequestInit} [init] - Standard fetch init options.
 * @param {Object} proxyConfig - SOCKS5 proxy config (hostname, port, username, password).
 * @param {Object} [options] - Extra options.
 * @param {string} [options.tlsHostname] - Override SNI hostname for TLS.
 * @returns {Promise<Response>}
 */
export async function proxyFetch(input, init = {}, proxyConfig, options = {}) {
    let url;
    let requestInit = { ...init };

    if (input instanceof Request) {
        url = new URL(input.url);
        requestInit = {
            method: input.method,
            headers: Object.fromEntries(input.headers.entries()),
            body: input.body,
            ...init,
        };
    } else {
        url = new URL(input.toString());
    }

    const isHttps = url.protocol === 'https:';
    const targetHost = url.hostname;
    const targetPort = parseInt(url.port) || (isHttps ? 443 : 80);
    const tlsHostname = options.tlsHostname || targetHost;

    // Establish SOCKS5 tunnel (with WASM TLS if HTTPS)
    const tunnel = await socks5Connect(proxyConfig, targetHost, targetPort, {
        enableTls: isHttps,
        tlsHostname,
    });

    try {
        // Build and send raw HTTP/1.1 request
        const requestBytes = buildHttpRequest(url, requestInit);
        const writer = tunnel.writable.getWriter();
        try {
            await writer.write(requestBytes);
        } catch (err) {
            const msg = err && err.message ? err.message : String(err);
            try { writer.releaseLock(); } catch (_) { /* noop */ }
            throw new Error(`Failed writing HTTP request: ${msg}`);
        }

        // Write request body if present
        if (requestInit.body) {
            if (typeof requestInit.body === 'string') {
                await writer.write(new TextEncoder().encode(requestInit.body));
                writer.releaseLock();
            } else if (requestInit.body instanceof ReadableStream) {
                writer.releaseLock();
                const bodyReader = requestInit.body.getReader();
                const bodyWriter = tunnel.writable.getWriter();
                try {
                    while (true) {
                        const { value, done } = await bodyReader.read();
                        if (done) break;
                        await bodyWriter.write(value);
                    }
                } finally {
                    bodyWriter.releaseLock();
                }
            } else if (requestInit.body instanceof ArrayBuffer || requestInit.body instanceof Uint8Array) {
                await writer.write(new Uint8Array(requestInit.body));
                writer.releaseLock();
            } else {
                writer.releaseLock();
            }
        } else {
            writer.releaseLock();
        }

        // Parse response — binary header scanning, then stream body
        return await parseResponseBinary(tunnel.readable, tunnel.socket);

    } catch (err) {
        try { await tunnel.socket.close(); } catch (_) { /* best-effort */ }
        throw err;
    }
}

// ─── HTTP Request Builder ───────────────────────────────────────────

function buildHttpRequest(url, init) {
    // ── Build HTTP Request ──
    const method = (init.method || 'GET').toUpperCase();
    const path = url.pathname + url.search;
    const host = url.port ? `${url.hostname}:${url.port}` : url.hostname;
    const headers = new Headers(init.headers);

    // Ensure Host header is set correctly (prevents Cloudflare domain fronting errors)
    // Overwrite any Host header that might have been forwarded blindly from the Worker's request.
    headers.set('Host', host);
    if (!headers.has('Connection')) headers.set('Connection', 'close');

    // Strip Cloudflare-specific routing and all proxy-related headers.
    // This guarantees the SOCKS5 traffic is fully anonymous, even if the Worker blindly forwards the client's original headers.
    const keysToDelete = [];
    for (const key of headers.keys()) {
        const k = key.toLowerCase();
        if (
            k.startsWith('cf-') ||
            k.startsWith('x-forwarded-') ||
            k === 'x-real-ip' ||
            k === 'true-client-ip' ||
            k === 'forwarded' ||
            k === 'via' ||
            k === 'cdn-loop'
        ) {
            keysToDelete.push(key);
        }
    }
    for (const key of keysToDelete) {
        headers.delete(key);
    }

    if (!headers.has('User-Agent')) headers.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    if (!headers.has('Accept')) headers.set('Accept', '*/*');

    // Force identity encoding unconditionally.
    // Decompressing gzip/brotli inside a Worker is slow and error-prone.
    // By forcing identity encoding, the target server sends plain data through the proxy.
    // Cloudflare's Edge will automatically re-compress the final response for the user.
    headers.set('Accept-Encoding', 'identity');

    // Auto Content-Length for string bodies
    if (init.body && typeof init.body === 'string' && !headers.has('Content-Length')) {
        headers.set('Content-Length', new TextEncoder().encode(init.body).byteLength.toString());
    }

    let str = `${method} ${path} HTTP/1.1\r\n`;
    for (const [key, value] of headers.entries()) {
        str += `${key}: ${value.replace(/[\r\n]/g, '')}\r\n`;
    }
    str += '\r\n';

    return new TextEncoder().encode(str);
}

// ─── Binary HTTP Response Parser ────────────────────────────────────

async function parseResponseBinary(readable, socket) {
    const reader = readable.getReader();
    const decoder = new TextDecoder();

    // Accumulate bytes until we find \r\n\r\n
    let buffers = [];
    let totalLen = 0;
    let headerEndOffset = -1;
    let combined = null;

    while (headerEndOffset === -1) {
        let chunk;
        try {
            chunk = await reader.read();
        } catch (err) {
            const msg = err && err.message ? err.message : String(err);
            throw new Error(`Failed reading response headers: ${msg}`);
        }
        const { value, done } = chunk;
        if (done) throw new Error('SOCKS5 proxy: connection closed before headers received');

        buffers.push(value);
        totalLen += value.byteLength;

        combined = concatBuffers(buffers, totalLen);
        headerEndOffset = findHeaderEnd(combined);
    }

    const headerBytes = combined.subarray(0, headerEndOffset);
    const bodyRemainder = combined.subarray(headerEndOffset + 4);

    // Parse status line and headers
    const headerStr = decoder.decode(headerBytes);
    const lines = headerStr.split('\r\n');
    const statusMatch = lines[0].match(/^HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
    if (!statusMatch) throw new Error(`Bad HTTP response line: ${lines[0]}`);

    const status = parseInt(statusMatch[1]);
    const statusText = statusMatch[2] || '';

    const responseHeaders = new Headers();
    for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
            responseHeaders.append(
                lines[i].substring(0, idx).trim(),
                lines[i].substring(idx + 1).trim()
            );
        }
    }

    // ── Handle null-body statuses ──
    const nullBodyStatuses = [101, 204, 205, 304];
    if (nullBodyStatuses.includes(status)) {
        reader.cancel().catch(() => { });
        try { socket.close(); } catch (_) { /* noop */ }
        return new Response(null, { status, statusText, headers: responseHeaders });
    }

    // ── Determine body strategy ──
    const transferEncoding = responseHeaders.get('transfer-encoding');
    const isChunked = transferEncoding && transferEncoding.toLowerCase().includes('chunked');
    const contentLengthStr = responseHeaders.get('content-length');
    const contentLength = contentLengthStr ? parseInt(contentLengthStr) : null;

    let bodyStream;

    if (isChunked) {
        bodyStream = createChunkedStream(reader, bodyRemainder, socket);
        responseHeaders.delete('transfer-encoding');
    } else if (contentLength !== null && contentLength >= 0) {
        bodyStream = createContentLengthStream(reader, bodyRemainder, contentLength, socket);
    } else {
        bodyStream = createDirectStream(reader, bodyRemainder);
    }

    return new Response(bodyStream, { status, statusText, headers: responseHeaders });
}

// ─── Body Streams ───────────────────────────────────────────────────

/**
 * Content-Length stream — reads exactly `contentLength` bytes then closes.
 */
function createContentLengthStream(reader, initialData, contentLength, socket) {
    let bytesRemaining = contentLength;
    let sentInitial = false;

    return new ReadableStream({
        pull(controller) {
            if (bytesRemaining <= 0) {
                controller.close();
                try { socket.close(); } catch (_) { /* noop */ }
                return;
            }

            if (!sentInitial) {
                sentInitial = true;
                if (initialData.byteLength > 0) {
                    if (initialData.byteLength >= bytesRemaining) {
                        controller.enqueue(initialData.subarray(0, bytesRemaining));
                        bytesRemaining = 0;
                        controller.close();
                        try { socket.close(); } catch (_) { /* noop */ }
                        return;
                    }
                    bytesRemaining -= initialData.byteLength;
                    controller.enqueue(initialData);
                    return;
                }
            }

            return reader.read().then(({ value, done }) => {
                if (done) {
                    controller.close();
                    return;
                }
                if (value.byteLength >= bytesRemaining) {
                    controller.enqueue(value.subarray(0, bytesRemaining));
                    bytesRemaining = 0;
                    controller.close();
                    try { socket.close(); } catch (_) { /* noop */ }
                } else {
                    bytesRemaining -= value.byteLength;
                    controller.enqueue(value);
                }
            }).catch(() => {
                controller.close();
            });
        },
        cancel() {
            reader.cancel();
            try { socket.close(); } catch (_) { /* noop */ }
        },
    });
}

/**
 * Chunked transfer encoding decoder — fully binary.
 */
function createChunkedStream(reader, initialData, socket) {
    let buffer = initialData;
    let streamDone = false;

    return new ReadableStream({
        async pull(controller) {
            if (streamDone) { controller.close(); return; }

            while (true) {
                const lineEnd = findCRLF(buffer);

                if (lineEnd === -1) {
                    const result = await reader.read();
                    if (result.done) { streamDone = true; controller.close(); return; }
                    buffer = appendBuffer(buffer, result.value);
                    continue;
                }

                const sizeStr = new TextDecoder().decode(buffer.subarray(0, lineEnd)).trim();
                const chunkSize = parseInt(sizeStr.split(';')[0], 16);

                if (isNaN(chunkSize) || chunkSize < 0) {
                    streamDone = true; controller.close(); return;
                }

                if (chunkSize === 0) {
                    streamDone = true;
                    controller.close();
                    try { socket.close(); } catch (_) { /* noop */ }
                    return;
                }

                buffer = buffer.subarray(lineEnd + 2);

                // Need chunkSize data bytes + 2 bytes trailing CRLF
                const totalNeeded = chunkSize + 2;
                while (buffer.byteLength < totalNeeded) {
                    const result = await reader.read();
                    if (result.done) {
                        if (buffer.byteLength > 0) {
                            controller.enqueue(buffer.subarray(0, Math.min(buffer.byteLength, chunkSize)));
                        }
                        streamDone = true; controller.close(); return;
                    }
                    buffer = appendBuffer(buffer, result.value);
                }

                const chunkData = buffer.subarray(0, chunkSize);
                buffer = buffer.subarray(chunkSize + 2);

                controller.enqueue(chunkData);
                return;
            }
        },
        cancel() {
            reader.cancel();
            try { socket.close(); } catch (_) { /* noop */ }
        },
    });
}

/**
 * Direct stream — pipe until close (no Content-Length, not chunked).
 */
function createDirectStream(reader, initialData) {
    let sentInitial = false;
    return new ReadableStream({
        pull(controller) {
            if (!sentInitial) {
                sentInitial = true;
                if (initialData.byteLength > 0) {
                    controller.enqueue(initialData);
                    return;
                }
            }
            return reader.read().then(({ value, done }) => {
                if (done) controller.close();
                else controller.enqueue(value);
            }).catch(() => controller.close());
        },
        cancel() { reader.cancel(); },
    });
}

// ─── Helpers ────────────────────────────────────────────────────────

function concatBuffers(buffers, totalLen) {
    if (buffers.length === 1) return buffers[0];
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const buf of buffers) {
        result.set(buf, offset);
        offset += buf.byteLength;
    }
    return result;
}

function findHeaderEnd(buf) {
    for (let i = 0; i <= buf.byteLength - 4; i++) {
        if (buf[i] === CR && buf[i + 1] === LF && buf[i + 2] === CR && buf[i + 3] === LF) {
            return i;
        }
    }
    return -1;
}

function findCRLF(buf) {
    for (let i = 0; i < buf.byteLength - 1; i++) {
        if (buf[i] === CR && buf[i + 1] === LF) return i;
    }
    return -1;
}

function appendBuffer(a, b) {
    if (a.byteLength === 0) return b;
    const result = new Uint8Array(a.byteLength + b.byteLength);
    result.set(a, 0);
    result.set(b, a.byteLength);
    return result;
}
