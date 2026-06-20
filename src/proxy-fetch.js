/**
 * Fetch over a SOCKS5 tunnel for Cloudflare Workers.
 *
 * Default path is HTTP/1.1, with optional experimental HTTP/2 dispatch.
 *
 * Handles:
 * - Content-Length based responses (exact byte read, no TCP-close wait)
 * - Chunked transfer encoding (binary decoder)
 * - Direct-stream fallback (pipe until close)
 * - identity-encoded responses
 *
 * @module proxy-fetch
 * @license GPL-3.0-or-later
 */

import { socks5Connect } from './socks5-client.js';
import { proxyFetchHttp2 } from './proxy-fetch-http2.js';

const CR = 0x0D;
const LF = 0x0A;
const textEncoder = new TextEncoder();

// Security limits — tuned for Cloudflare Workers (128MB memory ceiling)
const MAX_HEADER_SIZE = 128 * 1024;          // 128KB max response headers
const MAX_RESPONSE_HEADERS = 200;            // max individual header lines
const MAX_HEADER_LINE_LENGTH = 8192;         // 8KB per header line
const MAX_CHUNK_SIZE = 16 * 1024 * 1024;     // 16MB per chunked-TE chunk
const MAX_CHUNK_LINE_LENGTH = 8192;          // 8KB chunk-size / trailer line cap
const MAX_CONSECUTIVE_EMPTY_CHUNKS = 1024;
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER_VALUE_RE = /^[\t\x20-\x7E\x80-\xFF]*$/;
const HTTP2_NOT_NEGOTIATED_ERROR_CODE = 'ERR_SOCKSFLARE_HTTP2_NOT_NEGOTIATED';

// ─── Main Export ────────────────────────────────────────────────────

/**
 * Fetch-like helper that routes HTTP(S) requests through a SOCKS5 proxy.
 *
 * @param {string|URL|Request} input - URL or Request object.
 * @param {RequestInit} [init] - Standard fetch init options.
 * @param {Object} proxyConfig - SOCKS5 proxy config (hostname, port, username, password).
 * @param {Object} [options] - Extra options.
 * @param {string} [options.tlsHostname] - Override SNI hostname for TLS.
 * @param {'1.1'|'auto'|'2'} [options.httpVersion='1.1'] - HTTP version strategy for HTTPS targets.
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
            signal: input.signal,
            ...init,
        };
    } else {
        url = new URL(input.toString());
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new Error(`Unsupported URL protocol: ${url.protocol}`);
    }

    const isHttps = url.protocol === 'https:';
    const requestedVersion = options.httpVersion === '2'
        ? '2'
        : (options.httpVersion === 'auto' ? 'auto' : '1.1');

    if (isHttps && requestedVersion !== '1.1') {
        try {
            return await proxyFetchHttp2(url, requestInit, proxyConfig, {
                tlsHostname: options.tlsHostname,
            });
        } catch (err) {
            if (requestedVersion === '2' || !shouldFallbackToHttp11(err)) {
                throw err;
            }
        }
    }

    return proxyFetchHttp11(url, requestInit, proxyConfig, options);
}

async function proxyFetchHttp11(url, requestInit, proxyConfig, options = {}) {
    const isHttps = url.protocol === 'https:';
    const targetHost = url.hostname;
    const targetPort = parseInt(url.port) || (isHttps ? 443 : 80);
    const tlsHostname = options.tlsHostname || targetHost;
    const signal = requestInit.signal;
    let tunnel = null;
    let abortHandler = null;

    throwIfAborted(signal);
    const method = (requestInit.method || 'GET').toUpperCase();
    const bodyMode = await normalizeHttp11Body(requestInit.body);
    assertMethodBodyAllowed(method, bodyMode, 'HTTP/1.1');

    // Establish SOCKS5 tunnel (with WASM TLS if HTTPS)
    tunnel = await socks5Connect(proxyConfig, targetHost, targetPort, {
        enableTls: isHttps,
        tlsHostname,
        alpnProtocols: isHttps ? ['http/1.1'] : undefined,
        signal,
    });
    abortHandler = signal
        ? () => {
            try { tunnel.socket.close(); } catch (_) { /* noop */ }
        }
        : null;
    if (signal) signal.addEventListener('abort', abortHandler, { once: true });

    try {
        // Build and send raw HTTP/1.1 request
        throwIfAborted(signal);
        const requestBytes = buildHttpRequest(url, requestInit, bodyMode);
        const writer = tunnel.writable.getWriter();
        try {
            await writer.write(requestBytes);
            await writeHttp11Body(writer, bodyMode, signal);
        } catch (err) {
            if (signal && signal.aborted) throw makeAbortError(signal);
            const msg = err && err.message ? err.message : String(err);
            throw new Error(`Failed writing HTTP request: ${msg}`);
        } finally {
            try { writer.releaseLock(); } catch (_) { /* noop */ }
        }

        // Parse response — binary header scanning, then stream body
        if (signal) signal.removeEventListener('abort', abortHandler);
        return await parseResponseBinary(tunnel.readable, tunnel.socket, signal, method);

    } catch (err) {
        if (signal) signal.removeEventListener('abort', abortHandler);
        try { await tunnel.socket.close(); } catch (_) { /* best-effort */ }
        throw err;
    }
}

// ─── HTTP Request Builder ───────────────────────────────────────────

function buildHttpRequest(url, init, bodyMode) {
    // ── Build HTTP Request ──
    const method = (init.method || 'GET').toUpperCase();
    if (!/^[A-Z]+$/.test(method)) {
        throw new Error(`Invalid HTTP method: ${method}`);
    }
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

    headers.delete('Transfer-Encoding');
    if (bodyMode.kind === 'bytes') {
        headers.set('Content-Length', bodyMode.bytes.byteLength.toString());
    } else if (bodyMode.kind === 'stream') {
        headers.delete('Content-Length');
        headers.set('Transfer-Encoding', 'chunked');
    } else {
        headers.delete('Content-Length');
    }

    let str = `${method} ${path} HTTP/1.1\r\n`;
    for (const [key, value] of headers.entries()) {
        if (!HEADER_NAME_RE.test(key)) throw new Error(`Invalid request header name: ${key}`);
        if (!HEADER_VALUE_RE.test(value)) throw new Error(`Invalid request header value for ${key}`);
        str += `${key}: ${value}\r\n`;
    }
    str += '\r\n';

    return new TextEncoder().encode(str);
}

// ─── Binary HTTP Response Parser ────────────────────────────────────

async function parseResponseBinary(readable, socket, signal, method = 'GET') {
    const reader = readable.getReader();
    const decoder = new TextDecoder();
    let abortHandler = null;
    const cleanupAbort = () => {
        if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
        abortHandler = null;
    };

    if (signal) {
        abortHandler = () => {
            try { reader.cancel(); } catch (_) { /* noop */ }
            try { socket.close(); } catch (_) { /* noop */ }
        };
        signal.addEventListener('abort', abortHandler, { once: true });
    }

    let buffers = [];
    let totalLen = 0;
    let headerEndOffset = -1;
    let combined = null;
    let bodyRemainder = new Uint8Array(0);
    let status = 0;
    let statusText = '';
    let lines = [];

    while (true) {
        // Accumulate bytes until one complete header section exists.
        let emptyChunkCount = 0;
        while (headerEndOffset === -1) {
            throwIfAborted(signal);
            let chunk;
            try {
                chunk = await reader.read();
            } catch (err) {
                const msg = err && err.message ? err.message : String(err);
                throw new Error(`Failed reading response headers: ${msg}`);
            }
            const { value, done } = chunk;
            if (done) throw new Error('SOCKS5 proxy: connection closed before headers received');
            if (value && value.byteLength === 0) {
                emptyChunkCount += 1;
                if (emptyChunkCount > MAX_CONSECUTIVE_EMPTY_CHUNKS) {
                    throw new Error('HTTP response headers: too many consecutive empty chunks');
                }
                continue;
            }
            emptyChunkCount = 0;

            buffers.push(value);
            totalLen += value.byteLength;

            if (totalLen > MAX_HEADER_SIZE) {
                throw new Error(`HTTP response headers too large (>${MAX_HEADER_SIZE} bytes)`);
            }

            combined = concatBuffers(buffers, totalLen);
            headerEndOffset = findHeaderEnd(combined);
        }

        const headerBytes = combined.subarray(0, headerEndOffset);
        bodyRemainder = combined.subarray(headerEndOffset + 4);

        const headerStr = decoder.decode(headerBytes);
        lines = headerStr.split('\r\n');
        const statusMatch = lines[0].match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*(.*)$/);
        if (!statusMatch) throw new Error(`Bad HTTP response line: ${lines[0]}`);

        status = parseInt(statusMatch[1], 10);
        statusText = statusMatch[2] || '';
        if (status < 100 || status > 599) {
            throw new Error(`Invalid HTTP response status: ${status}`);
        }

        if (status === 101) {
            throw new Error('HTTP upgrade responses are not supported');
        }
        if (status >= 100 && status < 200) {
            buffers = bodyRemainder.byteLength > 0 ? [bodyRemainder] : [];
            totalLen = bodyRemainder.byteLength;
            combined = bodyRemainder;
            headerEndOffset = findHeaderEnd(combined);
            continue;
        }
        break;
    }

    const responseHeaders = new Headers();
    let headerCount = 0;
    const contentLengthValues = [];
    for (let i = 1; i < lines.length; i++) {
        if (++headerCount > MAX_RESPONSE_HEADERS) {
            throw new Error(`Too many response headers (>${MAX_RESPONSE_HEADERS})`);
        }
        if (lines[i].length > MAX_HEADER_LINE_LENGTH) {
            throw new Error(`Response header line too long (>${MAX_HEADER_LINE_LENGTH})`);
        }
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
            const name = lines[i].substring(0, idx).trim();
            const value = lines[i].substring(idx + 1).trim();
            if (!HEADER_NAME_RE.test(name)) {
                throw new Error(`Invalid HTTP response header name: ${name}`);
            }
            if (!HEADER_VALUE_RE.test(value)) {
                throw new Error(`Invalid HTTP response header value for ${name}`);
            }
            if (name.toLowerCase() === 'content-length') {
                contentLengthValues.push(value);
            }
            try {
                responseHeaders.append(name, value);
            } catch (err) {
                const msg = err && err.message ? err.message : String(err);
                throw new Error(`Invalid HTTP response header ${name}: ${msg}`);
            }
        } else if (lines[i] !== '') {
            throw new Error(`Malformed HTTP response header line: ${lines[i]}`);
        }
    }

    const nullBody = method === 'HEAD' || [204, 205, 304].includes(status);
    if (nullBody) {
        cleanupAbort();
        reader.cancel().catch(() => { });
        try { socket.close(); } catch (_) { /* noop */ }
        return new Response(null, { status, statusText, headers: responseHeaders });
    }

    // ── Determine body strategy ──
    const transferEncoding = responseHeaders.get('transfer-encoding');
    const isChunked = transferEncoding && transferEncoding.toLowerCase().includes('chunked');
    const contentLength = parseStrictContentLength(contentLengthValues);

    let bodyStream;

    if (isChunked) {
        bodyStream = createChunkedStream(reader, bodyRemainder, socket, signal, cleanupAbort);
        responseHeaders.delete('transfer-encoding');
    } else if (contentLength !== null && contentLength >= 0) {
        bodyStream = createContentLengthStream(reader, bodyRemainder, contentLength, socket, signal, cleanupAbort);
    } else {
        bodyStream = createDirectStream(reader, bodyRemainder, socket, signal, cleanupAbort);
    }

    return new Response(bodyStream, { status, statusText, headers: responseHeaders });
}

// ─── Body Streams ───────────────────────────────────────────────────

/**
 * Content-Length stream — reads exactly `contentLength` bytes then closes.
 */
function createContentLengthStream(reader, initialData, contentLength, socket, signal, cleanup) {
    let bytesRemaining = contentLength;
    let sentInitial = false;

    return new ReadableStream({
        pull(controller) {
            throwIfAborted(signal);
            if (bytesRemaining <= 0) {
                controller.close();
                cleanup();
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
                        cleanup();
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
                    const err = new Error(`HTTP response body truncated: expected ${bytesRemaining} more bytes`);
                    cleanup();
                    try { socket.close(); } catch (_) { /* noop */ }
                    controller.error(err);
                    return;
                }
                if (value.byteLength >= bytesRemaining) {
                    controller.enqueue(value.subarray(0, bytesRemaining));
                    bytesRemaining = 0;
                    controller.close();
                    cleanup();
                    try { socket.close(); } catch (_) { /* noop */ }
                } else {
                    bytesRemaining -= value.byteLength;
                    controller.enqueue(value);
                }
            }).catch(() => {
                cleanup();
                try { socket.close(); } catch (_) { /* noop */ }
                controller.error(signal && signal.aborted
                    ? makeAbortError(signal)
                    : new Error(`HTTP response body truncated: expected ${bytesRemaining} more bytes`));
            });
        },
        cancel() {
            cleanup();
            reader.cancel();
            try { socket.close(); } catch (_) { /* noop */ }
        },
    });
}

/**
 * Chunked transfer encoding decoder — fully binary.
 */
function createChunkedStream(reader, initialData, socket, signal, cleanup) {
    let buffer = initialData;
    let streamDone = false;
    const chunkDecoder = new TextDecoder();

    const failWith = (controller, err) => {
        streamDone = true;
        cleanup();
        try { socket.close(); } catch (_) { /* noop */ }
        controller.error(err);
    };

    const fail = (controller, message) => {
        failWith(controller, new Error(message));
    };

    const readMore = async (controller, eofMessage) => {
        let result;
        try {
            result = await reader.read();
        } catch (err) {
            failWith(controller, signal && signal.aborted ? makeAbortError(signal) : toError(err));
            return false;
        }
        if (result.done) {
            failWith(controller, signal && signal.aborted ? makeAbortError(signal) : new Error(eofMessage));
            return false;
        }
        buffer = appendBuffer(buffer, result.value);
        return true;
    };

    return new ReadableStream({
        async pull(controller) {
            throwIfAborted(signal);
            if (streamDone) { controller.close(); return; }

            while (true) {
                const lineEnd = findCRLF(buffer);

                if (lineEnd === -1) {
                    if (buffer.byteLength > MAX_CHUNK_LINE_LENGTH) {
                        fail(controller, 'HTTP chunk size line too long');
                        return;
                    }
                    if (!await readMore(controller, 'HTTP chunked body truncated while reading chunk size')) return;
                    continue;
                }

                if (lineEnd > MAX_CHUNK_LINE_LENGTH) {
                    fail(controller, 'HTTP chunk size line too long');
                    return;
                }

                const sizeStr = chunkDecoder.decode(buffer.subarray(0, lineEnd)).trim();
                const sizeToken = sizeStr.split(';', 1)[0].trim();
                if (!/^[0-9A-Fa-f]+$/.test(sizeToken)) {
                    fail(controller, 'Invalid HTTP chunk size');
                    return;
                }
                const chunkSize = parseInt(sizeToken, 16);

                if (!Number.isSafeInteger(chunkSize) || chunkSize < 0 || chunkSize > MAX_CHUNK_SIZE) {
                    fail(controller, 'Invalid HTTP chunk size');
                    return;
                }

                buffer = buffer.subarray(lineEnd + 2);

                if (chunkSize === 0) {
                    while (findTrailerEnd(buffer) === -1) {
                        if (buffer.byteLength > MAX_HEADER_SIZE) {
                            fail(controller, 'HTTP chunk trailers too large');
                            return;
                        }
                        if (!await readMore(controller, 'HTTP chunked body truncated while reading trailers')) return;
                    }
                    streamDone = true;
                    cleanup();
                    controller.close();
                    try { socket.close(); } catch (_) { /* noop */ }
                    return;
                }

                // Need chunkSize data bytes + 2 bytes trailing CRLF
                const totalNeeded = chunkSize + 2;
                while (buffer.byteLength < totalNeeded) {
                    if (!await readMore(controller, 'HTTP chunked body truncated while reading chunk data')) return;
                }

                if (buffer[chunkSize] !== CR || buffer[chunkSize + 1] !== LF) {
                    fail(controller, 'HTTP chunk data missing trailing CRLF');
                    return;
                }

                const chunkData = buffer.subarray(0, chunkSize);
                buffer = buffer.subarray(chunkSize + 2);

                controller.enqueue(chunkData);
                return;
            }
        },
        cancel() {
            cleanup();
            reader.cancel();
            try { socket.close(); } catch (_) { /* noop */ }
        },
    });
}

/**
 * Direct stream — pipe until close (no Content-Length, not chunked).
 */
function createDirectStream(reader, initialData, socket, signal, cleanup) {
    let sentInitial = false;
    return new ReadableStream({
        pull(controller) {
            throwIfAborted(signal);
            if (!sentInitial) {
                sentInitial = true;
                if (initialData.byteLength > 0) {
                    controller.enqueue(initialData);
                    return;
                }
            }
            return reader.read().then(({ value, done }) => {
                if (done) {
                    cleanup();
                    try { socket.close(); } catch (_) { /* noop */ }
                    controller.close();
                    return;
                }
                if (value && value.byteLength === 0) {
                    return;
                }
                controller.enqueue(value);
            }).catch((err) => {
                cleanup();
                try { socket.close(); } catch (_) { /* noop */ }
                controller.error(signal && signal.aborted ? makeAbortError(signal) : toError(err));
            });
        },
        cancel() {
            cleanup();
            reader.cancel();
            try { socket.close(); } catch (_) { /* noop */ }
        },
    });
}

async function normalizeHttp11Body(body) {
    if (body == null) return { kind: 'none' };
    if (typeof body === 'string') return { kind: 'bytes', bytes: textEncoder.encode(body) };
    if (body instanceof Uint8Array) return { kind: 'bytes', bytes: body };
    if (body instanceof ArrayBuffer) return { kind: 'bytes', bytes: new Uint8Array(body) };
    if (ArrayBuffer.isView(body)) {
        return { kind: 'bytes', bytes: new Uint8Array(body.buffer, body.byteOffset, body.byteLength) };
    }
    if (typeof URLSearchParams === 'function' && body instanceof URLSearchParams) {
        return { kind: 'bytes', bytes: textEncoder.encode(body.toString()) };
    }
    if (typeof Blob === 'function' && body instanceof Blob) {
        return { kind: 'stream', stream: body.stream() };
    }
    if (body instanceof ReadableStream) return { kind: 'stream', stream: body };
    if (typeof FormData === 'function' && body instanceof FormData) {
        throw new Error('FormData request bodies are not supported yet');
    }
    throw new Error(`Unsupported request body type: ${Object.prototype.toString.call(body)}`);
}

async function writeHttp11Body(writer, bodyMode, signal) {
    throwIfAborted(signal);
    if (bodyMode.kind === 'none') return;
    if (bodyMode.kind === 'bytes') {
        if (bodyMode.bytes.byteLength > 0) await writer.write(bodyMode.bytes);
        return;
    }

    const reader = bodyMode.stream.getReader();
    let abortHandler = null;
    try {
        if (signal) {
            abortHandler = () => {
                try { reader.cancel(makeAbortError(signal)); } catch (_) { /* noop */ }
            };
            signal.addEventListener('abort', abortHandler, { once: true });
        }
        while (true) {
            throwIfAborted(signal);
            const { value, done } = await reader.read();
            if (done) break;
            const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
            if (chunk.byteLength === 0) continue;
            await writer.write(textEncoder.encode(`${chunk.byteLength.toString(16)}\r\n`));
            await writer.write(chunk);
            await writer.write(textEncoder.encode('\r\n'));
        }
        throwIfAborted(signal);
        await writer.write(textEncoder.encode('0\r\n\r\n'));
    } finally {
        if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
        try { reader.releaseLock(); } catch (_) { /* noop */ }
    }
}

function makeAbortError(signal) {
    if (signal && signal.reason instanceof Error) return signal.reason;
    if (typeof DOMException === 'function') return new DOMException('Aborted', 'AbortError');
    const err = new Error('Aborted');
    err.name = 'AbortError';
    return err;
}

function shouldFallbackToHttp11(err) {
    return !!(err && err.code === HTTP2_NOT_NEGOTIATED_ERROR_CODE);
}

function assertMethodBodyAllowed(method, bodyMode, protocol) {
    if ((method === 'GET' || method === 'HEAD') && bodyMode.kind !== 'none') {
        throw new Error(`${protocol}: ${method} requests cannot have a body`);
    }
}

function toError(err) {
    return err instanceof Error ? err : new Error(String(err));
}

function throwIfAborted(signal) {
    if (signal && signal.aborted) throw makeAbortError(signal);
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

function findTrailerEnd(buf) {
    if (buf.byteLength >= 2 && buf[0] === CR && buf[1] === LF) return 2;
    const headerEnd = findHeaderEnd(buf);
    return headerEnd === -1 ? -1 : headerEnd + 4;
}

function parseStrictContentLength(values) {
    if (values.length === 0) return null;
    const parts = [];
    for (const value of values) {
        for (const part of String(value).split(',')) {
            const trimmed = part.trim();
            if (!/^(0|[1-9][0-9]*)$/.test(trimmed)) {
                throw new Error(`Invalid Content-Length: ${value}`);
            }
            parts.push(trimmed);
        }
    }
    const first = parts[0];
    for (const part of parts) {
        if (part !== first) {
            throw new Error(`Conflicting Content-Length values: ${values.join(', ')}`);
        }
    }
    const n = Number(first);
    if (!Number.isSafeInteger(n) || n < 0) {
        throw new Error(`Invalid Content-Length: ${first}`);
    }
    return n;
}

function appendBuffer(a, b) {
    if (a.byteLength === 0) return b;
    const result = new Uint8Array(a.byteLength + b.byteLength);
    result.set(a, 0);
    result.set(b, a.byteLength);
    return result;
}
