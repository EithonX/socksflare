/**
 * Experimental HTTP/2 fetch over SOCKS5 + Rustls WASM TLS.
 *
 * This module provides a single-stream HTTP/2 client path intended for
 * controlled rollout while keeping the existing HTTP/1.1 path intact.
 *
 * @module proxy-fetch-http2
 * @license GPL-3.0-or-later
 */

import { socks5Connect } from './socks5-client.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const HTTP2_PREFACE = encoder.encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

const FRAME_DATA = 0x0;
const FRAME_HEADERS = 0x1;
const FRAME_RST_STREAM = 0x3;
const FRAME_SETTINGS = 0x4;
const FRAME_PING = 0x6;
const FRAME_GOAWAY = 0x7;
const FRAME_WINDOW_UPDATE = 0x8;
const FRAME_CONTINUATION = 0x9;

const FLAG_ACK = 0x1;
const FLAG_END_STREAM = 0x1;
const FLAG_END_HEADERS = 0x4;
const FLAG_PADDED = 0x8;
const FLAG_PRIORITY = 0x20;

const SETTINGS_HEADER_TABLE_SIZE = 0x1;
const SETTINGS_ENABLE_PUSH = 0x2;

const DEFAULT_MAX_FRAME_SIZE = 16384;
const DEFAULT_HEADER_TABLE_SIZE = 4096;
const MAX_WINDOW_INCREMENT = 0x7fffffff;

// RFC 7541 static table (1-based index).
const HPACK_STATIC_TABLE = [
    null,
    [':authority', ''],
    [':method', 'GET'],
    [':method', 'POST'],
    [':path', '/'],
    [':path', '/index.html'],
    [':scheme', 'http'],
    [':scheme', 'https'],
    [':status', '200'],
    [':status', '204'],
    [':status', '206'],
    [':status', '304'],
    [':status', '400'],
    [':status', '404'],
    [':status', '500'],
    ['accept-charset', ''],
    ['accept-encoding', 'gzip, deflate'],
    ['accept-language', ''],
    ['accept-ranges', ''],
    ['accept', ''],
    ['access-control-allow-origin', ''],
    ['age', ''],
    ['allow', ''],
    ['authorization', ''],
    ['cache-control', ''],
    ['content-disposition', ''],
    ['content-encoding', ''],
    ['content-language', ''],
    ['content-length', ''],
    ['content-location', ''],
    ['content-range', ''],
    ['content-type', ''],
    ['cookie', ''],
    ['date', ''],
    ['etag', ''],
    ['expect', ''],
    ['expires', ''],
    ['from', ''],
    ['host', ''],
    ['if-match', ''],
    ['if-modified-since', ''],
    ['if-none-match', ''],
    ['if-range', ''],
    ['if-unmodified-since', ''],
    ['last-modified', ''],
    ['link', ''],
    ['location', ''],
    ['max-forwards', ''],
    ['proxy-authenticate', ''],
    ['proxy-authorization', ''],
    ['range', ''],
    ['referer', ''],
    ['refresh', ''],
    ['retry-after', ''],
    ['server', ''],
    ['set-cookie', ''],
    ['strict-transport-security', ''],
    ['transfer-encoding', ''],
    ['user-agent', ''],
    ['vary', ''],
    ['via', ''],
    ['www-authenticate', ''],
];

const HPACK_HUFFMAN_EOS = 256;

// RFC 7541 Appendix B. Code lengths indexed by symbol [0..256] (EOS at 256).
const HPACK_HUFFMAN_CODE_LENGTHS = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
];

const HPACK_HUFFMAN_DECODE_TREE = buildHpackHuffmanDecodeTree();

export async function proxyFetchHttp2(url, requestInit = {}, proxyConfig, options = {}) {
    const targetHost = url.hostname;
    const targetPort = parseInt(url.port, 10) || 443;
    const tlsHostname = options.tlsHostname || targetHost;
    const tunnel = await socks5Connect(proxyConfig, targetHost, targetPort, {
        enableTls: true,
        tlsHostname,
        alpnProtocols: ['h2', 'http/1.1'],
    });

    const negotiated = tunnel.alpnProtocol || null;
    if (negotiated !== 'h2') {
        try { await tunnel.socket.close(); } catch (_) { /* noop */ }
        throw new Error(`HTTP/2 not negotiated (ALPN=${negotiated || 'none'})`);
    }

    const frameReader = new H2FrameReader(tunnel.readable.getReader());
    const frameWriter = tunnel.writable.getWriter();
    const hpackDecoder = new HpackDecoder(DEFAULT_HEADER_TABLE_SIZE);

    try {
        await frameWriter.write(HTTP2_PREFACE);
        await writeFrame(frameWriter, FRAME_SETTINGS, 0x00, 0, buildSettingsPayload([
            [SETTINGS_HEADER_TABLE_SIZE, 0],
            [SETTINGS_ENABLE_PUSH, 0],
        ]));

        const method = (requestInit.method || 'GET').toUpperCase();
        const bodyMode = normalizeRequestBody(requestInit.body);
        const headersList = buildRequestHeaders(url, requestInit, method, bodyMode);
        const headerBlock = encodeRequestHeaderBlock(headersList);

        const streamId = 1;
        const headersEndStream = bodyMode.kind === 'none';
        await writeHeaderBlock(frameWriter, streamId, headerBlock, headersEndStream);

        const windowTracker = new WindowTracker();

        // Start write operation concurrently so we can read WINDOW_UPDATE frames
        const writePromise = (async () => {
            if (bodyMode.kind === 'bytes') {
                await writeDataBytes(frameWriter, windowTracker, streamId, bodyMode.bytes, true);
            } else if (bodyMode.kind === 'stream') {
                await writeDataStream(frameWriter, windowTracker, streamId, bodyMode.stream);
            }
        })().catch(err => {
            console.error('HTTP/2 write error:', err);
            try { tunnel.socket.close(); } catch (_) { /* noop */ }
        });

        return await readResponse(frameReader, frameWriter, streamId, hpackDecoder, tunnel.socket, windowTracker);
    } catch (err) {
        try { frameReader.releaseLock(); } catch (_) { /* noop */ }
        try { frameWriter.releaseLock(); } catch (_) { /* noop */ }
        try { await tunnel.socket.close(); } catch (_) { /* noop */ }
        throw err;
    }
}

class H2FrameReader {
    constructor(reader) {
        this.reader = reader;
        this.buffer = new Uint8Array(0);
    }

    async readExact(n) {
        while (this.buffer.byteLength < n) {
            const { done, value } = await this.reader.read();
            if (done) {
                throw new Error('HTTP/2: unexpected EOF');
            }
            if (value && value.byteLength > 0) {
                this.buffer = appendBuffer(this.buffer, value);
            }
        }

        const out = this.buffer.subarray(0, n);
        this.buffer = this.buffer.subarray(n);
        return out;
    }

    async readFrame() {
        const head = await this.readExact(9);
        const length = (head[0] << 16) | (head[1] << 8) | head[2];
        const type = head[3];
        const flags = head[4];
        const streamId = ((head[5] & 0x7f) << 24) | (head[6] << 16) | (head[7] << 8) | head[8];
        const payload = length > 0 ? await this.readExact(length) : new Uint8Array(0);
        return { length, type, flags, streamId, payload };
    }

    releaseLock() {
        this.reader.releaseLock();
    }
}

class WindowTracker {
    constructor(initialWindowSize = 65535, maxFrameSize = DEFAULT_MAX_FRAME_SIZE) {
        this.connectionWindow = initialWindowSize;
        this.streamWindows = new Map();
        this.streamWindows.set(1, initialWindowSize); // Stream 1 supported initially
        this.initialWindowSize = initialWindowSize;
        this.maxFrameSize = maxFrameSize;
        this.waiters = [];
    }

    updateMaxFrameSize(size) {
        this.maxFrameSize = Math.max(16384, Math.min(size, 16777215));
        this._notify();
    }
    
    updateInitialWindowSize(newSize) {
        const diff = newSize - this.initialWindowSize;
        this.initialWindowSize = newSize;
        for (const [id, current] of this.streamWindows.entries()) {
            this.streamWindows.set(id, current + diff);
        }
        this._notify();
    }

    addCredits(streamId, increment) {
        if (streamId === 0) {
            this.connectionWindow += increment;
        } else {
            const current = this.streamWindows.get(streamId) || this.initialWindowSize;
            this.streamWindows.set(streamId, current + increment);
        }
        this._notify();
    }

    async waitForCredits(streamId, requestedBytes) {
        while (true) {
            const streamWin = this.streamWindows.get(streamId) || this.initialWindowSize;
            const available = Math.min(this.connectionWindow, streamWin, this.maxFrameSize);
            
            if (available > 0) {
                const take = Math.min(available, requestedBytes);
                this.connectionWindow -= take;
                this.streamWindows.set(streamId, streamWin - take);
                return take;
            }
            
            await new Promise(resolve => this.waiters.push(resolve));
        }
    }

    _notify() {
        if (this.waiters.length > 0) {
            const resolveAll = this.waiters;
            this.waiters = [];
            for (const r of resolveAll) r();
        }
    }
}

class HpackDecoder {
    constructor(maxDynamicSize = DEFAULT_HEADER_TABLE_SIZE) {
        this.dynamicTable = [];
        this.dynamicTableSize = 0;
        this.maxDynamicSize = maxDynamicSize;
    }

    decode(headerBlock) {
        const out = [];
        let offset = 0;

        while (offset < headerBlock.byteLength) {
            const b = headerBlock[offset];

            if ((b & 0x80) === 0x80) {
                const decoded = decodeHpackInt(headerBlock, offset, 7);
                const header = this.getByIndex(decoded.value);
                if (header) out.push(header);
                offset = decoded.nextOffset;
                continue;
            }

            if ((b & 0xc0) === 0x40) {
                const decoded = decodeHpackInt(headerBlock, offset, 6);
                let name = '';
                offset = decoded.nextOffset;

                if (decoded.value === 0) {
                    const nameDecoded = decodeHpackString(headerBlock, offset);
                    name = nameDecoded.value || '';
                    offset = nameDecoded.nextOffset;
                } else {
                    const indexed = this.getByIndex(decoded.value);
                    name = indexed ? indexed[0] : '';
                }

                const valueDecoded = decodeHpackString(headerBlock, offset);
                const value = valueDecoded.value || '';
                offset = valueDecoded.nextOffset;

                this.addDynamic(name, value);
                if (name) out.push([name, value]);
                continue;
            }

            if ((b & 0xf0) === 0x00 || (b & 0xf0) === 0x10) {
                const decoded = decodeHpackInt(headerBlock, offset, 4);
                let name = '';
                offset = decoded.nextOffset;

                if (decoded.value === 0) {
                    const nameDecoded = decodeHpackString(headerBlock, offset);
                    name = nameDecoded.value || '';
                    offset = nameDecoded.nextOffset;
                } else {
                    const indexed = this.getByIndex(decoded.value);
                    name = indexed ? indexed[0] : '';
                }

                const valueDecoded = decodeHpackString(headerBlock, offset);
                const value = valueDecoded.value || '';
                offset = valueDecoded.nextOffset;

                if (name) out.push([name, value]);
                continue;
            }

            if ((b & 0xe0) === 0x20) {
                const decoded = decodeHpackInt(headerBlock, offset, 5);
                this.updateDynamicSize(decoded.value);
                offset = decoded.nextOffset;
                continue;
            }

            throw new Error('HTTP/2 HPACK: unsupported header representation');
        }

        return out;
    }

    getByIndex(index) {
        if (index <= 0) return null;
        if (index < HPACK_STATIC_TABLE.length) {
            return HPACK_STATIC_TABLE[index];
        }
        const dyn = index - (HPACK_STATIC_TABLE.length - 1);
        return this.dynamicTable[dyn - 1] || null;
    }

    addDynamic(name, value) {
        const size = 32 + encoder.encode(name).byteLength + encoder.encode(value).byteLength;

        if (size > this.maxDynamicSize) {
            this.dynamicTable = [];
            this.dynamicTableSize = 0;
            return;
        }

        while (this.dynamicTableSize + size > this.maxDynamicSize && this.dynamicTable.length > 0) {
            const evicted = this.dynamicTable.pop();
            this.dynamicTableSize -= evicted ? evicted.size : 0;
        }

        const entry = [name, value];
        entry.size = size;
        this.dynamicTable.unshift(entry);
        this.dynamicTableSize += size;
    }

    updateDynamicSize(newSize) {
        this.maxDynamicSize = newSize;
        while (this.dynamicTableSize > this.maxDynamicSize && this.dynamicTable.length > 0) {
            const evicted = this.dynamicTable.pop();
            this.dynamicTableSize -= evicted ? evicted.size : 0;
        }
    }
}

async function readResponse(frameReader, frameWriter, streamId, hpackDecoder, socket, windowTracker) {
    const headers = new Headers();
    let status = 200;
    let statusSeen = false;
    let streamEnded = false;
    let responseHeadersComplete = false;
    const initialBodyChunks = [];

    while (!streamEnded) {
        const frame = await frameReader.readFrame();

        if (frame.streamId === 0) {
            await handleConnectionFrame(frameWriter, frame, windowTracker);
            continue;
        }

        if (frame.streamId !== streamId) {
            continue;
        }

        if (frame.type === FRAME_WINDOW_UPDATE) {
            if (frame.payload.byteLength === 4) {
                const increment = ((frame.payload[0] & 0x7f) << 24) | (frame.payload[1] << 16) | (frame.payload[2] << 8) | frame.payload[3];
                windowTracker.addCredits(streamId, increment);
            }
            continue;
        }

        if (frame.type === FRAME_HEADERS) {
            const block = await collectHeaderBlock(frameReader, frameWriter, streamId, frame);
            const decoded = hpackDecoder.decode(block.headerBlock);

            if (!responseHeadersComplete) {
                const parsedStatus = getStatusFromDecoded(decoded);
                if (parsedStatus >= 100 && parsedStatus < 200 && parsedStatus !== 101) {
                    // Informational response block (e.g. 100 Continue), keep waiting for final headers.
                    continue;
                }

                if (parsedStatus > 0) {
                    status = parsedStatus;
                    statusSeen = true;
                }
                applyRegularHeaders(decoded, headers);
                responseHeadersComplete = true;
            } else {
                // Trailers: append only regular headers.
                applyTrailerHeaders(decoded, headers);
            }

            if (block.endStream) {
                streamEnded = true;
            }
            continue;
        }

        if (frame.type === FRAME_DATA) {
            if (!responseHeadersComplete) {
                throw new Error('HTTP/2: DATA received before response HEADERS');
            }
            const parsed = parseDataPayload(frame.payload, frame.flags);
            if (parsed.data.byteLength > 0) {
                initialBodyChunks.push(parsed.data);

                await sendWindowUpdate(frameWriter, 0, parsed.data.byteLength);
                await sendWindowUpdate(frameWriter, streamId, parsed.data.byteLength);
            }

            if (parsed.endStream) {
                streamEnded = true;
            }
            continue;
        }

        if (frame.type === FRAME_RST_STREAM) {
            throw new Error('HTTP/2: stream reset by peer');
        }

        if (frame.type === FRAME_GOAWAY) {
            throw new Error('HTTP/2: peer sent GOAWAY');
        }
    }

    if (!statusSeen) {
        throw new Error('HTTP/2: response missing :status pseudo-header');
    }

    if (streamEnded && initialBodyChunks.length === 0) {
        try { frameReader.releaseLock(); } catch (_) { /* noop */ }
        try { frameWriter.releaseLock(); } catch (_) { /* noop */ }
        try { await socket.close(); } catch (_) { /* noop */ }
        return new Response(null, { status, headers });
    }

    const bodyStream = createHttp2BodyStream({
        frameReader,
        frameWriter,
        streamId,
        hpackDecoder,
        headers,
        initialBodyChunks,
        streamEnded,
        socket,
        windowTracker,
    });
    return new Response(bodyStream, { status, headers });
}

async function handleConnectionFrame(frameWriter, frame, windowTracker) {
    if (frame.type === FRAME_SETTINGS) {
        if ((frame.flags & FLAG_ACK) === FLAG_ACK) {
            return;
        }
        if ((frame.payload.byteLength % 6) !== 0) {
            throw new Error('HTTP/2: invalid SETTINGS payload length');
        }
        
        for (let i = 0; i < frame.payload.byteLength; i += 6) {
            const id = (frame.payload[i] << 8) | frame.payload[i + 1];
            const val = (frame.payload[i+2] << 24) | (frame.payload[i+3] << 16) | (frame.payload[i+4] << 8) | frame.payload[i+5];
            if (id === 0x4) { // SETTINGS_INITIAL_WINDOW_SIZE
                windowTracker.updateInitialWindowSize(val);
            } else if (id === 0x5) { // SETTINGS_MAX_FRAME_SIZE
                windowTracker.updateMaxFrameSize(val);
            }
        }

        await writeFrame(frameWriter, FRAME_SETTINGS, FLAG_ACK, 0, new Uint8Array(0));
        return;
    }

    if (frame.type === FRAME_WINDOW_UPDATE) {
        if (frame.payload.byteLength === 4) {
            const increment = ((frame.payload[0] & 0x7f) << 24) | (frame.payload[1] << 16) | (frame.payload[2] << 8) | frame.payload[3];
            windowTracker.addCredits(0, increment);
        }
        return;
    }

    if (frame.type === FRAME_PING) {
        if (frame.payload.byteLength !== 8) {
            return;
        }
        if ((frame.flags & FLAG_ACK) === FLAG_ACK) {
            return;
        }
        await writeFrame(frameWriter, FRAME_PING, FLAG_ACK, 0, frame.payload);
        return;
    }

    // Ignore WINDOW_UPDATE and other connection-level frames we do not need for now.
}

function getStatusFromDecoded(decoded) {
    for (const [name, value] of decoded) {
        if (!name) continue;
        if (name !== ':status') continue;
        const code = parseInt(value, 10);
        if (!Number.isNaN(code)) return code;
    }
    return 0;
}

function applyRegularHeaders(decoded, headers) {
    for (const [name, value] of decoded) {
        if (!name || name[0] === ':' || value == null) continue;
        headers.append(name, value);
    }
}

function applyTrailerHeaders(decoded, headers) {
    for (const [name, value] of decoded) {
        if (!name || name[0] === ':' || value == null) continue;
        headers.append(name, value);
    }
}

async function collectHeaderBlock(frameReader, frameWriter, streamId, firstHeadersFrame) {
    const parsed = parseHeadersPayload(firstHeadersFrame.payload, firstHeadersFrame.flags);
    const fragments = [parsed.fragment];

    if (parsed.endHeaders) {
        return { headerBlock: concatChunks(fragments), endStream: parsed.endStream };
    }

    while (true) {
        const frame = await frameReader.readFrame();

        if (frame.streamId === 0) {
            await handleConnectionFrame(frameWriter, frame);
            continue;
        }

        if (frame.streamId !== streamId || frame.type !== FRAME_CONTINUATION) {
            throw new Error('HTTP/2: invalid continuation sequence');
        }

        fragments.push(frame.payload);
        if ((frame.flags & FLAG_END_HEADERS) === FLAG_END_HEADERS) {
            return { headerBlock: concatChunks(fragments), endStream: parsed.endStream };
        }
    }
}

function createHttp2BodyStream({
    frameReader,
    frameWriter,
    streamId,
    hpackDecoder,
    headers,
    initialBodyChunks,
    streamEnded,
    socket,
    windowTracker,
}) {
    const queue = [...initialBodyChunks];
    let done = streamEnded;
    let reading = false;
    let cleanedUp = false;

    async function cleanup() {
        if (cleanedUp) return;
        cleanedUp = true;
        try { frameReader.releaseLock(); } catch (_) { /* noop */ }
        try { frameWriter.releaseLock(); } catch (_) { /* noop */ }
        try { await socket.close(); } catch (_) { /* noop */ }
    }

    async function readUntilChunkOrDone(controller) {
        while (!done) {
            const frame = await frameReader.readFrame();

            if (frame.streamId === 0) {
                await handleConnectionFrame(frameWriter, frame, windowTracker);
                continue;
            }

            if (frame.streamId !== streamId) {
                continue;
            }

            if (frame.type === FRAME_WINDOW_UPDATE) {
                if (frame.payload.byteLength === 4) {
                    const increment = ((frame.payload[0] & 0x7f) << 24) | (frame.payload[1] << 16) | (frame.payload[2] << 8) | frame.payload[3];
                    windowTracker.addCredits(streamId, increment);
                }
                continue;
            }

            if (frame.type === FRAME_DATA) {
                const parsed = parseDataPayload(frame.payload, frame.flags);
                if (parsed.data.byteLength > 0) {
                    await sendWindowUpdate(frameWriter, 0, parsed.data.byteLength);
                    await sendWindowUpdate(frameWriter, streamId, parsed.data.byteLength);
                    controller.enqueue(parsed.data);
                }
                if (parsed.endStream) {
                    done = true;
                }
                return;
            }

            if (frame.type === FRAME_HEADERS) {
                // Trailer headers.
                const block = await collectHeaderBlock(frameReader, frameWriter, streamId, frame);
                const decoded = hpackDecoder.decode(block.headerBlock);
                applyTrailerHeaders(decoded, headers);
                if (block.endStream) {
                    done = true;
                }
                continue;
            }

            if (frame.type === FRAME_RST_STREAM) {
                throw new Error('HTTP/2: stream reset by peer');
            }

            if (frame.type === FRAME_GOAWAY) {
                throw new Error('HTTP/2: peer sent GOAWAY');
            }
        }
    }

    return new ReadableStream({
        async pull(controller) {
            if (queue.length > 0) {
                controller.enqueue(queue.shift());
                if (queue.length === 0 && done) {
                    controller.close();
                    await cleanup();
                }
                return;
            }

            if (done) {
                controller.close();
                await cleanup();
                return;
            }

            if (reading) return;
            reading = true;
            try {
                await readUntilChunkOrDone(controller);
                if (done) {
                    controller.close();
                    await cleanup();
                }
            } catch (err) {
                done = true;
                controller.error(err);
                await cleanup();
            } finally {
                reading = false;
            }
        },
        async cancel() {
            done = true;
            await cleanup();
        },
    });
}

function parseHeadersPayload(payload, flags) {
    let offset = 0;
    let padLength = 0;

    if ((flags & FLAG_PADDED) === FLAG_PADDED) {
        padLength = payload[offset];
        offset += 1;
    }

    if ((flags & FLAG_PRIORITY) === FLAG_PRIORITY) {
        offset += 5;
    }

    if (offset > payload.byteLength || (offset + padLength) > payload.byteLength) {
        throw new Error('HTTP/2: malformed HEADERS payload');
    }

    const fragment = payload.subarray(offset, payload.byteLength - padLength);
    return {
        fragment,
        endHeaders: (flags & FLAG_END_HEADERS) === FLAG_END_HEADERS,
        endStream: (flags & FLAG_END_STREAM) === FLAG_END_STREAM,
    };
}

function parseDataPayload(payload, flags) {
    let offset = 0;
    let padLength = 0;

    if ((flags & FLAG_PADDED) === FLAG_PADDED) {
        padLength = payload[offset];
        offset += 1;
    }

    if (offset > payload.byteLength || (offset + padLength) > payload.byteLength) {
        throw new Error('HTTP/2: malformed DATA payload');
    }

    return {
        data: payload.subarray(offset, payload.byteLength - padLength),
        endStream: (flags & FLAG_END_STREAM) === FLAG_END_STREAM,
    };
}

function normalizeRequestBody(body) {
    if (body == null) return { kind: 'none' };

    if (typeof body === 'string') {
        return { kind: 'bytes', bytes: encoder.encode(body) };
    }

    if (body instanceof Uint8Array) {
        return { kind: 'bytes', bytes: body };
    }

    if (body instanceof ArrayBuffer) {
        return { kind: 'bytes', bytes: new Uint8Array(body) };
    }

    if (body instanceof ReadableStream) {
        return { kind: 'stream', stream: body };
    }

    // Fallback to string serialization to keep behavior deterministic.
    return { kind: 'bytes', bytes: encoder.encode(String(body)) };
}

function buildRequestHeaders(url, requestInit, method, bodyMode) {
    const path = `${url.pathname || '/'}${url.search || ''}`;
    const authority = url.port ? `${url.hostname}:${url.port}` : url.hostname;
    const scheme = url.protocol.replace(':', '');

    const headers = new Headers(requestInit.headers || {});
    headers.set('host', authority);
    headers.set('accept-encoding', 'identity');

    if (!headers.has('user-agent')) {
        headers.set('user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    }
    if (!headers.has('accept')) {
        headers.set('accept', '*/*');
    }

    if (bodyMode.kind === 'bytes' && !headers.has('content-length')) {
        headers.set('content-length', String(bodyMode.bytes.byteLength));
    }

    const dropHeaders = new Set([
        'connection',
        'proxy-connection',
        'keep-alive',
        'upgrade',
        'transfer-encoding',
        'http2-settings',
        'host',
        'te',
    ]);

    const out = [
        [':method', method],
        [':scheme', scheme],
        [':authority', authority],
        [':path', path],
    ];

    for (const [rawName, rawValue] of headers.entries()) {
        const name = rawName.toLowerCase().trim();
        if (!name || name[0] === ':' || dropHeaders.has(name)) continue;
        if (
            name.startsWith('cf-') ||
            name.startsWith('x-forwarded-') ||
            name === 'x-real-ip' ||
            name === 'true-client-ip' ||
            name === 'forwarded' ||
            name === 'via' ||
            name === 'cdn-loop'
        ) {
            continue;
        }
        const value = String(rawValue).replace(/[\r\n]/g, '');
        out.push([name, value]);
    }

    return out;
}

function encodeRequestHeaderBlock(headersList) {
    const parts = [];
    for (const [name, value] of headersList) {
        parts.push(encodeLiteralHeaderNoIndex(name, value));
    }
    return concatChunks(parts);
}

function encodeLiteralHeaderNoIndex(name, value) {
    // Literal Header Field without Indexing, new name (0000 pattern, name index = 0)
    const prefix = encodeHpackInt(0, 4, 0x00);
    const encodedName = encodeHpackString(name);
    const encodedValue = encodeHpackString(value);
    return concatChunks([prefix, encodedName, encodedValue]);
}

function encodeHpackString(str) {
    const bytes = encoder.encode(String(str));
    const length = encodeHpackInt(bytes.byteLength, 7, 0x00); // Huffman bit = 0
    return concatChunks([length, bytes]);
}

function encodeHpackInt(value, prefixBits, firstByteMask) {
    const maxPrefix = (1 << prefixBits) - 1;
    if (value < maxPrefix) {
        return Uint8Array.of(firstByteMask | value);
    }

    const out = [firstByteMask | maxPrefix];
    let n = value - maxPrefix;
    while (n >= 128) {
        out.push((n % 128) + 128);
        n = Math.floor(n / 128);
    }
    out.push(n);
    return Uint8Array.from(out);
}

function decodeHpackInt(buf, offset, prefixBits) {
    if (offset >= buf.byteLength) {
        throw new Error('HTTP/2 HPACK: truncated integer');
    }

    const mask = (1 << prefixBits) - 1;
    let value = buf[offset] & mask;
    offset += 1;

    if (value < mask) {
        return { value, nextOffset: offset };
    }

    let m = 0;
    while (true) {
        if (offset >= buf.byteLength) {
            throw new Error('HTTP/2 HPACK: truncated integer continuation');
        }
        const b = buf[offset];
        offset += 1;

        value += (b & 0x7f) << m;
        if ((b & 0x80) === 0) break;

        m += 7;
        if (m > 28) throw new Error('HTTP/2 HPACK: integer too large');
    }

    return { value, nextOffset: offset };
}

function decodeHpackString(buf, offset) {
    if (offset >= buf.byteLength) {
        throw new Error('HTTP/2 HPACK: truncated string');
    }

    const huffman = (buf[offset] & 0x80) === 0x80;
    const lengthDecoded = decodeHpackInt(buf, offset, 7);
    const length = lengthDecoded.value;
    offset = lengthDecoded.nextOffset;

    if ((offset + length) > buf.byteLength) {
        throw new Error('HTTP/2 HPACK: truncated string bytes');
    }

    const bytes = buf.subarray(offset, offset + length);
    offset += length;

    if (huffman) {
        return { value: decodeHpackHuffman(bytes), nextOffset: offset };
    }

    return { value: decoder.decode(bytes), nextOffset: offset };
}

function buildHpackHuffmanDecodeTree() {
    const root = createHpackHuffmanNode();
    const symbols = [];

    for (let sym = 0; sym < HPACK_HUFFMAN_CODE_LENGTHS.length; sym++) {
        symbols.push({ sym, len: HPACK_HUFFMAN_CODE_LENGTHS[sym] });
    }
    symbols.sort((a, b) => (a.len - b.len) || (a.sym - b.sym));

    let code = 0;
    let prevLen = 0;

    for (const { sym, len } of symbols) {
        code <<= (len - prevLen);
        insertHpackHuffmanCode(root, code, len, sym);
        code += 1;
        prevLen = len;
    }
    return root;
}

function createHpackHuffmanNode() {
    return { zero: null, one: null, sym: -1 };
}

function insertHpackHuffmanCode(root, code, len, sym) {
    let node = root;
    for (let i = len - 1; i >= 0; i--) {
        const bit = (code >>> i) & 1;
        if (bit === 0) {
            if (!node.zero) node.zero = createHpackHuffmanNode();
            node = node.zero;
        } else {
            if (!node.one) node.one = createHpackHuffmanNode();
            node = node.one;
        }
    }

    if (node.sym !== -1) {
        throw new Error('HTTP/2 HPACK: duplicate Huffman symbol in decode tree');
    }
    if (node.zero || node.one) {
        throw new Error('HTTP/2 HPACK: invalid Huffman tree insertion');
    }
    node.sym = sym;
}

function decodeHpackHuffman(bytes) {
    const decoded = [];
    let node = HPACK_HUFFMAN_DECODE_TREE;
    let bitsSinceSymbol = 0;
    let trailingOnes = 0;

    for (let i = 0; i < bytes.byteLength; i++) {
        const b = bytes[i];
        for (let bitPos = 7; bitPos >= 0; bitPos--) {
            const bit = (b >> bitPos) & 1;
            node = bit === 0 ? node.zero : node.one;
            if (!node) {
                throw new Error('HTTP/2 HPACK: invalid Huffman code');
            }

            bitsSinceSymbol += 1;
            trailingOnes = bit === 1 ? (trailingOnes + 1) : 0;

            if (node.sym !== -1) {
                if (node.sym === HPACK_HUFFMAN_EOS) {
                    throw new Error('HTTP/2 HPACK: EOS symbol is not allowed in string literal');
                }
                decoded.push(node.sym);
                node = HPACK_HUFFMAN_DECODE_TREE;
                bitsSinceSymbol = 0;
                trailingOnes = 0;
            }
        }
    }

    if (node !== HPACK_HUFFMAN_DECODE_TREE) {
        if (bitsSinceSymbol > 7 || trailingOnes !== bitsSinceSymbol) {
            throw new Error('HTTP/2 HPACK: invalid Huffman padding');
        }
    }

    return decoder.decode(Uint8Array.from(decoded));
}

async function writeHeaderBlock(writer, streamId, headerBlock, endStream) {
    let offset = 0;
    let first = true;

    while (offset < headerBlock.byteLength || first) {
        const remaining = Math.max(0, headerBlock.byteLength - offset);
        const take = Math.min(DEFAULT_MAX_FRAME_SIZE, remaining);
        const chunk = headerBlock.subarray(offset, offset + take);
        offset += take;

        let flags = 0x00;
        if (offset >= headerBlock.byteLength) {
            flags |= FLAG_END_HEADERS;
            if (endStream) flags |= FLAG_END_STREAM;
        }

        if (first) {
            await writeFrame(writer, FRAME_HEADERS, flags, streamId, chunk);
            first = false;
        } else {
            await writeFrame(writer, FRAME_CONTINUATION, flags, streamId, chunk);
        }

        if (headerBlock.byteLength === 0) break;
    }
}

async function writeDataBytes(writer, windowTracker, streamId, bytes, endStream) {
    if (!(bytes instanceof Uint8Array)) {
        bytes = new Uint8Array(bytes);
    }

    let offset = 0;
    while (offset < bytes.byteLength) {
        const remaining = bytes.byteLength - offset;
        const take = await windowTracker.waitForCredits(streamId, remaining);

        const chunk = bytes.subarray(offset, offset + take);
        offset += take;
        const flags = (offset >= bytes.byteLength && endStream) ? FLAG_END_STREAM : 0x00;
        await writeFrame(writer, FRAME_DATA, flags, streamId, chunk);
    }

    if (bytes.byteLength === 0 && endStream) {
        await writeFrame(writer, FRAME_DATA, FLAG_END_STREAM, streamId, new Uint8Array(0));
    }
}

async function writeDataStream(writer, windowTracker, streamId, stream) {
    const reader = stream.getReader();
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
            await writeDataBytes(writer, windowTracker, streamId, chunk, false);
        }
        await writeFrame(writer, FRAME_DATA, FLAG_END_STREAM, streamId, new Uint8Array(0));
    } finally {
        try { reader.releaseLock(); } catch (_) { /* noop */ }
    }
}

function buildSettingsPayload(pairs) {
    const payload = new Uint8Array(pairs.length * 6);
    let o = 0;
    for (const [id, value] of pairs) {
        payload[o++] = (id >> 8) & 0xff;
        payload[o++] = id & 0xff;
        payload[o++] = (value >> 24) & 0xff;
        payload[o++] = (value >> 16) & 0xff;
        payload[o++] = (value >> 8) & 0xff;
        payload[o++] = value & 0xff;
    }
    return payload;
}

async function sendWindowUpdate(writer, streamId, increment) {
    if (!Number.isInteger(increment) || increment <= 0) return;
    const inc = Math.min(increment, MAX_WINDOW_INCREMENT);
    const payload = new Uint8Array(4);
    payload[0] = (inc >> 24) & 0x7f; // top bit reserved
    payload[1] = (inc >> 16) & 0xff;
    payload[2] = (inc >> 8) & 0xff;
    payload[3] = inc & 0xff;
    await writeFrame(writer, FRAME_WINDOW_UPDATE, 0x00, streamId, payload);
}

async function writeFrame(writer, type, flags, streamId, payload) {
    const frame = buildFrame(type, flags, streamId, payload);
    await writer.write(frame);
}

function buildFrame(type, flags, streamId, payload) {
    const length = payload.byteLength;
    const out = new Uint8Array(9 + length);
    out[0] = (length >> 16) & 0xff;
    out[1] = (length >> 8) & 0xff;
    out[2] = length & 0xff;
    out[3] = type & 0xff;
    out[4] = flags & 0xff;
    out[5] = (streamId >> 24) & 0x7f; // reserved bit cleared
    out[6] = (streamId >> 16) & 0xff;
    out[7] = (streamId >> 8) & 0xff;
    out[8] = streamId & 0xff;
    out.set(payload, 9);
    return out;
}

function concatChunks(chunks) {
    if (chunks.length === 0) return new Uint8Array(0);
    if (chunks.length === 1) return chunks[0];
    let total = 0;
    for (const c of chunks) total += c.byteLength;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
        out.set(c, offset);
        offset += c.byteLength;
    }
    return out;
}

function appendBuffer(a, b) {
    if (a.byteLength === 0) return b;
    if (b.byteLength === 0) return a;
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(a, 0);
    out.set(b, a.byteLength);
    return out;
}
