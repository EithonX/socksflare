/**
 * WASM TLS Bridge — JavaScript glue for the Rustls WASM module.
 *
 * Handles TLS handshake and bidirectional data pump between
 * the raw SOCKS5 TCP tunnel and the application-layer streams.
 *
 * CRITICAL: The networkPump() loop feeds data to provide_network_data()
 * slice-by-slice using the returned consumed byte count as an offset.
 * A single provide_network_data(wholeChunk) call drops data on
 * responses >64KB. Do NOT simplify this loop.
 *
 * @module wasm-tls
 * @license GPL-3.0-or-later
 */

import { initSync, WasmTlsClient } from '../rust-tls-wasm/pkg/rust_tls_wasm.js';
import wasmModule from '../rust-tls-wasm/pkg/rust_tls_wasm_bg.wasm';

let wasmInitialized = false;

/**
 * Performs TLS handshake over existing readable/writable streams
 * using the Rustls WASM module.
 *
 * @param {ReadableStream} networkReadable - Raw TCP readable (from SOCKS5 tunnel).
 * @param {WritableStream} networkWritable - Raw TCP writable (from SOCKS5 tunnel).
 * @param {string} tlsHostname - SNI hostname for the TLS handshake.
 * @param {Object} [options] - TLS handshake options.
 * @param {string[]} [options.alpnProtocols] - ALPN protocol list in preference order.
 * @param {AbortSignal} [options.signal] - Abort signal for handshake/tunnel teardown.
 * @param {number} [options.maxQueuedAppBytes=4194304] - Max decrypted bytes queued when caller is slow.
 * @returns {Promise<{readable: ReadableStream, writable: WritableStream, alpnProtocol: string|null}>}
 *   Application-layer streams carrying decrypted data.
 */
export async function wasmTlsHandshake(networkReadable, networkWritable, tlsHostname, options = {}) {
    if (!wasmInitialized) {
        initSync({ module: wasmModule });
        wasmInitialized = true;
    }

    const toError = (err) => err instanceof Error ? err : new Error(String(err));
    const signal = options.signal;
    const maxQueuedAppBytes = Number.isInteger(options.maxQueuedAppBytes) && options.maxQueuedAppBytes > 0
        ? options.maxQueuedAppBytes
        : 4 * 1024 * 1024;
    const alpnProtocols = Array.isArray(options.alpnProtocols)
        ? options.alpnProtocols.map(p => String(p).trim()).filter(Boolean)
        : [];
    const alpnCsv = alpnProtocols.join(',');

    if (!tlsHostname || typeof tlsHostname !== 'string' || tlsHostname.length > 253) {
        throw new Error('wasmTls: invalid SNI hostname');
    }

    const client = new WasmTlsClient(tlsHostname, alpnCsv || undefined);
    const abortError = () => {
        if (signal && signal.reason instanceof Error) return signal.reason;
        if (typeof DOMException === 'function') return new DOMException('Aborted', 'AbortError');
        const err = new Error('Aborted');
        err.name = 'AbortError';
        return err;
    };
    if (signal && signal.aborted) {
        client.free();
        throw abortError();
    }

    let appReadableController = null;
    let queuedAppBytes = 0;
    const appQueue = [];
    let demandWaiters = [];

    const appReadable = new ReadableStream({
        start(controller) {
            appReadableController = controller;
        },
        pull() {
            flushAppQueue();
            wakeDemand();
        },
        cancel(reason) {
            teardown(reason instanceof Error ? reason : new Error('wasmTls: app readable cancelled'), {
                readableError: false,
            });
        },
    });

    const networkReader = networkReadable.getReader();
    const networkWriter = networkWritable.getWriter();
    let settled = false;
    let closed = false;
    let freed = false;
    let locksReleased = false;
    let resolveHandshake;
    let rejectHandshake;

    function freeOnce() {
        if (freed) return;
        freed = true;
        try { client.free(); } catch (_) { /* noop */ }
    }

    function releaseLocksOnce() {
        if (locksReleased) return;
        locksReleased = true;
        try { networkReader.releaseLock(); } catch (_) { /* noop */ }
        try { networkWriter.releaseLock(); } catch (_) { /* noop */ }
    }

    function settleReject(err) {
        if (settled) return;
        settled = true;
        rejectHandshake(toError(err));
    }

    function settleResolve(value) {
        if (settled) return;
        settled = true;
        resolveHandshake(value);
    }

    function teardown(err, { readableError = true } = {}) {
        if (closed) return;
        closed = true;
        if (signal) signal.removeEventListener('abort', onAbort);
        if (!settled && err) settleReject(err);
        if (settled && err && readableError && appReadableController) {
            try { appReadableController.error(toError(err)); } catch (_) { /* noop */ }
        }
        try { networkReader.cancel(err).catch(() => { }); } catch (_) { /* noop */ }
        try { networkWriter.abort(err).catch(() => { }); } catch (_) { /* noop */ }
        wakeDemand();
        freeOnce();
        releaseLocksOnce();
    }

    function onAbort() {
        teardown(abortError());
    }

    function wakeDemand() {
        if (demandWaiters.length === 0) return;
        const waiters = demandWaiters;
        demandWaiters = [];
        for (const resolve of waiters) resolve();
    }

    function flushAppQueue() {
        while (
            appReadableController &&
            appQueue.length > 0 &&
            appReadableController.desiredSize > 0
        ) {
            const chunk = appQueue.shift();
            queuedAppBytes -= chunk.byteLength;
            appReadableController.enqueue(chunk);
        }
    }

    function enqueueAppData(appData) {
        if (!appReadableController || closed) return;
        flushAppQueue();
        if (appQueue.length === 0 && appReadableController.desiredSize > 0) {
            appReadableController.enqueue(appData);
            return;
        }
        appQueue.push(appData);
        queuedAppBytes += appData.byteLength;
        if (queuedAppBytes > maxQueuedAppBytes) {
            teardown(new Error(`wasmTls: decrypted data queue exceeded ${maxQueuedAppBytes} bytes`));
        }
    }

    async function waitForAppBackpressure() {
        while (
            !closed &&
            appQueue.length > 0 &&
            appReadableController &&
            appReadableController.desiredSize <= 0
        ) {
            await new Promise(resolve => demandWaiters.push(resolve));
        }
    }

    /**
     * Flushes all pending TLS records from Rustls to the network socket.
     */
    async function flushNetworkWrites() {
        while (!closed && client.wants_write()) {
            const netData = client.extract_network_data();
            if (netData && netData.length > 0) {
                await networkWriter.write(netData);
            }
        }
    }

    // Application-layer writable stream (plaintext data from the caller → Rustls → encrypted)
    const appWritable = new WritableStream({
        async write(chunk, controller) {
            try {
                if (closed) throw new Error('wasmTls: tunnel is closed');
                client.write_app_data(chunk);
                await flushNetworkWrites();
            } catch (err) {
                const e = toError(err);
                controller.error(e);
                teardown(e);
            }
        },
        close() {
            if (!settled) {
                teardown(new Error('wasmTls: app writable closed before TLS handshake completed'), {
                    readableError: false,
                });
                return;
            }
            try { networkWriter.close().catch(() => { }); } catch (_) { /* noop */ }
        }
    });

    return new Promise((resolve, reject) => {
        resolveHandshake = resolve;
        rejectHandshake = reject;
        if (signal) signal.addEventListener('abort', onAbort, { once: true });
        if (signal && signal.aborted) {
            teardown(abortError());
            return;
        }

        // Trigger initial ClientHello
        flushNetworkWrites().catch(e => {
            teardown(toError(e));
        });

        /**
         * Main network pump loop.
         *
         * Reads raw TLS records from the network, feeds them to Rustls
         * slice-by-slice (using the consumed byte offset), flushes any
         * outbound TLS records, and enqueues decrypted application data.
         *
         * The slice-by-slice feeding is CRITICAL:
         * - provide_network_data() returns usize (bytes consumed)
         * - rustls.read_tls() processes one TLS record at a time
         * - A single call with a large chunk truncates data >64KB
         */
        async function networkPump() {
            try {
                while (!closed) {
                    await waitForAppBackpressure();
                    if (closed) break;
                    const { done, value } = await networkReader.read();
                    if (done) {
                        const err = new Error('wasmTls: network closed before TLS handshake completed');
                        if (!settled) {
                            settleReject(err);
                        } else {
                            try { appReadableController.close(); } catch (_) { /* noop */ }
                        }
                        closed = true;
                        if (signal) signal.removeEventListener('abort', onAbort);
                        freeOnce();
                        releaseLocksOnce();
                        break;
                    }

                    if (value && value.length > 0) {
                        let offset = 0;
                        while (!closed && offset < value.length) {
                            const chunk = value.subarray(offset);
                            try {
                                offset = advanceRustlsNetworkOffset(client, value, offset);
                            } catch (err) {
                                const e = toError(err);
                                teardown(e);
                                return;
                            }

                            await flushNetworkWrites();
                            if (closed) return;

                            // Resolve on handshake completion
                            if (!client.is_handshaking() && !settled) {
                                const alpnProtocol = typeof client.negotiatedAlpn === 'function'
                                    ? (client.negotiatedAlpn() || null)
                                    : null;
                                settleResolve({ readable: appReadable, writable: appWritable, alpnProtocol });
                            }

                            // Read any decrypted application data
                            const appData = client.read_app_data();
                            if (appData && appData.length > 0) {
                                enqueueAppData(appData);
                                if (closed) return;
                            }
                        }
                    }
                }
            } catch (err) {
                const e = toError(err);
                teardown(e);
            }
        }

        networkPump().catch(e => {
            teardown(toError(e));
        });
    });
}

function advanceRustlsNetworkOffset(client, sourceChunk, offset) {
    const chunk = sourceChunk.subarray(offset);
    const consumed = client.provide_network_data(chunk);
    if (chunk.byteLength > 0 && consumed === 0) {
        throw new Error('wasmTls: Rustls consumed 0 bytes from non-empty network data');
    }
    return offset + consumed;
}
