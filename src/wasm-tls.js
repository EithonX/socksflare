/**
 * WASM TLS Bridge — JavaScript glue for the Rustls WASM module.
 *
 * Handles the TLS 1.3 handshake and bidirectional data pump between
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
 * Performs a TLS 1.3 handshake over existing readable/writable streams
 * using the Rustls WASM module.
 *
 * @param {ReadableStream} networkReadable - Raw TCP readable (from SOCKS5 tunnel).
 * @param {WritableStream} networkWritable - Raw TCP writable (from SOCKS5 tunnel).
 * @param {string} tlsHostname - SNI hostname for the TLS handshake.
 * @returns {Promise<{readable: ReadableStream, writable: WritableStream}>}
 *   Application-layer streams carrying decrypted data.
 */
export async function wasmTlsHandshake(networkReadable, networkWritable, tlsHostname) {
    if (!wasmInitialized) {
        initSync(wasmModule);
        wasmInitialized = true;
    }

    const client = new WasmTlsClient(tlsHostname);

    // Application-layer readable stream (decrypted data for the caller)
    let appReadableController = null;
    const appReadable = new ReadableStream({
        start(controller) {
            appReadableController = controller;
        }
    });

    const networkReader = networkReadable.getReader();
    const networkWriter = networkWritable.getWriter();

    /**
     * Flushes all pending TLS records from Rustls to the network socket.
     */
    async function flushNetworkWrites() {
        while (client.wants_write()) {
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
                client.write_app_data(chunk);
                await flushNetworkWrites();
            } catch (err) {
                controller.error(err);
            }
        },
        close() {
            client.free();
            try { networkWriter.close(); } catch (_) { /* noop */ }
        }
    });

    return new Promise((resolve, reject) => {
        let resolved = false;

        // Trigger initial ClientHello
        flushNetworkWrites().catch(e => {
            if (!resolved) { resolved = true; reject(e); }
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
                while (true) {
                    const { done, value } = await networkReader.read();
                    if (done) {
                        appReadableController.close();
                        break;
                    }

                    if (value && value.length > 0) {
                        let offset = 0;
                        while (offset < value.length) {
                            const chunk = value.subarray(offset);
                            try {
                                const consumed = client.provide_network_data(chunk);
                                offset += consumed;

                                // consumed === 0 means Rustls can't process more right now.
                                // Break to avoid infinite loop (connection closed or stalled).
                                if (consumed === 0) break;
                            } catch (err) {
                                if (!resolved) {
                                    resolved = true;
                                    return reject(err);
                                } else {
                                    appReadableController.error(err);
                                }
                                return;
                            }

                            await flushNetworkWrites();

                            // Resolve on handshake completion
                            if (!client.is_handshaking() && !resolved) {
                                resolved = true;
                                resolve({ readable: appReadable, writable: appWritable });
                            }

                            // Read any decrypted application data
                            const appData = client.read_app_data();
                            if (appData && appData.length > 0) {
                                appReadableController.enqueue(appData);
                            }
                        }
                    }
                }
            } catch (err) {
                if (!resolved) {
                    resolved = true;
                    reject(err);
                } else {
                    try { appReadableController.error(err); } catch (_) { /* noop */ }
                }
            }
        }

        networkPump().catch(e => {
            if (!resolved) { resolved = true; reject(e); }
        });
    });
}
