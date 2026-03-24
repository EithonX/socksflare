/* tslint:disable */
/* eslint-disable */

export class WasmTlsClient {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Extracts encrypted bytes that Rustls wants to send over the TCP socket.
     */
    extract_network_data(): Uint8Array;
    is_handshaking(): boolean;
    negotiatedAlpn(): string | undefined;
    constructor(hostname: string, alpn_csv?: string | null);
    /**
     * Feeds raw TCP bytes from the SOCKS5 proxy into the Rustls state machine.
     * Returns the number of bytes consumed.
     */
    provide_network_data(data: Uint8Array): number;
    /**
     * Reads decrypted plaintext application data from Rustls.
     */
    read_app_data(): Uint8Array;
    wants_read(): boolean;
    wants_write(): boolean;
    /**
     * Feeds plaintext application data to Rustls to be encrypted.
     */
    write_app_data(data: Uint8Array): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmtlsclient_free: (a: number, b: number) => void;
    readonly wasmtlsclient_extract_network_data: (a: number) => [number, number, number];
    readonly wasmtlsclient_is_handshaking: (a: number) => number;
    readonly wasmtlsclient_negotiatedAlpn: (a: number) => [number, number];
    readonly wasmtlsclient_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmtlsclient_provide_network_data: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmtlsclient_read_app_data: (a: number) => [number, number, number];
    readonly wasmtlsclient_wants_read: (a: number) => number;
    readonly wasmtlsclient_wants_write: (a: number) => number;
    readonly wasmtlsclient_write_app_data: (a: number, b: number, c: number) => [number, number];
    readonly ring_core_0_17_14__bn_mul_mont: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
