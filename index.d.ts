export interface Socks5Config {
  host: string;
  port?: number | string;
  username?: string;
  password?: string;
  user?: string;
  pass?: string;
}

export interface Socks5LowLevelConfig {
  hostname: string;
  port?: number;
  username?: string;
  password?: string;
}

export interface SocksflareFetchOptions {
  /**
   * Override SNI hostname for TLS.
   */
  tlsHostname?: string;

  /**
   * HTTPS strategy.
   *
   * - '1.1': force HTTP/1.1
   * - 'auto': try HTTP/2, then fall back only if ALPN does not negotiate h2
   * - '2': require HTTP/2
   */
  httpVersion?: '1.1' | 'auto' | '2';

  /**
   * Abort after this many milliseconds.
   */
  timeoutMs?: number;
}

export interface SocksflareConnectOptions {
  /**
   * Upgrade the raw SOCKS5 tunnel with TLS via Rustls WASM.
   */
  enableTls?: boolean;

  /**
   * SNI hostname. Defaults to targetHost.
   */
  tlsHostname?: string;

  /**
   * Optional ALPN protocols, for example ['h2', 'http/1.1'].
   */
  alpnProtocols?: string[];

  /**
   * Abort signal for connection / handshake teardown.
   */
  signal?: AbortSignal;

  /**
   * Abort after this many milliseconds.
   */
  timeoutMs?: number;
}

export interface SocksflareTunnel {
  socket: unknown;
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  alpnProtocol?: string | null;
}

export class Socks5Client {
  constructor(config: Socks5Config);

  fetch(
    input: string | URL | Request,
    init?: RequestInit,
    options?: SocksflareFetchOptions,
  ): Promise<Response>;

  connect(
    targetHost: string,
    targetPort: number,
    options?: SocksflareConnectOptions,
  ): Promise<SocksflareTunnel>;
}

export function proxyFetch(
  input: string | URL | Request,
  init: RequestInit | undefined,
  proxyConfig: Socks5LowLevelConfig,
  options?: SocksflareFetchOptions,
): Promise<Response>;

export function socks5Connect(
  proxyConfig: Socks5LowLevelConfig,
  targetHost: string,
  targetPort: number,
  options?: SocksflareConnectOptions,
): Promise<SocksflareTunnel>;
