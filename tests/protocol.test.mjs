import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const encoder = new TextEncoder();

const byteLimits = loadSource('byte-limits.js', [
  'REQUEST_BODY_LIMIT_ERROR',
  'RESPONSE_BODY_LIMIT_ERROR',
  'normalizeOptionalByteLimit',
  'isByteLimitExceededError',
]);

function loadSource(file, names, scope = {}) {
  let source = readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8');
  source = source
    .replace(/^import .*?;\r?\n/gm, '')
    .replace(/\bexport\s+(?=(async\s+)?function|class|const|let|var)/g, '')
    .replace(/^export\s*\{[^}]+\};?\r?\n/gm, '');

  const params = Object.keys(scope);
  const values = Object.values(scope);
  return Function(...params, `${source}\nreturn { ${names.join(', ')} };`)(...values);
}

const http1 = loadSource('proxy-fetch.js', [
  'proxyFetch',
  'parseResponseBinary',
  'createContentLengthStream',
  'createChunkedStream',
  'createDirectStream',
  'writeHttp11Body',
  'buildHttpRequest',
], byteLimits);

const h2 = loadSource('proxy-fetch-http2.js', [
  'proxyFetchHttp2',
  'Http2SingleConnection',
  'H2FrameReader',
  'HpackDecoder',
  'WindowTracker',
  'encodeLiteralHeaderNoIndex',
  'buildRequestHeaders',
  'concatChunks',
  'MAX_WINDOW_SIZE',
  'DEFAULT_MAX_FRAME_SIZE',
  'FRAME_HEADERS',
  'FRAME_DATA',
  'FRAME_RST_STREAM',
  'FRAME_SETTINGS',
  'FRAME_GOAWAY',
  'FRAME_PING',
  'FRAME_CONTINUATION',
  'FRAME_PRIORITY',
  'FRAME_WINDOW_UPDATE',
  'FLAG_END_HEADERS',
  'FLAG_END_STREAM',
  'FLAG_ACK',
  'FLAG_PADDED',
  'writeDataStream',
], byteLimits);

const tls = loadSource('wasm-tls.js', [
  'advanceRustlsNetworkOffset',
]);

const socksApi = loadSource('socks5-client.js', [
  'BufferedReader',
  'socks5Connect',
]);

const indexApi = loadSource('index.js', [
  'Socks5Client',
  'buildMergedSignal',
]);

function bytes(s) {
  return encoder.encode(s);
}

function readerFromChunks(chunks) {
  const queue = chunks.map(chunk => chunk instanceof Uint8Array ? chunk : bytes(chunk));
  return {
    async read() {
      if (queue.length === 0) return { done: true, value: undefined };
      return { done: false, value: queue.shift() };
    },
    cancel() {
      queue.length = 0;
      return Promise.resolve();
    },
  };
}

function streamFromChunks(chunks) {
  const queue = chunks.map(chunk => chunk instanceof Uint8Array ? chunk : bytes(chunk));
  return new ReadableStream({
    pull(controller) {
      if (queue.length === 0) {
        controller.close();
        return;
      }
      controller.enqueue(queue.shift());
    },
  });
}

function fakeSocket() {
  return {
    closed: false,
    close() {
      this.closed = true;
      return Promise.resolve();
    },
  };
}

function readerFromSteps(steps) {
  const queue = steps.slice();
  return {
    async read() {
      if (queue.length === 0) return { done: true, value: undefined };
      const step = queue.shift();
      if (step instanceof Error) throw step;
      if (step && step.throw) throw step.throw;
      if (step && step.done) return { done: true, value: step.value };
      const value = step instanceof Uint8Array ? step : bytes(step ?? '');
      return { done: false, value };
    },
    cancel() {
      queue.length = 0;
      return Promise.resolve();
    },
    releaseLock() {},
  };
}

function fakeTunnel(chunks) {
  const writes = [];
  const socket = fakeSocket();
  return {
    socket,
    writes,
    readable: streamFromChunks(chunks),
    writable: {
      getWriter() {
        return {
          write(chunk) {
            writes.push(chunk);
            return Promise.resolve();
          },
          releaseLock() {},
        };
      },
    },
  };
}

async function readAll(stream) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(out);
}

function withTimeout(promise, ms = 250) {
  let id;
  const timeout = new Promise((_, reject) => {
    id = setTimeout(() => reject(new Error('test timeout')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(id));
}

function h2Conn() {
  const writes = [];
  const socket = fakeSocket();
  const writer = {
    write(frame) {
      writes.push(frame);
      return Promise.resolve();
    },
    abort() {
      return Promise.resolve();
    },
    releaseLock() {},
  };
  const reader = {
    read() {
      return new Promise(() => {});
    },
    cancel() {
      return Promise.resolve();
    },
    releaseLock() {},
  };
  const tunnel = {
    readable: { getReader: () => reader },
    writable: { getWriter: () => writer },
    socket,
  };
  return { conn: new h2.Http2SingleConnection(tunnel, null), writes, socket };
}

function u32(value) {
  return Uint8Array.of(
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

function settingsPayload(id, value) {
  return Uint8Array.of(
    (id >>> 8) & 0xff,
    id & 0xff,
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  );
}

function h2HeaderBlock(pairs) {
  return h2.concatChunks(pairs.map(([name, value]) => h2.encodeLiteralHeaderNoIndex(name, value)));
}

function h2Frame(type, flags, streamId, payload) {
  const out = new Uint8Array(9 + payload.byteLength);
  out[0] = (payload.byteLength >>> 16) & 0xff;
  out[1] = (payload.byteLength >>> 8) & 0xff;
  out[2] = payload.byteLength & 0xff;
  out[3] = type & 0xff;
  out[4] = flags & 0xff;
  out[5] = (streamId >>> 24) & 0x7f;
  out[6] = (streamId >>> 16) & 0xff;
  out[7] = (streamId >>> 8) & 0xff;
  out[8] = streamId & 0xff;
  out.set(payload, 9);
  return out;
}

function windowUpdateIncrement(frame) {
  return ((frame[9] & 0x7f) << 24) | (frame[10] << 16) | (frame[11] << 8) | frame[12];
}

function createMockSocksSocket(readSteps, options = {}) {
  const writes = [];
  let closeCount = 0;
  const reader = readerFromSteps(readSteps);
  const writer = {
    write(chunk) {
      writes.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
      return Promise.resolve();
    },
    releaseLock() {},
  };

  const socket = {
    opened: options.openedError
      ? Promise.reject(options.openedError)
      : Promise.resolve(),
    readable: {
      getReader() {
        return reader;
      },
    },
    writable: {
      getWriter() {
        return writer;
      },
    },
    close() {
      closeCount += 1;
      return Promise.resolve();
    },
  };

  return {
    socket,
    writes,
    get closeCount() {
      return closeCount;
    },
  };
}

test('HTTP/1.1 Content-Length body succeeds exactly', async () => {
  const socket = fakeSocket();
  const stream = http1.createContentLengthStream(
    readerFromChunks(['llo']),
    bytes('he'),
    5,
    socket,
    null,
    () => {},
  );
  assert.equal(await readAll(stream), 'hello');
  assert.equal(socket.closed, true);
});

test('HTTP/1.1 short Content-Length rejects instead of closing cleanly', async () => {
  const stream = http1.createContentLengthStream(
    readerFromChunks(['short']),
    new Uint8Array(0),
    10,
    fakeSocket(),
    null,
    () => {},
  );
  await assert.rejects(withTimeout(readAll(stream)), /HTTP response body truncated: expected 5 more bytes/);
});

test('HTTP/1.1 chunked success decodes chunks', async () => {
  const stream = http1.createChunkedStream(
    readerFromChunks(['5\r\nhello\r\n0\r\n\r\n']),
    new Uint8Array(0),
    fakeSocket(),
    null,
    () => {},
  );
  assert.equal(await readAll(stream), 'hello');
});

test('HTTP/1.1 chunked EOF mid-chunk rejects', async () => {
  const stream = http1.createChunkedStream(
    readerFromChunks(['a\r\nhello']),
    new Uint8Array(0),
    fakeSocket(),
    null,
    () => {},
  );
  await assert.rejects(withTimeout(readAll(stream)), /truncated while reading chunk data/);
});

test('HTTP/1.1 invalid chunk size rejects', async () => {
  const stream = http1.createChunkedStream(
    readerFromChunks(['xyz\r\nhello\r\n']),
    new Uint8Array(0),
    fakeSocket(),
    null,
    () => {},
  );
  await assert.rejects(withTimeout(readAll(stream)), /Invalid HTTP chunk size/);
});

test('HTTP/1.1 parser skips informational responses', async () => {
  const readable = streamFromChunks([
    'HTTP/1.1 100 Continue\r\n\r\n',
    'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
  ]);
  const res = await http1.parseResponseBinary(readable, fakeSocket(), null);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
});

test('HTTP/1.1 chunked Transfer-Encoding strips stale Content-Length from returned headers', async () => {
  const readable = streamFromChunks([
    'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n5\r\nhello\r\n0\r\n\r\n',
  ]);
  const res = await http1.parseResponseBinary(readable, fakeSocket(), null);
  assert.equal(await res.text(), 'hello');
  assert.equal(res.headers.has('transfer-encoding'), false);
  assert.equal(res.headers.has('content-length'), false);
});

test('HTTP/1.1 unsupported Transfer-Encoding gzip rejects', async () => {
  await assert.rejects(
    http1.parseResponseBinary(
      streamFromChunks(['HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nhello']),
      fakeSocket(),
      null,
    ),
    /Unsupported Transfer-Encoding: gzip/,
  );
});

test('HTTP/1.1 invalid Transfer-Encoding chunked, gzip rejects', async () => {
  await assert.rejects(
    http1.parseResponseBinary(
      streamFromChunks(['HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nhello']),
      fakeSocket(),
      null,
    ),
    /Unsupported Transfer-Encoding: chunked, gzip/,
  );
});

test('HTTP/1.1 invalid Transfer-Encoding gzip, chunked rejects', async () => {
  await assert.rejects(
    http1.parseResponseBinary(
      streamFromChunks(['HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\nhello']),
      fakeSocket(),
      null,
    ),
    /Unsupported Transfer-Encoding: gzip, chunked/,
  );
});

test('proxyFetch rejects unsupported protocols before dialing', async () => {
  await assert.rejects(
    http1.proxyFetch('ftp://example.com/', {}, {}, {}),
    /Unsupported URL protocol: ftp:/,
  );
});

test('fetch byte-limit options validate finite safe non-negative integers', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    for (const value of [-1, NaN, Infinity, 1.5]) {
      await assert.rejects(
        http1.proxyFetch('http://example.com/', {}, {}, { maxUploadBytes: value }),
        /socksflare: maxUploadBytes must be a finite safe integer >= 0/,
      );
      await assert.rejects(
        http1.proxyFetch('http://example.com/', {}, {}, { maxResponseBytes: value }),
        /socksflare: maxResponseBytes must be a finite safe integer >= 0/,
      );
    }
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('proxyFetch preserves Request signal and aborts before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  const ac = new AbortController();
  ac.abort(new Error('stop'));
  const request = new Request('http://example.com/', { signal: ac.signal });

  try {
    await assert.rejects(
      http1.proxyFetch(request, {}, {}, {}),
      /stop/,
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('Socks5Client.fetch preserves Request signal when no init signal or timeout is provided', async () => {
  const prevProxyFetch = globalThis.proxyFetch;
  let seenInit;

  globalThis.proxyFetch = async (_input, init) => {
    seenInit = init;
    return new Response('ok');
  };

  try {
    const client = new indexApi.Socks5Client({ host: '127.0.0.1' });
    const ac = new AbortController();
    const request = new Request('http://example.com/', { signal: ac.signal });

    await client.fetch(request);

    assert.equal('signal' in seenInit, false);
  } finally {
    globalThis.proxyFetch = prevProxyFetch;
  }
});

test('Socks5Client.fetch merges Request signal with timeout', async () => {
  const prevProxyFetch = globalThis.proxyFetch;
  let seenInit;

  globalThis.proxyFetch = async (_input, init) => {
    seenInit = init;
    return new Response('ok');
  };

  try {
    const client = new indexApi.Socks5Client({ host: '127.0.0.1' });
    const ac = new AbortController();
    const request = new Request('http://example.com/', { signal: ac.signal });

    await client.fetch(request, {}, { timeoutMs: 1000 });

    const reason = new Error('request abort');
    ac.abort(reason);

    assert.equal(seenInit.signal.aborted, true);
    assert.equal(seenInit.signal.reason, reason);
  } finally {
    globalThis.proxyFetch = prevProxyFetch;
  }
});

test('Socks5Client.fetch forwards byte-limit options', async () => {
  const prevProxyFetch = globalThis.proxyFetch;
  let seenOptions;

  globalThis.proxyFetch = async (_input, _init, _proxyConfig, options) => {
    seenOptions = options;
    return new Response('ok');
  };

  try {
    const client = new indexApi.Socks5Client({ host: '127.0.0.1' });
    await client.fetch('https://example.com/', {}, {
      maxUploadBytes: 10,
      maxResponseBytes: 20,
    });

    assert.equal(seenOptions.maxUploadBytes, 10);
    assert.equal(seenOptions.maxResponseBytes, 20);
  } finally {
    globalThis.proxyFetch = prevProxyFetch;
  }
});

test('proxyFetch auto falls back to HTTP/1.1 only when HTTP/2 ALPN negotiation fails', async () => {
  const prevProxyFetchHttp2 = globalThis.proxyFetchHttp2;
  const prevSocks5Connect = globalThis.socks5Connect;

  globalThis.proxyFetchHttp2 = async () => {
    const err = new Error('HTTP/2 not negotiated (ALPN=http/1.1)');
    err.code = 'ERR_SOCKSFLARE_HTTP2_NOT_NEGOTIATED';
    throw err;
  };
  globalThis.socks5Connect = async () => fakeTunnel([
    'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
  ]);

  try {
    const res = await http1.proxyFetch('https://example.com/', {}, {}, { httpVersion: 'auto' });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'ok');
  } finally {
    globalThis.proxyFetchHttp2 = prevProxyFetchHttp2;
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('proxyFetch auto does not retry unsafe HTTP/2 failures over HTTP/1.1', async () => {
  const prevProxyFetchHttp2 = globalThis.proxyFetchHttp2;
  const prevSocks5Connect = globalThis.socks5Connect;
  let fellBack = false;

  globalThis.proxyFetchHttp2 = async () => {
    throw new Error('HTTP/2 stream write failed after request dispatch');
  };
  globalThis.socks5Connect = async () => {
    fellBack = true;
    return fakeTunnel(['HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok']);
  };

  try {
    await assert.rejects(
      http1.proxyFetch('https://example.com/', { method: 'POST', body: 'x' }, {}, { httpVersion: 'auto' }),
      /stream write failed/,
    );
    assert.equal(fellBack, false);
  } finally {
    globalThis.proxyFetchHttp2 = prevProxyFetchHttp2;
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/1.1 rejects GET request body before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    await assert.rejects(
      http1.proxyFetch('http://example.com/', { method: 'GET', body: 'x' }, {}, {}),
      /HTTP\/1\.1: GET requests cannot have a body/,
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/1.1 byte request body over maxUploadBytes rejects before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    await assert.rejects(
      http1.proxyFetch('http://example.com/', { method: 'POST', body: 'hello' }, {}, { maxUploadBytes: 4 }),
      new RegExp(byteLimits.REQUEST_BODY_LIMIT_ERROR),
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/1.1 byte request body at maxUploadBytes succeeds', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  globalThis.socks5Connect = async () => fakeTunnel([
    'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
  ]);

  try {
    const res = await http1.proxyFetch(
      'http://example.com/',
      { method: 'POST', body: 'test' },
      {},
      { maxUploadBytes: 4 },
    );
    assert.equal(await res.text(), 'ok');
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/1.1 stream request body over maxUploadBytes rejects and cancels source', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let tunnel;
  let cancelReason = null;
  let dialed = false;
  const chunks = [bytes('abc'), bytes('def')];
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
    },
    cancel(reason) {
      cancelReason = reason;
    },
  });

  globalThis.socks5Connect = async () => {
    dialed = true;
    tunnel = fakeTunnel(['HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok']);
    return tunnel;
  };

  try {
    await assert.rejects(
      http1.proxyFetch(
        'http://example.com/',
        { method: 'POST', body },
        {},
        { maxUploadBytes: 5 },
      ),
      new RegExp(byteLimits.REQUEST_BODY_LIMIT_ERROR),
    );
    assert.equal(dialed, true);
    assert.match(cancelReason?.message ?? '', new RegExp(byteLimits.REQUEST_BODY_LIMIT_ERROR));
    assert.equal(tunnel.socket.closed, true);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/1.1 stream request body exactly maxUploadBytes succeeds', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let cancelCalled = false;
  const chunks = [bytes('abc'), bytes('de')];
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(chunks[index++]);
        if (index >= chunks.length) controller.close();
      }
    },
    cancel() {
      cancelCalled = true;
    },
  });

  globalThis.socks5Connect = async () => fakeTunnel([
    'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
  ]);

  try {
    const res = await http1.proxyFetch(
      'http://example.com/',
      { method: 'POST', body },
      {},
      { maxUploadBytes: 5 },
    );
    assert.equal(await res.text(), 'ok');
    assert.equal(cancelCalled, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/1.1 Content-Length response over maxResponseBytes rejects', async () => {
  const socket = fakeSocket();
  await assert.rejects(
    http1.parseResponseBinary(
      streamFromChunks(['HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello']),
      socket,
      null,
      'GET',
      4,
    ),
    new RegExp(byteLimits.RESPONSE_BODY_LIMIT_ERROR),
  );
  assert.equal(socket.closed, true);
});

test('HTTP/1.1 chunked response errors when streamed bytes exceed maxResponseBytes', async () => {
  const socket = fakeSocket();
  const res = await http1.parseResponseBinary(
    streamFromChunks(['HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n3\r\nbye\r\n0\r\n\r\n']),
    socket,
    null,
    'GET',
    4,
  );

  await assert.rejects(
    withTimeout(res.text()),
    new RegExp(byteLimits.RESPONSE_BODY_LIMIT_ERROR),
  );
  assert.equal(socket.closed, true);
});

test('SOCKS5 rejects unsupported selected auth method 0x01', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x01),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect({ hostname: 'proxy.test', port: 1080 }, 'example.com', 80),
      /unsupported auth method selected: 0x01/,
    );
    assert.equal(mock.writes.length, 1);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 with credentials offers only username/password auth', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0xff),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect(
        { hostname: 'proxy.test', port: 1080, username: 'user', password: 'pass' },
        'example.com',
        80,
      ),
      /no acceptable auth method/,
    );
    assert.deepEqual(Array.from(mock.writes[0]), [0x05, 0x01, 0x02]);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 with credentials rejects server-selected no-auth downgrade', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x00),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect(
        { hostname: 'proxy.test', port: 1080, username: 'user', password: 'pass' },
        'example.com',
        80,
      ),
      /auth downgrade refused|selected no-auth/,
    );
    assert.deepEqual(Array.from(mock.writes[0]), [0x05, 0x01, 0x02]);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 without credentials offers only no-auth method', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0xff),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect({ hostname: 'proxy.test', port: 1080 }, 'example.com', 80),
      /no acceptable auth method/,
    );
    assert.deepEqual(Array.from(mock.writes[0]), [0x05, 0x01, 0x00]);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 rejects unsupported selected auth method 0x7f', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x7f),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect({ hostname: 'proxy.test', port: 1080 }, 'example.com', 80),
      /unsupported auth method selected: 0x7f/,
    );
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 server requiring auth succeeds when credentials are provided', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x02),
    Uint8Array.of(0x01, 0x00),
    Uint8Array.of(0x05, 0x00, 0x00, 0x01),
    Uint8Array.of(127, 0, 0, 1, 0x1f, 0x90),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    const tunnel = await socksApi.socks5Connect(
      { hostname: 'proxy.test', port: 1080, username: 'user', password: 'pass' },
      'example.com',
      80,
    );
    assert.equal(tunnel.socket, mock.socket);
    assert.deepEqual(Array.from(mock.writes[0]), [0x05, 0x01, 0x02]);
    assert.deepEqual(Array.from(mock.writes[1]), [
      0x01, 0x04, 0x75, 0x73, 0x65, 0x72, 0x04, 0x70, 0x61, 0x73, 0x73,
    ]);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 server requiring auth fails when credentials are missing', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x02),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect({ hostname: 'proxy.test', port: 1080 }, 'example.com', 80),
      /server requires auth but no credentials provided|unsupported auth method selected: 0x02/,
    );
    assert.deepEqual(Array.from(mock.writes[0]), [0x05, 0x01, 0x00]);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 rejects empty username or password values', async () => {
  await assert.rejects(
    socksApi.socks5Connect(
      { hostname: 'proxy.test', port: 1080, username: '', password: 'pass' },
      'example.com',
      80,
    ),
    /username must not be empty/,
  );

  await assert.rejects(
    socksApi.socks5Connect(
      { hostname: 'proxy.test', port: 1080, username: 'user', password: '' },
      'example.com',
      80,
    ),
    /password must not be empty/,
  );
});

test('SOCKS5 rejects bad username/password auth response version', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x02),
    Uint8Array.of(0x02, 0x00),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect(
        { hostname: 'proxy.test', port: 1080, username: 'user', password: 'pass' },
        'example.com',
        80,
      ),
      /bad auth response version: 2/,
    );
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 rejects CONNECT reply with non-zero reserved byte', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const mock = createMockSocksSocket([
    Uint8Array.of(0x05, 0x00),
    Uint8Array.of(0x05, 0x00, 0x01, 0x01),
  ]);

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect({ hostname: 'proxy.test', port: 1080 }, 'example.com', 80),
      /bad reserved byte in reply: 1/,
    );
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('SOCKS5 cleans up if socket.opened rejects before handshake starts', async () => {
  const prevConnect = globalThis.connect;
  const prevTls = globalThis.wasmTlsHandshake;
  const openedError = new Error('open failed');
  const mock = createMockSocksSocket([], { openedError });
  const ac = new AbortController();

  globalThis.connect = () => mock.socket;
  globalThis.wasmTlsHandshake = async () => {
    throw new Error('unexpected TLS handshake');
  };

  try {
    await assert.rejects(
      socksApi.socks5Connect({ hostname: 'proxy.test', port: 1080 }, 'example.com', 80, {
        signal: ac.signal,
      }),
      /open failed/,
    );
    assert.equal(mock.closeCount, 1);
    ac.abort(new Error('later abort'));
    assert.equal(mock.closeCount, 1);
  } finally {
    globalThis.connect = prevConnect;
    globalThis.wasmTlsHandshake = prevTls;
  }
});

test('HTTP/1.1 streaming upload abort wakes pending read', async () => {
  const ac = new AbortController();
  const body = new ReadableStream();
  const sink = new WritableStream();
  const writer = sink.getWriter();
  const writePromise = http1.writeHttp11Body(writer, { kind: 'stream', stream: body }, ac.signal);

  ac.abort();
  await assert.rejects(withTimeout(writePromise), err => err && err.name === 'AbortError');
});

test('HPACK invalid indexed header rejects', () => {
  const decoder = new h2.HpackDecoder(0);
  assert.throws(() => decoder.decode(Uint8Array.of(0xbe)), /invalid header index/);
});

test('HTTP/2 missing :status rejects', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);

  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS,
      streamId: 1,
      payload: h2HeaderBlock([['content-length', '0']]),
    }),
    /missing :status/,
  );
});

test('HTTP/2 duplicate :status and uppercase headers reject', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);

  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS,
      streamId: 1,
      payload: h2HeaderBlock([[':status', '200'], [':status', '204']]),
    }),
    /duplicate :status/,
  );

  const stream2 = conn.createStreamState(3);
  conn.streams.set(3, stream2);
  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS,
      streamId: 3,
      payload: h2HeaderBlock([[':status', '200'], ['Content-Type', 'text/plain']]),
    }),
    /uppercase response header name/,
  );
});

test('HTTP/2 GET response path reads full body', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200'], ['content-length', '5']]),
  });
  const headers = await stream.headers.promise;
  assert.equal(headers.meta.status, 200);

  const bodyPromise = readAll(stream.bodyReadable);
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_END_STREAM,
    streamId: 1,
    payload: bytes('hello'),
  });

  assert.equal(await withTimeout(bodyPromise), 'hello');
});

test('HTTP/2 short Content-Length rejects body and removes state', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });
  stream.contentLength = 100;
  stream.receivedBytes = 50;

  const readPromise = stream.bodyReadable.getReader().read();
  conn.finishStream(stream);

  await assert.rejects(withTimeout(readPromise), /expected 100, received 50/);
  assert.equal(conn.streams.has(1), false);
  assert.equal(conn.windowTracker.streamWindows.has(1), false);
});

test('HTTP/2 longer-than-Content-Length rejects body', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });
  stream.contentLength = 1;

  const readPromise = stream.bodyReadable.getReader().read();
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_END_STREAM,
    streamId: 1,
    payload: bytes('no'),
  });

  await assert.rejects(withTimeout(readPromise), /exceeded Content-Length/);
});

test('HTTP/2 body cancellation sends RST_STREAM and closes', async () => {
  const { conn, writes, socket } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);
  stream.headers.resolve({ meta: {}, endStream: false });

  await stream.bodyReadable.cancel();

  assert.equal(conn.streams.has(1), false);
  assert.equal(conn.windowTracker.streamWindows.has(1), false);
  assert.equal(socket.closed, true);
  assert.equal(writes.some(frame => frame[3] === h2.FRAME_RST_STREAM), true);
});

test('HTTP/2 GOAWAY before response rejects pending request with clear error', async () => {
  const { conn } = h2Conn();
  conn.frameReader.readFrame = async () => ({
    type: h2.FRAME_GOAWAY,
    flags: 0,
    streamId: 0,
    payload: Uint8Array.of(0, 0, 0, 1, 0, 0, 0, 2),
  });

  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'GET' });
  const loopPromise = conn.readLoop();

  await assert.rejects(withTimeout(fetchPromise), /HTTP\/2: peer sent GOAWAY \(2\)/);
  await withTimeout(loopPromise);
});

test('HTTP/2 RST_STREAM before response rejects pending request', async () => {
  const { conn } = h2Conn();
  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'GET' });

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_RST_STREAM,
    flags: 0,
    streamId: 1,
    payload: u32(0),
  });

  await assert.rejects(withTimeout(fetchPromise), /stream reset by peer/);
});

test('HTTP/2 malformed control frames reject', async () => {
  const { conn } = h2Conn();

  await assert.rejects(
    conn.handleFrame({ type: h2.FRAME_RST_STREAM, flags: 0, streamId: 1, payload: Uint8Array.of(0) }),
    /malformed RST_STREAM/,
  );
  await assert.rejects(
    conn.handleFrame({ type: h2.FRAME_GOAWAY, flags: 0, streamId: 0, payload: Uint8Array.of(0) }),
    /malformed GOAWAY/,
  );
  await assert.rejects(
    conn.handleFrame({ type: h2.FRAME_PRIORITY, flags: 0, streamId: 0, payload: new Uint8Array(5) }),
    /PRIORITY on stream 0/,
  );
  await assert.rejects(
    conn.handleFrame({ type: h2.FRAME_SETTINGS, flags: 0, streamId: 0, payload: settingsPayload(0x2, 2) }),
    /invalid SETTINGS_ENABLE_PUSH/,
  );
  assert.throws(
    () => conn.handleWindowUpdate({ streamId: 0, payload: u32(0) }),
    /WINDOW_UPDATE increment of 0/,
  );
});

test('HTTP/2 PING without ACK gets ACKed', async () => {
  const { conn, writes } = h2Conn();
  const payload = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8);

  await conn.handleControlFrame({
    type: h2.FRAME_PING,
    flags: 0,
    streamId: 0,
    payload,
  });

  const pingAck = writes.find(frame => frame[3] === h2.FRAME_PING);
  assert.ok(pingAck);
  assert.equal(pingAck[4], h2.FLAG_ACK);
  assert.deepEqual(Array.from(pingAck.subarray(9)), Array.from(payload));
});

test('HTTP/2 WINDOW_UPDATE after stream closed is ignored', () => {
  const { conn } = h2Conn();
  conn.handleWindowUpdate({ streamId: 1, payload: u32(1) });
  assert.equal(conn.windowTracker.streamWindows.has(1), false);
});

test('WindowTracker waits when stream window is exactly zero', async () => {
  const tracker = new h2.WindowTracker();
  tracker.connectionWindow = 65535;
  tracker.streamWindows.set(1, 0);

  const ac = new AbortController();
  let resolved = false;

  const p = tracker.waitForCredits(1, 1, ac.signal).then(() => {
    resolved = true;
  });

  await new Promise(r => setTimeout(r, 20));
  assert.equal(resolved, false);

  tracker.addCredits(1, 1);
  await p;
  assert.equal(resolved, true);
});

test('WindowTracker uses peer outbound max frame size for upload chunking', async () => {
  const tracker = new h2.WindowTracker();
  tracker.connectionWindow = 65535;
  tracker.streamWindows.set(1, 65535);
  tracker.updatePeerMaxFrameSize(32768);

  const take = await tracker.waitForCredits(1, 40000, null);
  assert.equal(take, 32768);
});

test('WindowTracker addCredits when stream window is zero yields correct value', () => {
  const tracker = new h2.WindowTracker();
  tracker.streamWindows.set(1, 0);
  tracker.addCredits(1, 10);
  assert.equal(tracker.streamWindows.get(1), 10);
});

test('WindowTracker rejects SETTINGS_INITIAL_WINDOW_SIZE overflow for existing stream', () => {
  const tracker = new h2.WindowTracker();
  tracker.streamWindows.set(1, h2.MAX_WINDOW_SIZE);
  assert.throws(
    () => tracker.updateInitialWindowSize(h2.MAX_WINDOW_SIZE),
    /overflow after SETTINGS_INITIAL_WINDOW_SIZE/,
  );
});

test('HTTP/2 rejects out-of-range :status values', async () => {
  const { conn } = h2Conn();

  const stream1 = conn.createStreamState(1);
  conn.streams.set(1, stream1);
  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS,
      streamId: 1,
      payload: h2HeaderBlock([[':status', '099']]),
    }),
    /invalid :status value: 099/,
  );

  const stream2 = conn.createStreamState(3);
  conn.streams.set(3, stream2);
  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS,
      streamId: 3,
      payload: h2HeaderBlock([[':status', '700']]),
    }),
    /invalid :status value: 700/,
  );
});

test('HTTP/2 304 with content-length and END_STREAM returns null body without error', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'GET';
  conn.streams.set(1, stream);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '304'], ['content-length', '123']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 304);
  assert.equal(endStream, true);
  assert.equal(conn.streams.has(1), false);
});

test('HTTP/2 204 with content-length and END_STREAM returns null body without error', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'GET';
  conn.streams.set(1, stream);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '204'], ['content-length', '123']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 204);
  assert.equal(endStream, true);
  assert.equal(conn.streams.has(1), false);
});

test('HTTP/2 HEAD response with content-length and END_STREAM returns null body without error', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'HEAD';
  conn.streams.set(1, stream);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200'], ['content-length', '123']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 200);
  assert.equal(endStream, true);
  assert.equal(conn.streams.has(1), false);
});

test('HTTP/2 null-body response that sends non-empty DATA rejects', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'GET';
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '304'], ['content-length', '5']]),
  });
  await stream.headers.promise;

  const readPromise = stream.bodyReadable.getReader().read();
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: 0,
    streamId: 1,
    payload: bytes('hello'),
  });

  await assert.rejects(withTimeout(readPromise), /DATA frame on null-body response/);
});

test('HTTP/2 HEAD response returns null body and rejects unexpected body data', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'HEAD';
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200'], ['content-length', '5']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 200);
  assert.equal(endStream, false);
  assert.equal(stream.nullBody, true);

  const readPromise = stream.bodyReadable.getReader().read();
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: 0,
    streamId: 1,
    payload: bytes('hello'),
  });

  await assert.rejects(withTimeout(readPromise), /DATA frame on null-body response/);
});

test('HTTP/2 DATA before response HEADERS rejects', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);

  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_DATA,
      flags: 0,
      streamId: 1,
      payload: bytes('x'),
    }),
    /DATA before response HEADERS/,
  );
});

test('HTTP/2 invalid continuation sequence rejects interleaved non-CONTINUATION frame', async () => {
  const { conn } = h2Conn();
  conn.frameReader.readFrame = async () => ({
    type: h2.FRAME_DATA,
    flags: 0,
    streamId: 1,
    payload: bytes('x'),
  });

  await assert.rejects(
    conn.readHeaderBlock({
      type: h2.FRAME_HEADERS,
      flags: 0,
      streamId: 1,
      payload: h2HeaderBlock([[':status', '200']]),
    }),
    /invalid continuation sequence/,
  );
});

test('HTTP/2 body exceeds Content-Length closes socket', async () => {
  const { conn, socket } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });
  stream.contentLength = 1;

  const readPromise = stream.bodyReadable.getReader().read();
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_END_STREAM,
    streamId: 1,
    payload: bytes('no'),
  });

  await assert.rejects(withTimeout(readPromise), /exceeded Content-Length/);
  assert.equal(socket.closed, true);
});

test('HTTP/2 RST_STREAM closes socket', async () => {
  const { conn, socket } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });

  const readPromise = stream.bodyReadable.getReader().read();
  await conn.handleFrame({
    type: h2.FRAME_RST_STREAM,
    flags: 0,
    streamId: 1,
    payload: u32(0),
  });

  await assert.rejects(withTimeout(readPromise), /stream reset by peer/);
  assert.equal(socket.closed, true);
});

test('HTTP/2 informational 103 followed by final 200 response succeeds', async () => {
  const { conn } = h2Conn();
  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'GET' });

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '103'], ['link', '</style.css>; rel=preload; as=style']]),
  });

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200'], ['content-length', '2']]),
  });

  const res = await withTimeout(fetchPromise);
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_END_STREAM,
    streamId: 1,
    payload: bytes('ok'),
  });

  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
});

test('HTTP/2 101 Switching Protocols rejects request', async () => {
  const { conn } = h2Conn();
  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'GET' });

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '101']]),
  });

  await assert.rejects(withTimeout(fetchPromise), /101 Switching Protocols is not supported/);
});

test('HTTP/2 truncated body through finishStream closes socket', async () => {
  const { conn, socket } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });
  stream.contentLength = 100;
  stream.receivedBytes = 50;

  const readPromise = stream.bodyReadable.getReader().read();
  conn.finishStream(stream);

  await assert.rejects(withTimeout(readPromise), /expected 100, received 50/);
  assert.equal(socket.closed, true);
});

test('HTTP/2 HPACK dynamic table enforced immediately before SETTINGS ACK', () => {
  const decoder = new h2.HpackDecoder(4096);
  decoder.setSettingsMaxDynamicSize(0);
  assert.throws(
    () => decoder.decode(Uint8Array.of(0x3f, 0x01)),
    /dynamic table size update.*exceeds SETTINGS limit/,
  );
});

test('HTTP/2 byte body content-length overwrites user-supplied value', () => {
  const fakeUrl = new URL('https://example.com/');
  const bodyMode = { kind: 'bytes', bytes: new Uint8Array(7) };
  const headers = h2.buildRequestHeaders(fakeUrl, { headers: { 'content-length': '999' } }, 'POST', bodyMode);
  const cl = headers.find(([n]) => n === 'content-length');
  assert.ok(cl, 'content-length header should be present');
  assert.equal(cl[1], '7');
});

test('HTTP/2 stream body removes user-supplied content-length', () => {
  const fakeUrl = new URL('https://example.com/');
  const bodyMode = { kind: 'stream', stream: new ReadableStream() };
  const headers = h2.buildRequestHeaders(fakeUrl, { headers: { 'content-length': '999' } }, 'POST', bodyMode);
  const cl = headers.find(([n]) => n === 'content-length');
  assert.equal(cl, undefined);
});

test('HTTP/2 invalid method rejects', async () => {
  const { conn } = h2Conn();
  await conn.init();
  await assert.rejects(
    conn.fetch(new URL('https://example.com/'), { method: 'get bad' }),
    /invalid method/,
  );
});

test('HTTP/2 rejects HEAD request body before sending request', async () => {
  const { conn } = h2Conn();
  await conn.init();
  await assert.rejects(
    conn.fetch(new URL('https://example.com/'), { method: 'HEAD', body: 'x' }),
    /HTTP\/2: HEAD requests cannot have a body/,
  );
});

test('HTTP/2 top-level GET with body rejects before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    await assert.rejects(
      h2.proxyFetchHttp2(new URL('https://example.com/'), { method: 'GET', body: 'x' }, {}),
      /HTTP\/2: GET requests cannot have a body/,
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/2 top-level HEAD with body rejects before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    await assert.rejects(
      h2.proxyFetchHttp2(new URL('https://example.com/'), { method: 'HEAD', body: 'x' }, {}),
      /HTTP\/2: HEAD requests cannot have a body/,
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/2 FormData rejects before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    const form = new FormData();
    form.set('x', '1');
    await assert.rejects(
      h2.proxyFetchHttp2(new URL('https://example.com/'), { method: 'POST', body: form }, {}),
      /FormData request bodies are not supported yet/,
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/2 unsupported body object rejects before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    await assert.rejects(
      h2.proxyFetchHttp2(new URL('https://example.com/'), { method: 'POST', body: { nope: true } }, {}),
      /Unsupported request body type/,
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/2 byte request body over maxUploadBytes rejects before dialing', async () => {
  const prevSocks5Connect = globalThis.socks5Connect;
  let dialed = false;
  globalThis.socks5Connect = async () => {
    dialed = true;
    return fakeTunnel([]);
  };

  try {
    await assert.rejects(
      h2.proxyFetchHttp2(
        new URL('https://example.com/'),
        { method: 'POST', body: 'hello' },
        {},
        { maxUploadBytes: 4 },
      ),
      new RegExp(byteLimits.REQUEST_BODY_LIMIT_ERROR),
    );
    assert.equal(dialed, false);
  } finally {
    globalThis.socks5Connect = prevSocks5Connect;
  }
});

test('HTTP/2 stream request body over maxUploadBytes rejects and cancels source', async () => {
  const writes = [];
  let cancelReason = null;
  const chunks = [bytes('abc'), bytes('def')];
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
    },
    cancel(reason) {
      cancelReason = reason;
    },
  });

  await assert.rejects(
    h2.writeDataStream(
      {
        write(frame) {
          writes.push(frame);
          return Promise.resolve();
        },
      },
      {
        waitForCredits(_streamId, remaining) {
          return Promise.resolve(remaining);
        },
      },
      1,
      body,
      null,
      5,
    ),
    new RegExp(byteLimits.REQUEST_BODY_LIMIT_ERROR),
  );

  assert.match(cancelReason?.message ?? '', new RegExp(byteLimits.REQUEST_BODY_LIMIT_ERROR));
  assert.equal(writes.some(frame => frame[3] === h2.FRAME_DATA), true);
  assert.equal(writes.some(frame => frame[3] === h2.FRAME_DATA && (frame[4] & h2.FLAG_END_STREAM) === h2.FLAG_END_STREAM), false);
});

test('HTTP/2 stream request body exactly maxUploadBytes succeeds', async () => {
  const writes = [];
  let cancelCalled = false;
  const chunks = [bytes('abc'), bytes('de')];
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(chunks[index++]);
        if (index >= chunks.length) controller.close();
      }
    },
    cancel() {
      cancelCalled = true;
    },
  });

  await h2.writeDataStream(
    {
      write(frame) {
        writes.push(frame);
        return Promise.resolve();
      },
    },
    {
      waitForCredits(_streamId, remaining) {
        return Promise.resolve(remaining);
      },
    },
    1,
    body,
    null,
    5,
  );

  assert.equal(cancelCalled, false);
  assert.equal(writes.some(frame => frame[3] === h2.FRAME_DATA && (frame[4] & h2.FLAG_END_STREAM) === h2.FLAG_END_STREAM), true);
});

test('HTTP/2 invalid request header name rejects', () => {
  const fakeUrl = new URL('https://example.com/');
  const bodyMode = { kind: 'none' };
  assert.throws(
    () => h2.buildRequestHeaders(fakeUrl, { headers: { 'bad header!': 'value' } }, 'GET', bodyMode),
    /invalid header name/,
  );
});

test('HTTP/2 request header value with CR/LF rejects', () => {
  const fakeUrl = new URL('https://example.com/');
  const bodyMode = { kind: 'none' };
  assert.throws(
    () => h2.buildRequestHeaders(fakeUrl, { headers: { 'x-test': 'val\r\ninjected' } }, 'GET', bodyMode),
    /invalid header value/,
  );
});

test('HTTP/1.1 HEAD 200 with Content-Length returns null body without truncation error', async () => {
  const readable = streamFromChunks(['HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n']);
  const res = await http1.parseResponseBinary(readable, fakeSocket(), null, 'HEAD');
  assert.equal(res.status, 200);
  assert.equal(res.body, null);
});

test('HTTP/1.1 304 with Content-Length returns null body', async () => {
  const readable = streamFromChunks(['HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n']);
  const res = await http1.parseResponseBinary(readable, fakeSocket(), null, 'GET');
  assert.equal(res.status, 304);
  assert.equal(res.body, null);
});

test('HTTP/1.1 direct stream read error rejects body', async () => {
  const socket = fakeSocket();
  const stream = http1.createDirectStream(
    readerFromSteps([{ throw: new Error('boom') }]),
    new Uint8Array(0),
    socket,
    null,
    () => {},
  );

  await assert.rejects(withTimeout(readAll(stream)), /boom/);
  assert.equal(socket.closed, true);
});

test('HTTP/1.1 parser rejects out-of-range final status codes', async () => {
  await assert.rejects(
    http1.parseResponseBinary(
      streamFromChunks(['HTTP/1.1 099 Weird\r\nContent-Length: 0\r\n\r\n']),
      fakeSocket(),
      null,
    ),
    /Invalid HTTP response status: 99/,
  );
  await assert.rejects(
    http1.parseResponseBinary(
      streamFromChunks(['HTTP/1.1 700 Weird\r\nContent-Length: 0\r\n\r\n']),
      fakeSocket(),
      null,
    ),
    /Invalid HTTP response status: 700/,
  );
});

test('HTTP/1.1 parser skips empty header chunks', async () => {
  const readable = {
    getReader() {
      return readerFromSteps([
        new Uint8Array(0),
        new Uint8Array(0),
        bytes('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'),
      ]);
    },
  };
  const res = await http1.parseResponseBinary(readable, fakeSocket(), null);
  assert.equal(await res.text(), 'ok');
});

test('HTTP/2 204 without END_STREAM on HEADERS: nullBody=true and endStream=false', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'GET';
  conn.streams.set(1, stream);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '204'], ['content-length', '123']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 204);
  assert.equal(endStream, false);
  assert.equal(stream.nullBody, true);
  assert.doesNotThrow(() => new Response(null, { status: 204, headers: meta.headers }));
});

test('HTTP/2 304 without END_STREAM on HEADERS: nullBody=true and endStream=false', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'GET';
  conn.streams.set(1, stream);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '304'], ['content-length', '123']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 304);
  assert.equal(endStream, false);
  assert.equal(stream.nullBody, true);
  assert.doesNotThrow(() => new Response(null, { status: 304, headers: meta.headers }));
});

test('HTTP/2 HEAD 200 without END_STREAM on HEADERS: nullBody=true and endStream=false', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'HEAD';
  conn.streams.set(1, stream);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200'], ['content-length', '123']]),
  });

  const { meta, endStream } = await stream.headers.promise;
  assert.equal(meta.status, 200);
  assert.equal(endStream, false);
  assert.equal(stream.nullBody, true);
});

test('HTTP/1.1 invalid request header name rejects', () => {
  assert.throws(
    () => http1.buildHttpRequest(
      new URL('http://example.com/'),
      { headers: { 'bad header!': 'value' } },
      'GET',
      { kind: 'none' },
    ),
    /invalid header name/,
  );
});

test('HTTP/1.1 request header value with CR/LF rejects', () => {
  assert.throws(
    () => http1.buildHttpRequest(
      new URL('http://example.com/'),
      { headers: { 'x-test': 'val\r\ninjected' } },
      'GET',
      { kind: 'none' },
    ),
    /invalid header value/,
  );
});

test('HTTP/1.1 allows RFC token request method such as M-SEARCH', () => {
  const req = http1.buildHttpRequest(
    new URL('http://example.com/'),
    {},
    'M-SEARCH',
    { kind: 'none' },
  );

  assert.match(new TextDecoder().decode(req), /^M-SEARCH \/ HTTP\/1\.1/);
});

test('HTTP/2 fetch returns null body for 204 without END_STREAM on HEADERS', async () => {
  const { conn, socket } = h2Conn();

  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'GET' });

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '204'], ['content-length', '123']]),
  });

  const res = await withTimeout(fetchPromise);
  assert.equal(res.status, 204);
  assert.equal(res.body, null);

  await new Promise(r => setTimeout(r, 0));
  assert.equal(socket.closed, true);
});

test('HTTP/2 fetch returns null body for 304 without END_STREAM on HEADERS', async () => {
  const { conn, socket } = h2Conn();

  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'GET' });

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '304'], ['content-length', '123']]),
  });

  const res = await withTimeout(fetchPromise);
  assert.equal(res.status, 304);
  assert.equal(res.body, null);

  await new Promise(r => setTimeout(r, 0));
  assert.equal(socket.closed, true);
});

test('HTTP/2 fetch returns null body for HEAD 200 without END_STREAM on HEADERS', async () => {
  const { conn, socket } = h2Conn();

  const fetchPromise = conn.fetch(new URL('https://example.com/'), { method: 'HEAD' });

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200'], ['content-length', '123']]),
  });

  const res = await withTimeout(fetchPromise);
  assert.equal(res.status, 200);
  assert.equal(res.body, null);

  await new Promise(r => setTimeout(r, 0));
  assert.equal(socket.closed, true);
});

test('HTTP/2 inbound frame size does not expand from peer SETTINGS_MAX_FRAME_SIZE', async () => {
  const { conn } = h2Conn();
  await conn.handleControlFrame({
    type: h2.FRAME_SETTINGS,
    flags: 0,
    streamId: 0,
    payload: settingsPayload(0x5, 32768),
  });
  assert.equal(conn.windowTracker.peerOutboundMaxFrameSize, 32768);

  const reader = new h2.H2FrameReader(readerFromSteps([
    h2Frame(h2.FRAME_DATA, 0, 1, new Uint8Array(h2.DEFAULT_MAX_FRAME_SIZE + 1)),
  ]));
  await assert.rejects(
    reader.readFrame(h2.DEFAULT_MAX_FRAME_SIZE),
    new RegExp(`exceeds MAX_FRAME_SIZE \\(${h2.DEFAULT_MAX_FRAME_SIZE}\\)`),
  );
});

test('HTTP/2 frame reader skips empty chunks before valid frame', async () => {
  const frameBytes = h2Frame(h2.FRAME_DATA, h2.FLAG_END_STREAM, 1, bytes('ok'));
  const reader = new h2.H2FrameReader(readerFromSteps([
    new Uint8Array(0),
    new Uint8Array(0),
    frameBytes.subarray(0, 5),
    frameBytes.subarray(5),
  ]));

  const frame = await reader.readFrame(h2.DEFAULT_MAX_FRAME_SIZE);
  assert.equal(frame.streamId, 1);
  assert.equal(new TextDecoder().decode(frame.payload), 'ok');
});

test('SOCKS BufferedReader skips empty chunks before exact read', async () => {
  const socks = loadSource('socks5-client.js', ['BufferedReader']);
  const reader = new socks.BufferedReader(readerFromSteps([
    new Uint8Array(0),
    new Uint8Array(0),
    bytes('he'),
    bytes('llo'),
  ]));

  const out = await reader.readExact(5);
  assert.equal(new TextDecoder().decode(out), 'hello');
});

test('buildMergedSignal validates timeoutMs', () => {
  assert.throws(() => indexApi.buildMergedSignal(null, -1), /timeoutMs must be a finite number > 0/);
  assert.throws(() => indexApi.buildMergedSignal(null, NaN), /timeoutMs must be a finite number > 0/);
  assert.throws(() => indexApi.buildMergedSignal(null, Infinity), /timeoutMs must be a finite number > 0/);
});

test('buildMergedSignal fallback propagates source abort', () => {
  const prevTimeout = AbortSignal.timeout;
  const prevAny = AbortSignal.any;
  AbortSignal.timeout = undefined;
  AbortSignal.any = undefined;

  try {
    const ac = new AbortController();
    const merged = indexApi.buildMergedSignal(ac.signal, 1000);
    const reason = new Error('user abort');
    ac.abort(reason);
    assert.equal(merged.aborted, true);
    assert.equal(merged.reason, reason);
  } finally {
    AbortSignal.timeout = prevTimeout;
    AbortSignal.any = prevAny;
  }
});

test('buildMergedSignal fallback preserves already-aborted source signal', () => {
  const prevTimeout = AbortSignal.timeout;
  const prevAny = AbortSignal.any;
  AbortSignal.timeout = undefined;
  AbortSignal.any = undefined;

  try {
    const ac = new AbortController();
    const reason = new Error('already aborted');
    ac.abort(reason);

    const merged = indexApi.buildMergedSignal(ac.signal, 1000);
    assert.equal(merged.aborted, true);
    assert.equal(merged.reason, reason);
  } finally {
    AbortSignal.timeout = prevTimeout;
    AbortSignal.any = prevAny;
  }
});

test('HTTP/2 sends WINDOW_UPDATE after body writer resolves', async () => {
  const { conn, writes } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });

  let releaseWrite;
  const bodyWriteStarted = new Promise(resolve => {
    stream.bodyWriter = {
      write() {
        resolve();
        return new Promise(r => { releaseWrite = r; });
      },
      close() {},
      abort() {},
    };
  });

  const framePromise = conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_END_STREAM,
    streamId: 1,
    payload: bytes('ok'),
  });

  await bodyWriteStarted;
  assert.equal(writes.some(frame => frame[3] === h2.FRAME_WINDOW_UPDATE), false);
  releaseWrite();
  await framePromise;
  assert.equal(writes.some(frame => frame[3] === h2.FRAME_WINDOW_UPDATE), true);
});

test('HTTP/2 response DATA over maxResponseBytes errors body stream', async () => {
  const { conn, socket } = h2Conn();

  const fetchPromise = conn.fetch(
    new URL('https://example.com/'),
    { method: 'GET' },
    { method: 'GET', bodyMode: { kind: 'none' }, maxResponseBytes: 3 },
  );

  await Promise.resolve();
  await Promise.resolve();

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200']]),
  });

  const res = await withTimeout(fetchPromise);
  const textPromise = withTimeout(res.text());

  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: 0,
    streamId: 1,
    payload: bytes('ok'),
  });
  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_END_STREAM,
    streamId: 1,
    payload: bytes('!!'),
  });

  await assert.rejects(
    textPromise,
    new RegExp(byteLimits.RESPONSE_BODY_LIMIT_ERROR),
  );
  assert.equal(socket.closed, true);
});

test('HTTP/2 padded DATA refunds full flow-controlled length', async () => {
  const { conn, writes } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);
  stream.headerSeen = true;
  stream.headers.resolve({ meta: {}, endStream: false });

  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_PADDED | h2.FLAG_END_STREAM,
    streamId: 1,
    payload: Uint8Array.of(2, 0x6f, 0x6b, 0x00, 0x00),
  });

  const updates = writes.filter(frame => frame[3] === h2.FRAME_WINDOW_UPDATE);
  assert.equal(updates.length, 2);
  assert.deepEqual(updates.map(windowUpdateIncrement), [5, 5]);
});

test('HTTP/2 null-body padded DATA with zero app data still refunds flow-control credit', async () => {
  const { conn, writes } = h2Conn();
  const stream = conn.createStreamState(1);
  stream.method = 'HEAD';
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200']]),
  });
  await stream.headers.promise;

  await conn.handleFrame({
    type: h2.FRAME_DATA,
    flags: h2.FLAG_PADDED | h2.FLAG_END_STREAM,
    streamId: 1,
    payload: Uint8Array.of(2, 0x00, 0x00),
  });

  const updates = writes.filter(frame => frame[3] === h2.FRAME_WINDOW_UPDATE);
  assert.equal(updates.length, 2);
  assert.deepEqual(updates.map(windowUpdateIncrement), [3, 3]);
});

test('HTTP/2 rejects DATA after trailers', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200']]),
  });
  await stream.headers.promise;

  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS,
      streamId: 1,
      payload: h2HeaderBlock([['etag', 'abc']]),
    }),
    /trailing HEADERS must set END_STREAM/,
  );
});

test('HTTP/2 trailers with pseudo-header reject', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200']]),
  });
  await stream.headers.promise;

  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_HEADERS,
      flags: h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
      streamId: 1,
      payload: h2HeaderBlock([[':status', '204']]),
    }),
    /pseudo-header in trailers/,
  );
});

test('HTTP/2 DATA after valid trailers rejects', async () => {
  const { conn } = h2Conn();
  const stream = conn.createStreamState(1);
  conn.streams.set(1, stream);
  conn.windowTracker.streamWindows.set(1, 65535);

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS,
    streamId: 1,
    payload: h2HeaderBlock([[':status', '200']]),
  });
  await stream.headers.promise;

  await conn.handleFrame({
    type: h2.FRAME_HEADERS,
    flags: h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
    streamId: 1,
    payload: h2HeaderBlock([['etag', 'abc']]),
  });

  await assert.rejects(
    conn.handleFrame({
      type: h2.FRAME_DATA,
      flags: 0,
      streamId: 1,
      payload: bytes('x'),
    }),
    /DATA after trailers/,
  );
});

test('wasmTls rejects zero-byte Rustls consumption from non-empty network chunk', () => {
  const client = {
    provide_network_data() {
      return 0;
    },
  };

  assert.throws(
    () => tls.advanceRustlsNetworkOffset(client, bytes('abc'), 0),
    /Rustls consumed 0 bytes from non-empty network data/,
  );
});

test('wasmTls forwards extra roots and enforces queued decrypted byte cap', async () => {
  let seenExtraRoots;
  class FakeTlsClient {
    constructor(_hostname, _alpnCsv, extraRoots) {
      seenExtraRoots = extraRoots;
      this.appChunks = [bytes('abcdef')];
    }
    free() {}
    wants_write() { return false; }
    extract_network_data() { return new Uint8Array(0); }
    provide_network_data(chunk) { return chunk.byteLength; }
    is_handshaking() { return false; }
    negotiatedAlpn() { return 'h2'; }
    read_app_data() { return this.appChunks.shift() ?? new Uint8Array(0); }
    write_app_data() {}
  }

  const tlsModule = loadSource('wasm-tls.js', ['wasmTlsHandshake'], {
    initSync() {},
    WasmTlsClient: FakeTlsClient,
    wasmModule: {},
  });

  const tunnel = await tlsModule.wasmTlsHandshake(
    streamFromChunks([bytes('record')]),
    new WritableStream({ write() {} }),
    'localhost',
    {
      extraRootCertificates: [new Uint8Array([1, 2, 3])],
      maxQueuedAppBytes: 4,
    },
  );

  assert.equal(seenExtraRoots.length, 1);
  assert.deepEqual(Array.from(seenExtraRoots[0]), [1, 2, 3]);

  await assert.rejects(
    withTimeout(tunnel.readable.getReader().read()),
    /decrypted data queue exceeded 4 bytes/,
  );
});

test('wasmTls pauses network pump until app demand resumes', async () => {
  let provideCalls = 0;
  class FakeTlsClient {
    constructor() {
      this.appChunks = [bytes('first'), bytes('second')];
    }
    free() {}
    wants_write() { return false; }
    extract_network_data() { return new Uint8Array(0); }
    provide_network_data(chunk) {
      provideCalls += 1;
      return chunk.byteLength;
    }
    is_handshaking() { return false; }
    negotiatedAlpn() { return null; }
    read_app_data() { return this.appChunks.shift() ?? new Uint8Array(0); }
    write_app_data() {}
  }

  const tlsModule = loadSource('wasm-tls.js', ['wasmTlsHandshake'], {
    initSync() {},
    WasmTlsClient: FakeTlsClient,
    wasmModule: {},
  });

  const tunnel = await tlsModule.wasmTlsHandshake(
    streamFromChunks([bytes('record-1'), bytes('record-2')]),
    new WritableStream({ write() {} }),
    'localhost',
  );

  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(provideCalls, 1);

  const reader = tunnel.readable.getReader();
  const first = await withTimeout(reader.read());
  assert.equal(new TextDecoder().decode(first.value), 'first');

  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(provideCalls, 2);

  const second = await withTimeout(reader.read());
  assert.equal(new TextDecoder().decode(second.value), 'second');
});

test('wasmTls rejects extraRootCertificates when pkg artifact is stale', async () => {
  function LegacyWasmTlsClient() {}

  const tlsModule = loadSource('wasm-tls.js', ['wasmTlsHandshake'], {
    initSync() {},
    WasmTlsClient: LegacyWasmTlsClient,
    wasmModule: {},
  });

  await assert.rejects(
    tlsModule.wasmTlsHandshake(
      streamFromChunks([]),
      new WritableStream({ write() {} }),
      'localhost',
      { extraRootCertificates: [new Uint8Array([1, 2, 3])] },
    ),
    /requires a rebuilt rust-tls-wasm\/pkg artifact/,
  );
});
