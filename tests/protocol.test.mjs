import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const encoder = new TextEncoder();

function loadSource(file, names) {
  let source = readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8');
  source = source
    .replace(/^import .*?;\r?\n/gm, '')
    .replace(/\bexport\s+(?=(async\s+)?function|class|const|let|var)/g, '');

  return Function(`${source}\nreturn { ${names.join(', ')} };`)();
}

const http1 = loadSource('proxy-fetch.js', [
  'proxyFetch',
  'parseResponseBinary',
  'createContentLengthStream',
  'createChunkedStream',
  'writeHttp11Body',
  'buildHttpRequest',
]);

const h2 = loadSource('proxy-fetch-http2.js', [
  'Http2SingleConnection',
  'HpackDecoder',
  'WindowTracker',
  'encodeLiteralHeaderNoIndex',
  'buildRequestHeaders',
  'concatChunks',
  'MAX_WINDOW_SIZE',
  'FRAME_HEADERS',
  'FRAME_DATA',
  'FRAME_RST_STREAM',
  'FRAME_SETTINGS',
  'FRAME_GOAWAY',
  'FRAME_PRIORITY',
  'FRAME_WINDOW_UPDATE',
  'FLAG_END_HEADERS',
  'FLAG_END_STREAM',
  'FLAG_ACK',
]);

const tls = loadSource('wasm-tls.js', [
  'advanceRustlsNetworkOffset',
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

test('proxyFetch rejects unsupported protocols before dialing', async () => {
  await assert.rejects(
    http1.proxyFetch('ftp://example.com/', {}, {}, {}),
    /Unsupported URL protocol: ftp:/,
  );
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
      { kind: 'none' },
    ),
    /invalid header value/,
  );
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
