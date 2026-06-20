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
]);

const h2 = loadSource('proxy-fetch-http2.js', [
  'Http2SingleConnection',
  'HpackDecoder',
  'encodeLiteralHeaderNoIndex',
  'concatChunks',
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
