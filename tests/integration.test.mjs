import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { test } from 'node:test';

function loadSource(file, names, scope = {}) {
  let source = readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8');
  source = source
    .replace(/^import .*?;\r?\n/gm, '')
    .replace(/\bexport\s+(?=(async\s+)?function|class|const|let|var)/g, '');

  const params = Object.keys(scope);
  const values = Object.values(scope);
  return Function(...params, `${source}\nreturn { ${names.join(', ')} };`)(...values);
}

function createDeferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function withTimeout(promise, ms = 1000) {
  let id;
  const timeout = new Promise((_, reject) => {
    id = setTimeout(() => reject(new Error(`test timeout after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(id));
}

async function closeSocket(socket) {
  if (socket.destroyed) return;
  await new Promise(resolve => {
    socket.once('close', resolve);
    socket.destroy();
  });
}

function nodeConnect({ hostname, port }) {
  const socket = net.connect({ host: hostname, port });
  const webSocket = Duplex.toWeb(socket);

  const opened = new Promise((resolve, reject) => {
    const onConnect = () => {
      cleanup();
      resolve();
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error('Socket closed before connect'));
    };
    const cleanup = () => {
      socket.off('connect', onConnect);
      socket.off('error', onError);
      socket.off('close', onClose);
    };

    socket.on('connect', onConnect);
    socket.on('error', onError);
    socket.on('close', onClose);
  });

  return {
    opened,
    readable: webSocket.readable,
    writable: webSocket.writable,
    close() {
      return closeSocket(socket);
    },
  };
}

const { socks5Connect } = loadSource('socks5-client.js', ['socks5Connect'], {
  connect: nodeConnect,
  wasmTlsHandshake: async () => {
    throw new Error('TLS integration TODO: local HTTP harness only in this phase');
  },
});

const { proxyFetch } = loadSource('proxy-fetch.js', ['proxyFetch'], {
  socks5Connect,
  proxyFetchHttp2: async () => {
    throw new Error('HTTP/2 integration TODO: local HTTP harness only in this phase');
  },
});

class SocketReader {
  constructor(socket) {
    this.socket = socket;
    this.chunks = [];
    this.totalBytes = 0;
    this.offset = 0;
    this.pending = [];
    this.ended = null;

    this.onData = chunk => {
      this.chunks.push(chunk);
      this.totalBytes += chunk.length;
      this.flush();
    };
    this.onEnd = () => {
      this.ended = new Error('socket ended before enough bytes were available');
      this.flush();
    };
    this.onClose = () => {
      if (!this.ended) this.ended = new Error('socket closed before enough bytes were available');
      this.flush();
    };
    this.onError = err => {
      this.ended = err;
      this.flush();
    };

    socket.on('data', this.onData);
    socket.on('end', this.onEnd);
    socket.on('close', this.onClose);
    socket.on('error', this.onError);
  }

  readExact(n) {
    if (this.totalBytes - this.offset >= n) {
      return Promise.resolve(this.consume(n));
    }
    if (this.ended) {
      return Promise.reject(this.ended);
    }
    return new Promise((resolve, reject) => {
      this.pending.push({ n, resolve, reject });
    });
  }

  flush() {
    while (this.pending.length > 0) {
      const next = this.pending[0];
      if (this.totalBytes - this.offset >= next.n) {
        this.pending.shift();
        next.resolve(this.consume(next.n));
        continue;
      }
      if (this.ended) {
        this.pending.shift();
        next.reject(this.ended);
        continue;
      }
      break;
    }
  }

  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('end', this.onEnd);
    this.socket.off('close', this.onClose);
    this.socket.off('error', this.onError);

    const remaining = this.totalBytes - this.offset;
    if (remaining <= 0) return Buffer.alloc(0);
    return this.consume(remaining);
  }

  consume(n) {
    if (this.chunks[0].length - this.offset >= n) {
      const chunk = this.chunks[0];
      const out = chunk.subarray(this.offset, this.offset + n);
      this.offset += n;
      if (this.offset >= chunk.length) {
        this.chunks.shift();
        this.totalBytes -= chunk.length;
        this.offset = 0;
      }
      return out;
    }

    const out = Buffer.allocUnsafe(n);
    let written = 0;
    while (written < n) {
      const chunk = this.chunks[0];
      const available = chunk.length - this.offset;
      const needed = n - written;
      if (available <= needed) {
        chunk.copy(out, written, this.offset);
        written += available;
        this.chunks.shift();
        this.totalBytes -= chunk.length;
        this.offset = 0;
      } else {
        chunk.copy(out, written, this.offset, this.offset + needed);
        this.offset += needed;
        written += needed;
      }
    }
    return out;
  }
}

function writeAll(socket, bytes) {
  return new Promise((resolve, reject) => {
    socket.write(bytes, err => err ? reject(err) : resolve());
  });
}

async function startHttpOrigin() {
  const sockets = new Set();
  const abortClosures = [];
  const abortWaiters = [];

  const server = createHttpServer(async (req, res) => {
    const url = new URL(req.url, 'http://origin.test');

    if (url.pathname === '/hello') {
      const body = 'hello via socks5!';
      res.writeHead(200, {
        'content-type': 'text/plain',
        'x-origin': 'local-http',
        'content-length': String(Buffer.byteLength(body)),
      });
      res.end(body);
      return;
    }

    if (url.pathname === '/echo' && req.method === 'POST') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      res.writeHead(201, {
        'content-type': 'application/octet-stream',
        'x-body-length': String(body.length),
        'content-length': String(body.length),
      });
      res.end(body);
      return;
    }

    if (url.pathname === '/content-length') {
      const body = 'content-length-response';
      res.writeHead(200, {
        'content-type': 'text/plain',
        'content-length': String(Buffer.byteLength(body)),
      });
      res.write(body.slice(0, 7));
      setImmediate(() => {
        res.write(body.slice(7, 15));
        setImmediate(() => res.end(body.slice(15)));
      });
      return;
    }

    if (url.pathname === '/truncated') {
      res.writeHead(200, {
        'content-type': 'text/plain',
        'content-length': '10',
      });
      res.write('short');
      res.socket.end();
      return;
    }

    if (url.pathname === '/chunked') {
      res.writeHead(200, {
        'content-type': 'text/plain',
      });
      res.write('chunk-1');
      setImmediate(() => {
        res.write('-chunk-2');
        setImmediate(() => res.end('-chunk-3'));
      });
      return;
    }

    if (url.pathname === '/abort-stream') {
      const deferred = createDeferred();
      abortClosures.push(deferred);
      flushAbortWaiters();

      res.writeHead(200, {
        'content-type': 'text/plain',
      });
      res.write('first-');

      const interval = setInterval(() => {
        res.write('later-');
      }, 50);

      const onClose = () => {
        clearInterval(interval);
        deferred.resolve();
      };

      req.socket.once('close', onClose);
      res.once('close', () => clearInterval(interval));
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain', 'content-length': '9' });
    res.end('not found');
  });

  function flushAbortWaiters() {
    for (let i = abortWaiters.length - 1; i >= 0; i--) {
      const waiter = abortWaiters[i];
      if (abortClosures.length > waiter.index) {
        abortWaiters.splice(i, 1);
        waiter.resolve(abortClosures[waiter.index]);
      }
    }
  }

  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind local HTTP origin');
  }

  return {
    port: address.port,
    url(hostname, path) {
      return `http://${hostname}:${address.port}${path}`;
    },
    nextAbortClosure(index) {
      if (abortClosures.length > index) return Promise.resolve(abortClosures[index]);
      return new Promise(resolve => abortWaiters.push({ index, resolve }));
    },
    async close() {
      for (const socket of Array.from(sockets)) socket.destroy();
      await new Promise(resolve => server.close(() => resolve()));
    },
  };
}

async function startSocksServer() {
  const sockets = new Set();
  const tunnels = [];
  const tunnelWaiters = [];
  let clientConnections = 0;

  function flushTunnelWaiters() {
    for (let i = tunnelWaiters.length - 1; i >= 0; i--) {
      const waiter = tunnelWaiters[i];
      if (tunnels.length > waiter.index) {
        tunnelWaiters.splice(i, 1);
        waiter.resolve(tunnels[waiter.index]);
      }
    }
  }

  const server = net.createServer(async client => {
    clientConnections += 1;
    sockets.add(client);
    client.on('close', () => sockets.delete(client));
    client.on('error', () => {});

    const reader = new SocketReader(client);

    try {
      const hello = await reader.readExact(2);
      const version = hello[0];
      const methodsLength = hello[1];
      if (version !== 0x05) {
        client.destroy();
        return;
      }

      const methods = await reader.readExact(methodsLength);
      if (!methods.includes(0x00)) {
        await writeAll(client, Buffer.from([0x05, 0xff]));
        client.destroy();
        return;
      }

      await writeAll(client, Buffer.from([0x05, 0x00]));

      const requestHead = await reader.readExact(4);
      const [reqVersion, command, , atyp] = requestHead;
      if (reqVersion !== 0x05 || command !== 0x01) {
        client.destroy();
        return;
      }

      let targetHost;
      if (atyp === 0x01) {
        const raw = await reader.readExact(4);
        targetHost = Array.from(raw).join('.');
      } else if (atyp === 0x03) {
        const length = (await reader.readExact(1))[0];
        targetHost = (await reader.readExact(length)).toString('utf8');
      } else {
        await writeAll(client, Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        client.destroy();
        return;
      }

      const portBytes = await reader.readExact(2);
      const targetPort = (portBytes[0] << 8) | portBytes[1];
      const connectHost = targetHost === 'localhost' ? '127.0.0.1' : targetHost;

      const upstream = net.connect({ host: connectHost, port: targetPort });
      sockets.add(upstream);
      upstream.on('close', () => sockets.delete(upstream));
      upstream.on('error', () => {});

      await new Promise((resolve, reject) => {
        const onConnect = () => {
          cleanup();
          resolve();
        };
        const onError = (err) => {
          cleanup();
          reject(err);
        };
        const cleanup = () => {
          upstream.off('connect', onConnect);
          upstream.off('error', onError);
        };
        upstream.on('connect', onConnect);
        upstream.on('error', onError);
      });

      await writeAll(client, Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

      const tunnel = {
        targetHost,
        targetPort,
        closed: new Promise(resolve => {
          let settled = false;
          const done = () => {
            if (settled) return;
            settled = true;
            resolve();
          };
          client.once('close', done);
          upstream.once('close', done);
        }),
      };
      tunnels.push(tunnel);
      flushTunnelWaiters();

      const leftover = reader.detach();
      if (leftover.byteLength > 0) {
        upstream.write(leftover);
      }

      client.pipe(upstream);
      upstream.pipe(client);

      client.on('close', () => upstream.destroy());
      upstream.on('close', () => client.destroy());
    } catch {
      client.destroy();
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind local SOCKS5 server');
  }

  return {
    port: address.port,
    get clientConnections() {
      return clientConnections;
    },
    get tunnels() {
      return tunnels;
    },
    nextTunnel(index) {
      if (tunnels.length > index) return Promise.resolve(tunnels[index]);
      return new Promise(resolve => tunnelWaiters.push({ index, resolve }));
    },
    async close() {
      for (const socket of Array.from(sockets)) socket.destroy();
      await new Promise(resolve => server.close(() => resolve()));
    },
  };
}

async function createHarness() {
  const origin = await startHttpOrigin();
  const socks = await startSocksServer();
  return {
    origin,
    socks,
    proxyConfig: {
      hostname: '127.0.0.1',
      port: socks.port,
    },
    async close() {
      await Promise.allSettled([
        socks.close(),
        origin.close(),
      ]);
    },
  };
}

test('proxyFetch fetches local HTTP/1.1 origin through SOCKS5 domain tunnel', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  const res = await proxyFetch(
    harness.origin.url('localhost', '/hello'),
    {},
    harness.proxyConfig,
  );

  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-origin'), 'local-http');
  assert.equal(await res.text(), 'hello via socks5!');
  assert.equal(harness.socks.clientConnections, 1);
  assert.equal(harness.socks.tunnels[0].targetHost, 'localhost');
});

test('proxyFetch POST with byte body works through SOCKS5 IPv4 tunnel', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  const body = Uint8Array.from([0, 1, 2, 3, 250, 251]);
  const res = await proxyFetch(
    harness.origin.url('127.0.0.1', '/echo'),
    {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
      },
      body,
    },
    harness.proxyConfig,
  );

  const returned = new Uint8Array(await res.arrayBuffer());
  assert.equal(res.status, 201);
  assert.equal(res.headers.get('x-body-length'), String(body.length));
  assert.deepEqual(returned, body);
  assert.equal(harness.socks.tunnels[0].targetHost, '127.0.0.1');
});

test('proxyFetch GET with body rejects before dialing SOCKS5 server', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  await assert.rejects(
    proxyFetch(
      harness.origin.url('127.0.0.1', '/hello'),
      { method: 'GET', body: Uint8Array.of(1) },
      harness.proxyConfig,
    ),
    /GET requests cannot have a body/,
  );

  assert.equal(harness.socks.clientConnections, 0);
});

test('proxyFetch streams Content-Length response through SOCKS5', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  const res = await proxyFetch(
    harness.origin.url('localhost', '/content-length'),
    {},
    harness.proxyConfig,
  );

  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'content-length-response');
});

test('proxyFetch rejects truncated Content-Length response through SOCKS5', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  const res = await proxyFetch(
    harness.origin.url('localhost', '/truncated'),
    {},
    harness.proxyConfig,
  );

  await assert.rejects(
    withTimeout(res.text()),
    /HTTP response body truncated/,
  );
});

test('proxyFetch streams chunked response through SOCKS5', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  const res = await proxyFetch(
    harness.origin.url('localhost', '/chunked'),
    {},
    harness.proxyConfig,
  );

  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'chunk-1-chunk-2-chunk-3');
});

test('proxyFetch abort during response body closes SOCKS5 tunnel', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.close());

  const ac = new AbortController();
  const tunnelIndex = harness.socks.tunnels.length;
  const abortIndex = 0;

  const res = await proxyFetch(
    harness.origin.url('localhost', '/abort-stream'),
    { signal: ac.signal },
    harness.proxyConfig,
  );

  const tunnel = await harness.socks.nextTunnel(tunnelIndex);
  const originClose = await harness.origin.nextAbortClosure(abortIndex);
  const reader = res.body.getReader();

  const first = await withTimeout(reader.read());
  assert.equal(first.done, false);
  assert.match(new TextDecoder().decode(first.value), /^first-/);

  const nextRead = withTimeout(reader.read());
  ac.abort();

  await assert.rejects(
    nextRead,
    err => err && (err.name === 'AbortError' || /Aborted/.test(err.message)),
  );
  await withTimeout(tunnel.closed);
  await withTimeout(originClose.promise);
});
