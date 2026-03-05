/**
 * Example Cloudflare Worker — Socksflare demo
 *
 * Deploy this worker with wrangler and set these environment variables:
 *   SOCKS5_HOST, SOCKS5_PORT, SOCKS5_USER, SOCKS5_PASS
 *
 * Usage:
 *   https://your-worker.workers.dev/?url=https://httpbin.org/get
 */

import { Socks5Client } from '../src/index.js';

export default {
    async fetch(request, env) {
        const proxy = new Socks5Client({
            host: env.SOCKS5_HOST,
            port: env.SOCKS5_PORT,
            username: env.SOCKS5_USER,
            password: env.SOCKS5_PASS,
        });

        const url = new URL(request.url).searchParams.get('url');
        if (!url) {
            return new Response('Missing ?url= parameter\n\nUsage: ?url=https://example.com', {
                status: 400,
                headers: { 'Content-Type': 'text/plain' },
            });
        }

        try {
            const proxyHeaders = new Headers(request.headers);
            proxyHeaders.delete('host');

            return await proxy.fetch(url, {
                method: request.method,
                headers: Object.fromEntries(proxyHeaders.entries()),
                body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
            });
        } catch (err) {
            return new Response(`Proxy error: ${err.message}`, {
                status: 502,
                headers: { 'Content-Type': 'text/plain' },
            });
        }
    },
};
