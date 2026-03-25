/**
 * Example Cloudflare Worker — Socksflare demo
 *
 * Deploy with wrangler and set these env vars:
 *   SOCKS5_HOST, SOCKS5_PORT, SOCKS5_USER, SOCKS5_PASS
 *
 * Usage:
 *   https://your-worker.workers.dev/?url=https://httpbin.org/get
 */

import { Socks5Client } from 'socksflare';

// ⚠️ SSRF protection: only allow these hostnames to be proxied.
// Without this, attackers can reach internal networks via your Worker.
const ALLOWED_HOSTS = new Set([
    'httpbin.org',
    'example.com',
    // Add your target hostnames here
]);

export default {
    async fetch(request, env) {
        const proxy = new Socks5Client({
            host: env.SOCKS5_HOST,
            port: env.SOCKS5_PORT,
            username: env.SOCKS5_USER,
            password: env.SOCKS5_PASS,
        });

        const raw = new URL(request.url).searchParams.get('url');
        if (!raw) {
            return new Response('Missing ?url= parameter\n\nUsage: ?url=https://example.com', {
                status: 400,
                headers: { 'Content-Type': 'text/plain' },
            });
        }

        let target;
        try {
            target = new URL(raw);
        } catch {
            return new Response('Invalid URL', { status: 400 });
        }

        if (!ALLOWED_HOSTS.has(target.hostname)) {
            return new Response('Hostname not allowed', { status: 403 });
        }

        try {
            const proxyHeaders = new Headers(request.headers);
            proxyHeaders.delete('host');

            return await proxy.fetch(target, {
                method: request.method,
                headers: Object.fromEntries(proxyHeaders.entries()),
                body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
            }, { timeoutMs: 15000 });
        } catch (err) {
            return new Response(`Proxy error: ${err.message}`, {
                status: 502,
                headers: { 'Content-Type': 'text/plain' },
            });
        }
    },
};
