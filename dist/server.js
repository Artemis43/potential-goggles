import http from 'node:http';
import { Readable } from 'node:stream';
import { Buffer } from 'node:buffer';
import { handleRequest } from './index.js';
export function startNodeServer() {
    const PORT = Number(process.env.PORT || 10000);
    const HOST = '0.0.0.0';
    // In-memory KV store for rate limiting when running outside Cloudflare
    const memoryKV = new Map();
    const mockKV = {
        async get(key, typeOrOpts) {
            const entry = memoryKV.get(key);
            if (!entry)
                return null;
            if (entry.exp && Date.now() > entry.exp) {
                memoryKV.delete(key);
                return null;
            }
            if (typeOrOpts === 'json' || (typeof typeOrOpts === 'object' && typeOrOpts?.type === 'json')) {
                try {
                    return JSON.parse(entry.val);
                }
                catch {
                    return null;
                }
            }
            return entry.val;
        },
        async put(key, val, opts) {
            const exp = opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined;
            memoryKV.set(key, { val, exp });
        },
    };
    // In-memory segment cache for Node.js fallback
    const segmentCache = new Map();
    const mockCache = {
        async match(req) {
            const entry = segmentCache.get(req.url);
            if (!entry)
                return undefined;
            return new Response(entry.body, { status: entry.status, headers: entry.headers });
        },
        async put(req, res) {
            try {
                const buf = Buffer.from(await res.arrayBuffer());
                const headers = [];
                res.headers.forEach((v, k) => headers.push([k, v]));
                segmentCache.set(req.url, { status: res.status, headers, body: buf });
                // Cap in-memory segment cache at 500 entries (~1.5 GB max) to prevent memory leak
                if (segmentCache.size > 500) {
                    const firstKey = segmentCache.keys().next().value;
                    if (firstKey)
                        segmentCache.delete(firstKey);
                }
            }
            catch { }
        },
    };
    if (typeof globalThis.caches === 'undefined') {
        globalThis.caches = { default: mockCache };
    }
    const defaultEnv = {
        API_BASE_URL: (process.env.API_BASE_URL || 'https://api.slimestream.space').replace(/\/+$/, ''),
        JWT_SECRET: process.env.JWT_SECRET,
        WORKER_SHARED_SECRET: process.env.WORKER_SHARED_SECRET,
        RATE_LIMIT_KV: mockKV,
        ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS,
        WORKER_ID: process.env.WORKER_ID || 'render-worker',
    };
    const server = http.createServer(async (req, res) => {
        try {
            const protocol = req.headers['x-forwarded-proto'] || 'http';
            const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
            const url = `${protocol}://${host}${req.url}`;
            const headers = new Headers();
            for (const [k, v] of Object.entries(req.headers)) {
                if (v) {
                    if (Array.isArray(v))
                        v.forEach((val) => headers.append(k, val));
                    else
                        headers.set(k, v);
                }
            }
            let body = undefined;
            if (req.method !== 'GET' && req.method !== 'HEAD') {
                body = Readable.toWeb(req);
            }
            const webReq = new Request(url, {
                method: req.method,
                headers,
                body,
                // @ts-ignore
                duplex: 'half',
            });
            // Inject simulated Cloudflare region info
            webReq.cf = {
                colo: process.env.RENDER_REGION || 'render-edge',
            };
            const backgroundTasks = [];
            const ctx = {
                waitUntil(p) {
                    backgroundTasks.push(p.catch(() => { }));
                },
                passThroughOnException() { },
            };
            const response = await handleRequest(webReq, defaultEnv, ctx);
            res.statusCode = response.status;
            response.headers.forEach((val, key) => {
                res.setHeader(key, val);
            });
            // Ensure intermediate proxies (Cloudflare, Nginx, Caddy) never buffer stream chunks
            res.setHeader('X-Accel-Buffering', 'no');
            res.setHeader('Cloudflare-CDN-Cache-Control', 'no-store, no-transform, bypass');
            res.setHeader('X-Worker-Provider', 'render');
            // Flush response headers immediately to start video streaming without proxy delays
            if (typeof res.flushHeaders === 'function') {
                res.flushHeaders();
            }
            if (response.body) {
                Readable.fromWeb(response.body).pipe(res);
            }
            else {
                res.end();
            }
        }
        catch (err) {
            if (!res.headersSent) {
                res.statusCode = 500;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ error: 'Worker error', details: err?.message }));
            }
        }
    });
    server.listen(PORT, HOST, () => {
        console.log(`[SlimeStream] CDN Edge Worker (Node.js/Render runtime) listening on port ${PORT}`);
    });
    const shutdown = () => {
        console.log('[SlimeStream] Worker shutting down gracefully...');
        server.close(() => {
            process.exit(0);
        });
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
}
// Auto-start if executed directly
if (typeof process !== 'undefined' &&
    process.release?.name === 'node' &&
    process.argv?.[1]?.endsWith('server.js')) {
    startNodeServer();
}
//# sourceMappingURL=server.js.map