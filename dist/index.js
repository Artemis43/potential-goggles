/**
 * SlimeStream — Cloudflare Worker (Ultra-Fast Edge Segment Delivery & Caching)
 *
 * Fetches encrypted video segments directly from Google Drive at the edge.
 * Encrypted segments are completely immutable and cached at Cloudflare's
 * global edge (300+ data centers) for up to 1 year.
 *
 * Performance optimizations (v2):
 *   1. JWT token verification cached in-memory per isolate (~60s TTL)
 *   2. Chunk signature verification cached per fileId
 *   3. Rate limiting is fire-and-forget (non-blocking via waitUntil)
 *   4. Responses stream through — no full-body buffering
 *   5. GDrive access tokens triple-cached (memory → KV → VPS)
 *   6. HMAC CryptoKey objects cached across requests
 *
 * VPS CPU & Bandwidth Impact: 0% during video playback.
 */
// No hardcoded fallback secrets — a worker deployed without JWT_SECRET /
// WORKER_SHARED_SECRET set (via `wrangler secret put`) must fail closed,
// not silently authenticate every request with a value anyone reading this
// source file also has. Every call site below throws/401s when these are
// unset rather than falling back to a constant.
function requireSecret(env, name) {
    const value = env[name];
    if (!value)
        throw new Error(`${name} is not configured on this worker`);
    return value;
}
// ── In-flight & Load telemetry tracking ───────────────────────
let _activeRequests = 0;
let _windowRequests = 0;
let _windowResetAt = Date.now();
function trackRequestStart() {
    _activeRequests++;
    const now = Date.now();
    if (now - _windowResetAt > 10_000) {
        _windowRequests = 0;
        _windowResetAt = now;
    }
    _windowRequests++;
}
function trackRequestEnd() {
    _activeRequests = Math.max(0, _activeRequests - 1);
}
function getWorkerLoadMetrics() {
    const now = Date.now();
    if (now - _windowResetAt > 10_000) {
        _windowRequests = 0;
        _windowResetAt = now;
    }
    // Load score: active in-flight requests heavily weighted + recent request velocity
    const loadScore = _activeRequests * 10 + Math.min(_windowRequests, 100);
    return { activeRequests: _activeRequests, recentRequests: _windowRequests, loadScore };
}
// ── In-memory hot caches ──────────────────────────────────────
// These survive across requests within the same Worker isolate
// (typically 30s–5min depending on traffic). Zero-cost lookups.
// GDrive OAuth access token cache — keyed by gdriveAccountId, so its size
// is naturally bounded by the number of Drive accounts configured
// platform-wide (small), not by request volume. Still capped for defense
// in depth, matching every other cache in this file.
const memoryTokenCache = new Map();
const MEMORY_TOKEN_CACHE_MAX = 500;
function memoryTokenCacheSet(key, value) {
    if (memoryTokenCache.size >= MEMORY_TOKEN_CACHE_MAX && !memoryTokenCache.has(key)) {
        const oldestKey = memoryTokenCache.keys().next().value;
        if (oldestKey !== undefined)
            memoryTokenCache.delete(oldestKey);
    }
    memoryTokenCache.set(key, value);
}
// JWT verification cache: avoids repeated HMAC verify calls.
// Key = raw JWT string, value = verified payload + expiry.
const jwtVerifyCache = new Map();
const JWT_CACHE_TTL = 60_000; // 60s — tokens are valid for hours, so 60s cache is safe
// Chunk signature cache: avoids repeated HMAC sign calls.
// Key = "videoId:chunkIndex:quality:fid:acc", value = computed sig.
const sigCache = new Map();
const SIG_CACHE_MAX = 5_000; // cap to prevent unbounded growth
// Precomputed HMAC CryptoKey cache (per secret string)
let _hmacVerifyKey = null;
let _hmacVerifySecret = '';
let _hmacSignKey = null;
let _hmacSignSecret = '';
async function getHmacVerifyKey(secret) {
    if (_hmacVerifyKey && _hmacVerifySecret === secret)
        return _hmacVerifyKey;
    _hmacVerifyKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    _hmacVerifySecret = secret;
    return _hmacVerifyKey;
}
async function getHmacSignKey(secret) {
    if (_hmacSignKey && _hmacSignSecret === secret)
        return _hmacSignKey;
    _hmacSignKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    _hmacSignSecret = secret;
    return _hmacSignKey;
}
// ── CORS ─────────────────────────────────────────────────────
function getAllowedOrigins(env) {
    return env.ALLOWED_ORIGINS?.split(',').map((o) => o.trim()).filter(Boolean) ?? [];
}
function corsHeaders(origin, env) {
    const allowed = getAllowedOrigins(env);
    const allowOrigin = origin && allowed.includes(origin) ? origin : (allowed[0] ?? '*');
    return {
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Range, Cache-Control, Pragma',
        'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, X-Slime-Chunk, X-Slime-Cache, Cache-Control, X-Worker-Load, X-Worker-Active, X-Worker-Colo, X-Worker-Id, Server-Timing',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin',
    };
}
// ── Rate limiting (in-isolate, per IP+video) ────────────────────
//
// Was a KV read+write pair (checkRateLimit(key).catch(()=>{})) fired via
// ctx.waitUntil on every single segment request — a real cost/quota
// concern at scale, AND its resolved boolean was never actually read by
// the caller, so it counted requests but never rejected anything: this
// rate limiter has never blocked a single request. KV is also eventually
// consistent, so even reading the result back wouldn't have been accurate
// under concurrent requests hitting different edge nodes. An in-isolate
// (per-edge-instance) counter is cheap, actually synchronous, and "good
// enough" for anti-abuse throttling — not billing-grade precision, which
// nothing here needs.
const rateLimitCounters = new Map();
const RATE_LIMIT_MAP_MAX = 5000; // bound memory; oldest entries evicted first
function checkRateLimitInMemory(key, maxPerMin) {
    const now = Date.now();
    const windowMs = 60_000;
    const entry = rateLimitCounters.get(key);
    if (!entry || now - entry.windowStart >= windowMs) {
        if (rateLimitCounters.size >= RATE_LIMIT_MAP_MAX && !rateLimitCounters.has(key)) {
            const oldestKey = rateLimitCounters.keys().next().value;
            if (oldestKey !== undefined)
                rateLimitCounters.delete(oldestKey);
        }
        rateLimitCounters.set(key, { windowStart: now, count: 1 });
        return true;
    }
    if (entry.count >= maxPerMin)
        return false;
    entry.count++;
    return true;
}
function base64UrlDecode(input) {
    const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
// Grant-validity cache — separate from jwtVerifyCache above. A JWT
// signature only proves a token was genuinely issued for this video at
// MINT time; it says nothing about whether the share behind it has since
// been revoked, expired, or hit its view cap. Stream tokens live up to
// 12h, so relying on signature+exp alone (all this worker ever checked)
// meant a revoked share kept serving from the edge for up to 12h. Keyed
// by a hash of the token (never the raw token — avoids putting a bearer
// credential in a KV key/log), TTL ~45s: short enough that a revocation
// takes effect quickly, long enough that it costs one origin round trip
// per token per PoP per ~45s, not per segment request.
const grantCache = new Map(); // tokenHash -> validUntilMs
const GRANT_CACHE_TTL_MS = 45_000;
async function sha256Hex(input) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
/** Asks the origin whether this token's underlying grant (share active/
 * not expired/under view cap, geo) is still valid — the same check
 * (validateStreamAccess) the origin already runs on every direct
 * request. Fails OPEN (returns true) on any origin/network failure —
 * availability over strictness: a temporarily unreachable origin must
 * not take down playback for every existing viewer, only a positively
 * confirmed revocation should. */
async function checkStreamGrant(token, env) {
    const tokenHash = await sha256Hex(token);
    const now = Date.now();
    const memValidUntil = grantCache.get(tokenHash);
    if (memValidUntil && memValidUntil > now)
        return true;
    try {
        const kvHit = await env.RATE_LIMIT_KV.get(`grant:${tokenHash}`);
        if (kvHit) {
            grantCache.set(tokenHash, now + GRANT_CACHE_TTL_MS);
            return true;
        }
    }
    catch {
        // KV read failure — fall through to the origin check below
    }
    try {
        const workerSecret = requireSecret(env, 'WORKER_SHARED_SECRET');
        const res = await fetch(`${env.API_BASE_URL}/api/v1/internal/stream-grant/validate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Worker-Secret': workerSecret },
            body: JSON.stringify({ token }),
            signal: AbortSignal.timeout(3000),
        });
        if (!res.ok) {
            // 401/400 here means OUR request was malformed/unauthenticated
            // (a config problem, not a revocation) — fail open rather than
            // block real viewers over a worker misconfiguration. A genuine
            // revocation comes back as ok:200 with body.ok:false, handled below.
            return true;
        }
        const body = (await res.json().catch(() => null));
        if (body?.ok) {
            grantCache.set(tokenHash, now + GRANT_CACHE_TTL_MS);
            await env.RATE_LIMIT_KV.put(`grant:${tokenHash}`, '1', { expirationTtl: 45 }).catch(() => { });
            return true;
        }
        return false; // origin explicitly confirmed the grant is no longer valid
    }
    catch {
        return true; // network/timeout reaching origin — fail open
    }
}
async function verifyStreamToken(token, secret, env) {
    let payload;
    // Check in-memory cache first (<0.01ms)
    const cached = jwtVerifyCache.get(token);
    if (cached && Date.now() - cached.cachedAt < JWT_CACHE_TTL) {
        if (cached.payload.exp && cached.payload.exp * 1000 < Date.now()) {
            jwtVerifyCache.delete(token);
            return null;
        }
        payload = cached.payload;
    }
    else {
        const parts = token.split('.');
        if (parts.length !== 3)
            return null;
        const [headerB64, payloadB64, sigB64] = parts;
        try {
            const key = await getHmacVerifyKey(secret);
            const signature = base64UrlDecode(sigB64);
            const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
            const valid = await crypto.subtle.verify('HMAC', key, signature, signedData);
            if (!valid)
                return null;
            const verified = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
            if (verified.purpose !== 'stream' && verified.purpose !== 'admin_review')
                return null;
            if (verified.exp && verified.exp * 1000 < Date.now())
                return null;
            payload = verified;
            // Cache verified token
            jwtVerifyCache.set(token, { payload, cachedAt: Date.now() });
            if (jwtVerifyCache.size > 1000) {
                const keys = Array.from(jwtVerifyCache.keys());
                for (let i = 0; i < 200; i++)
                    jwtVerifyCache.delete(keys[i]);
            }
        }
        catch {
            return null;
        }
    }
    // Runs on BOTH the cache-hit and freshly-verified paths — a revoked
    // share must stop serving even mid-way through the 60s local JWT cache
    // window, not only after it expires.
    const grantOk = await checkStreamGrant(token, env);
    if (!grantOk) {
        jwtVerifyCache.delete(token);
        return null;
    }
    return payload;
}
// ── Chunk-param signature verification ──────────────────────────
function bytesToBase64Url(bytes) {
    let binary = '';
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i++)
        binary += String.fromCharCode(view[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function signChunkParams(videoId, chunkIndex, quality, fid, acc, secret) {
    const cacheKey = `${videoId}:${chunkIndex}:${quality}:${fid}:${acc}`;
    const cached = sigCache.get(cacheKey);
    if (cached)
        return cached;
    const key = await getHmacSignKey(secret);
    const data = new TextEncoder().encode(cacheKey);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    const result = bytesToBase64Url(sig);
    sigCache.set(cacheKey, result);
    if (sigCache.size > SIG_CACHE_MAX) {
        const keys = Array.from(sigCache.keys());
        for (let i = 0; i < 500; i++)
            sigCache.delete(keys[i]);
    }
    return result;
}
function timingSafeEqualStr(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}
// ── GDrive access token (Memory -> KV -> VPS) ───────────────────
async function getGDriveAccessToken(gdriveAccountId, env) {
    const now = Date.now();
    // 1. Check in-memory isolate cache (<0.01ms)
    const memCached = memoryTokenCache.get(gdriveAccountId);
    if (memCached && memCached.expiresAt > now + 60_000) {
        return memCached.token;
    }
    // 2. Check Cloudflare KV namespace (~2ms)
    const cacheKey = `gtoken:${gdriveAccountId}`;
    const kvCached = await env.RATE_LIMIT_KV.get(cacheKey, 'json');
    if (kvCached && kvCached.expiresAt > now + 60_000) {
        memoryTokenCacheSet(gdriveAccountId, { token: kvCached.accessToken, expiresAt: kvCached.expiresAt });
        return kvCached.accessToken;
    }
    // 3. Mint fresh token via VPS internal endpoint
    const workerSecret = requireSecret(env, 'WORKER_SHARED_SECRET');
    const res = await fetch(`${env.API_BASE_URL}/internal/gdrive-token/${gdriveAccountId}`, {
        headers: { 'X-Worker-Secret': workerSecret },
    });
    if (!res.ok)
        return null;
    const data = await res.json();
    const ttlSeconds = Math.min(Math.max(Math.floor((data.expiresAt - now) / 1000) - 60, 60), 55 * 60);
    memoryTokenCacheSet(gdriveAccountId, { token: data.accessToken, expiresAt: data.expiresAt });
    await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(data), { expirationTtl: ttlSeconds });
    return data.accessToken;
}
// ── Main fetch handler ────────────────────────────────────────
export async function handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const cors = corsHeaders(origin, env);
    // Reject direct access via *.workers.dev (enforce custom domain)
    if (url.hostname.endsWith('.workers.dev')) {
        return new Response(JSON.stringify({
            error: 'Direct access via workers.dev is disabled. Please access via the custom CDN domain.',
        }), {
            status: 403,
            headers: {
                ...cors,
                'Content-Type': 'application/json',
            },
        });
    }
    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: cors });
    }
    if (url.pathname === '/health' || url.pathname === '/load') {
        const metrics = getWorkerLoadMetrics();
        const colo = request.cf?.colo ?? 'edge';
        const secretsConfigured = !!(env.JWT_SECRET && env.WORKER_SHARED_SECRET);
        const isNodeOrRender = (typeof process !== 'undefined' && process.release?.name === 'node') ||
            !!(env.WORKER_ID && env.WORKER_ID.includes('render')) ||
            colo === 'render-edge' ||
            colo === 'render';
        // This is a public, unauthenticated endpoint (the load balancer polls
        // every worker with no auth) — trimmed to exactly what
        // apps/web/lib/worker-balancer.ts actually reads (`status`,
        // `secretsConfigured`, `loadScore`, `colo`, and the two X-Worker-Load
        // / X-Worker-Colo headers). It used to also hand out workerId,
        // cache sizes, request counts, and provider/region details to anyone
        // — a fingerprinting/reconnaissance freebie with no functional use.
        return new Response(JSON.stringify({
            status: 'ok',
            colo,
            secretsConfigured,
            loadScore: metrics.loadScore,
        }), {
            headers: {
                ...cors,
                'Content-Type': 'application/json',
                'X-Worker-Load': String(metrics.loadScore),
                'X-Worker-Colo': colo,
                ...(isNodeOrRender
                    ? {
                        'Cloudflare-CDN-Cache-Control': 'no-store, no-transform, bypass',
                        'Cache-Control': 'no-cache, no-store, no-transform',
                        'X-Accel-Buffering': 'no',
                    }
                    : {}),
            },
        });
    }
    const chunkMatch = url.pathname.match(/^\/([0-9a-f-]{36})\/chunk\/(\d+)$/);
    if (chunkMatch) {
        return handleChunkRequest(request, env, ctx, cors, chunkMatch[1], parseInt(chunkMatch[2], 10));
    }
    return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { ...cors, 'Content-Type': 'application/json' },
    });
}
export default {
    fetch: handleRequest,
};
// ── Chunk handler with Cloudflare Edge Caching ─────────────────
async function handleChunkRequest(request, env, ctx, cors, videoId, chunkIndex) {
    trackRequestStart();
    try {
        return await executeChunkRequest(request, env, ctx, cors, videoId, chunkIndex);
    }
    finally {
        trackRequestEnd();
    }
}
async function executeChunkRequest(request, env, ctx, cors, videoId, chunkIndex) {
    // Fail closed, once, for the whole request — a worker deployed without
    // both secrets set used to silently authenticate every segment request
    // against a constant baked into this source file.
    if (!env.JWT_SECRET || !env.WORKER_SHARED_SECRET) {
        return errorResponse(500, 'Worker is misconfigured (missing JWT_SECRET/WORKER_SHARED_SECRET)', cors);
    }
    const url = new URL(request.url);
    const token = url.searchParams.get('token');
    const quality = url.searchParams.get('q');
    const fileId = url.searchParams.get('fid');
    const gdriveAccountId = url.searchParams.get('acc');
    const sig = url.searchParams.get('sig');
    if (!token || !quality || !fileId || !gdriveAccountId || !sig) {
        return errorResponse(400, 'Missing token, q, fid, acc, or sig', cors);
    }
    // 0. Anti-Scraper & Download Tool Guard (Edge Inspection)
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const knownScrapers = [
        'yt-dlp', 'youtube-dl', 'curl/', 'wget/', 'aria2', 'axel/', 'httpie',
        'python-requests', 'requests/', 'aiohttp', 'httpx', 'urllib', 'scrapy',
        'go-http-client', 'okhttp', 'ffmpeg', 'ffprobe', 'mpv', 'node-fetch', 'undici'
    ];
    if (!ua || knownScrapers.some((s) => ua.includes(s))) {
        return errorResponse(403, 'Access denied: Automated scraping tools are strictly prohibited.', cors);
    }
    // 1. Verify stream token (cached in-memory — <0.01ms for repeat requests)
    const jwtSecret = requireSecret(env, 'JWT_SECRET');
    const payload = await verifyStreamToken(token, jwtSecret, env);
    if (!payload || payload.videoId !== videoId) {
        return errorResponse(401, 'Invalid or expired stream token', cors);
    }
    // 2. Tamper-evident segment signature verification (cached per fileId)
    const workerSecret = requireSecret(env, 'WORKER_SHARED_SECRET');
    const expectedSig = await signChunkParams(videoId, chunkIndex, quality, fileId, gdriveAccountId, workerSecret);
    if (!timingSafeEqualStr(sig, expectedSig)) {
        return errorResponse(403, 'Invalid segment signature', cors);
    }
    // 3. Rate limiting — now actually synchronous and actually enforced
    // (see checkRateLimitInMemory's comment above).
    const rlKey = payload.userId ?? `anon:${request.headers.get('CF-Connecting-IP') ?? 'unknown'}`;
    const maxPerMin = parseInt(env.MAX_SEGMENT_REQ_PER_MIN ?? '1200', 10);
    if (!checkRateLimitInMemory(`${rlKey}:${videoId}`, maxPerMin)) {
        return errorResponse(429, 'Rate limit exceeded', cors);
    }
    // 4. Cloudflare Edge Cache Match
    const cacheKey = new Request(`https://cache.slimestream.internal/segment/${encodeURIComponent(fileId)}`, {
        method: 'GET',
    });
    const cache = caches.default;
    const cached = await cache.match(cacheKey);
    if (cached) {
        const cachedHeaders = new Headers(cached.headers);
        for (const [k, v] of Object.entries(cors)) {
            cachedHeaders.set(k, v);
        }
        const metrics = getWorkerLoadMetrics();
        const colo = request.cf?.colo ?? 'edge';
        cachedHeaders.set('X-Slime-Cache', 'HIT');
        cachedHeaders.set('X-Slime-Chunk', String(chunkIndex));
        cachedHeaders.set('Accept-Ranges', 'bytes');
        cachedHeaders.set('Cache-Control', 'public, max-age=31536000, s-maxage=31536000, immutable');
        cachedHeaders.set('X-Worker-Load', String(metrics.loadScore));
        cachedHeaders.set('X-Worker-Active', String(metrics.activeRequests));
        cachedHeaders.set('X-Worker-Colo', colo);
        cachedHeaders.set('X-Worker-Id', env.WORKER_ID || 'edge-worker');
        return new Response(cached.body, {
            status: cached.status,
            headers: cachedHeaders,
        });
    }
    // 5. Fetch from Storage Node
    const rangeHeader = request.headers.get('Range');
    let storageRes;
    if (fileId.startsWith('http://') || fileId.startsWith('https://')) {
        storageRes = await fetch(fileId, {
            headers: rangeHeader ? { Range: rangeHeader } : {},
        });
    }
    else {
        const accessToken = await getGDriveAccessToken(gdriveAccountId, env);
        if (accessToken) {
            storageRes = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`, {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    ...(rangeHeader ? { Range: rangeHeader } : {}),
                },
            });
        }
        else {
            const workerSecret = requireSecret(env, 'WORKER_SHARED_SECRET');
            const internalRes = await fetch(`${env.API_BASE_URL}/internal/storage-url/${encodeURIComponent(gdriveAccountId)}?path=${encodeURIComponent(fileId)}`, {
                headers: { 'X-Worker-Secret': workerSecret },
            });
            if (internalRes.ok) {
                const { downloadUrl } = (await internalRes.json());
                storageRes = await fetch(downloadUrl, {
                    headers: rangeHeader ? { Range: rangeHeader } : {},
                });
            }
            else {
                return errorResponse(503, 'No usable credentials for this storage node', cors);
            }
        }
    }
    // If primary storage fetch fails (e.g. rate-limit, 403, 404, 5xx), seamlessly failover to standby replica mesh via VPS internal failover endpoint
    if (!storageRes || (!storageRes.ok && storageRes.status !== 206)) {
        try {
            const workerSecret = requireSecret(env, 'WORKER_SHARED_SECRET');
            const failoverUrl = `${env.API_BASE_URL}/internal/failover-chunk/${encodeURIComponent(videoId)}?q=${encodeURIComponent(quality)}&idx=${chunkIndex}`;
            const failoverRes = await fetch(failoverUrl, {
                headers: {
                    'X-Worker-Secret': workerSecret,
                    ...(rangeHeader ? { Range: rangeHeader } : {}),
                },
            });
            if (failoverRes.ok || failoverRes.status === 206) {
                storageRes = failoverRes;
            }
            else {
                return errorResponse(502, `Failed to fetch segment from primary node (${storageRes?.status ?? 502}) and replica mesh failover failed (${failoverRes.status})`, cors);
            }
        }
        catch {
            return errorResponse(502, `Failed to fetch segment from storage node (${storageRes?.status ?? 502})`, cors);
        }
    }
    // 6. Construct Edge Cacheable response
    const metrics = getWorkerLoadMetrics();
    const colo = request.cf?.colo ?? 'edge';
    const isNodeOrRender = (typeof process !== 'undefined' && process.release?.name === 'node') ||
        !!(env.WORKER_ID && env.WORKER_ID.includes('render')) ||
        colo === 'render-edge' ||
        colo === 'render';
    const responseHeaders = {
        ...cors,
        'Content-Type': 'application/octet-stream',
        'X-Slime-Chunk': String(chunkIndex),
        'X-Slime-Cache': 'MISS',
        'Accept-Ranges': 'bytes',
        'X-Worker-Load': String(metrics.loadScore),
        'X-Worker-Active': String(metrics.activeRequests),
        'X-Worker-Colo': colo,
        'X-Worker-Id': env.WORKER_ID || (isNodeOrRender ? 'render-worker' : 'edge-worker'),
        'X-Worker-Provider': isNodeOrRender ? 'render' : 'cloudflare',
    };
    if (isNodeOrRender) {
        // RENDER WORKER: Ensure chunk data is NEVER proxied, cached, or buffered by Cloudflare.
        // Proxy buffering delays video chunks and introduces stuttering.
        responseHeaders['Cache-Control'] = 'public, max-age=31536000, no-transform';
        responseHeaders['CDN-Cache-Control'] = 'public, max-age=31536000, no-transform';
        responseHeaders['Cloudflare-CDN-Cache-Control'] = 'no-store, no-transform, bypass';
        responseHeaders['CF-Cache-Status'] = 'BYPASS';
        responseHeaders['X-Accel-Buffering'] = 'no';
    }
    else {
        // CLOUDFLARE WORKER: Uses Cloudflare's native edge cache
        responseHeaders['Cache-Control'] = 'public, max-age=31536000, s-maxage=31536000, immutable';
        responseHeaders['CDN-Cache-Control'] = 'public, max-age=31536000, immutable';
        responseHeaders['Cloudflare-CDN-Cache-Control'] = 'public, max-age=31536000, immutable';
    }
    const contentLength = storageRes.headers.get('Content-Length');
    if (contentLength)
        responseHeaders['Content-Length'] = contentLength;
    if (rangeHeader && storageRes.status === 206) {
        responseHeaders['Content-Range'] = storageRes.headers.get('Content-Range') ?? '';
    }
    const status = storageRes.status === 206 ? 206 : 200;
    const response = new Response(storageRes.body, { status, headers: responseHeaders });
    // 7. Asynchronously save 200 OK responses to Cloudflare Edge Cache (only if running inside Cloudflare isolate)
    if (status === 200 && !isNodeOrRender && typeof caches !== 'undefined' && caches.default) {
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
    }
    else if (status === 200 && isNodeOrRender && typeof caches !== 'undefined' && caches.default) {
        // In-memory local cache on Render
        ctx.waitUntil(cache.put(cacheKey, response.clone()));
    }
    return response;
}
function errorResponse(status, message, cors) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { ...cors, 'Content-Type': 'application/json' },
    });
}
// If executed directly by Node (e.g. Render Web Service, node dist/index.js), launch the Node HTTP server
if (typeof process !== 'undefined' &&
    process.release?.name === 'node' &&
    process.argv?.[1] &&
    (process.argv[1].endsWith('index.js') || process.argv[1].endsWith('index.mjs') || process.argv[1].endsWith('server.js'))) {
    import('./server.js').then((m) => m.startNodeServer()).catch((err) => {
        console.error('[SlimeStream] Failed to start Node worker server:', err);
    });
}
//# sourceMappingURL=index.js.map