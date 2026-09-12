const encoder = new TextEncoder();
const decoder = new TextDecoder();
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const fail = (message, status = 400) => json({ ok: false, message }, status);
const now = () => Math.floor(Date.now() / 1000);
const token = () => crypto.getRandomValues(new Uint8Array(64)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const b64url = bytes => b64(bytes).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
async function sha256(text) { return b64url(await crypto.subtle.digest('SHA-256', encoder.encode(text))); }
function pemBytes(pem) { return Uint8Array.from(atob(pem.replace(/-----(BEGIN|END) PRIVATE KEY-----|\s/g, '')), c => c.charCodeAt(0)); }
async function signingKey(pem) { return crypto.subtle.importKey('pkcs8', pemBytes(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']); }
async function envelope(payload, pem, extra = {}) {
  const payloadBytes = encoder.encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', await signingKey(pem), payloadBytes);
  return { algorithm: 'SHA256withRSA', payload: b64(payloadBytes), signature: b64(signature), ...extra };
}
function part(value, name) { if (typeof value !== 'string' || !/^[A-Za-z0-9._-]{1,200}$/.test(value)) throw Error(`Invalid ${name}`); return value; }
async function input(request) { return request.json(); }
async function catalog(env) { return (await env.ARTIFACTS.get('catalog/public.json'))?.json() || { schema: 1, audience: 'moodtools-standalone', modules: [] }; }
async function capability(env, request) { const value = request.headers.get('authorization')?.replace(/^Bearer\s+/i, ''); return value ? env.STATE.get(`cap:${value}`, 'json') : null; }
async function issueLease(env, request) {
  const deviceId = part(request.deviceId, 'deviceId'), flavor = part(request.flavor, 'flavor'), proofKeyId = part(request.proofKeyId, 'proofKeyId');
  const digitalKey = typeof request.digitalKey === 'string' && request.digitalKey.length >= 80 ? request.digitalKey : token() + token();
  const issuedAt = now(), expiresAt = issuedAt + 604800;
  const lease = await envelope({ schema: 1, audience: 'moodtools-launcher-offline-lease', leaseVersion: 1, accessVersion: 4, proofVersion: 1, grantId: token().slice(0, 32), deviceId, flavor, proofKeyId, digitalKeySha256: await sha256(digitalKey), issuedAt, expiresAt }, env.LEASE_SIGNING_PRIVATE_KEY, { keyId: 'launcher-lease-rsa-2026-01' });
  return { ok: true, digitalKey, issuedAt, expiresAt, proofKeyId, recoveryBound: true, offlineLease: lease };
}
export default { async fetch(request, env) {
  try {
    const url = new URL(request.url), path = url.pathname;
    if (request.method === 'GET' && path === '/health') return json({ ok: true, developmentMode: true, time: now() });
    if (request.method === 'GET' && path === '/api/launcher-modules') return json(await envelope(await catalog(env), env.UPDATE_SIGNING_PRIVATE_KEY));
    if (request.method === 'POST' && (path === '/api/launcher/recover' || path === '/api/launcher/access')) return json(await issueLease(env, await input(request)));
    if (request.method === 'POST' && path === '/api/launcher/proof/challenge') { const body = await input(request); const keyId = part(body.keyId || body.proofKeyId, 'proofKeyId'); return json({ ok: true, registered: true, proofVersion: 1, keyId, nonce: token().slice(0, 48), expiresAt: now() + 300 }); }
    if (request.method === 'POST' && path === '/api/launcher-module') {
      const body = await input(request), slug = part(body.slug, 'slug'), abi = part(body.abi, 'abi'); const item = (await catalog(env)).modules.find(x => x.slug === slug); if (!item) return fail('Unknown module', 404);
      const build = item.build, manifest = await (await env.ARTIFACTS.get(`modules/${slug}/${build}/manifest.json`))?.json(); if (!manifest) return fail('Module manifest missing', 404);
      const capabilityToken = token(), expiresAt = now() + 600; await env.STATE.put(`cap:${capabilityToken}`, JSON.stringify({ slug, build, abi, expiresAt }), { expiration: expiresAt });
      return json({ ok: true, capability: capabilityToken, expiresAt, proofRequired: true, proofVersion: 1, proofKeyId: part(body.proof?.keyId || body.keyId, 'proofKeyId'), attestationRequired: false, manifest: await envelope(manifest, env.UPDATE_SIGNING_PRIVATE_KEY) });
    }
    const match = path.match(/^\/api\/launcher-module-payload\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\/(dex\/classes\.dex|native\/(arm64-v8a|armeabi-v7a))$/);
    if (request.method === 'GET' && match) { const claim = await capability(env, request); if (!claim || claim.expiresAt <= now()) return fail('Capability required', 401); const [, slug, build, kind, abi] = match; if (claim.slug !== slug || String(claim.build) !== build || (abi && claim.abi !== abi)) return fail('Capability scope mismatch', 403); const object = await env.ARTIFACTS.get(`modules/${slug}/${build}/${kind === 'dex/classes.dex' ? 'classes.dex' : `native-${abi}.so`}`); return object ? new Response(object.body, { headers: { 'content-type': 'application/octet-stream', 'cache-control': 'no-store' } }) : fail('Payload missing', 404); }
    return fail('Not found', 404);
  } catch (error) { return fail(error.message || 'Invalid request'); }
} };
