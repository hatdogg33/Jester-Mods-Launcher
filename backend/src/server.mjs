import { createServer } from 'node:http';
import {
  createHash, createPublicKey, createSign, createVerify, randomBytes, timingSafeEqual
} from 'node:crypto';
import { readFileSync, existsSync, mkdirSync, renameSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve, relative, sep } from 'node:path';

const env = { ...process.env };
const root = resolve(env.DATA_DIR || 'data');
const host = env.HOST || '127.0.0.1';
const port = Number(env.PORT || 8787);
const developmentMode = env.DEVELOPMENT_MODE !== 'false';
const adminToken = requireEnv('ADMIN_TOKEN');
const updatePrivateKey = readFileSync(requireEnv('UPDATE_SIGNING_PRIVATE_KEY'), 'utf8');
const leasePrivateKey = readFileSync(requireEnv('LEASE_SIGNING_PRIVATE_KEY'), 'utf8');
const updatePublicKeyPem = readFileSync(requireEnv('UPDATE_PUBLIC_KEY_PEM'), 'utf8');
const leasePublicKeyPem = readFileSync(requireEnv('LEASE_PUBLIC_KEY_PEM'), 'utf8');
const serviceHost = env.SERVICE_HOST || 'mono-server.internal';
const serviceOrigin = env.SERVICE_ORIGIN || `https://${serviceHost}`;

for (const directory of ['catalog', 'catalog/private', 'modules', 'releases', 'releases/apk', 'games', 'state', 'state/devices', 'state/tokens', 'state/grants']) {
  mkdirSync(join(root, directory), { recursive: true, mode: 0o700 });
}

function requireEnv(name) {
  if (!env[name]) throw new Error(`${name} is required.`);
  return env[name];
}
function now() { return Math.floor(Date.now() / 1000); }
function id(bytes = 24) { return randomBytes(bytes).toString('base64url'); }
function json(res, status, value) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(JSON.stringify(value));
}
function error(res, status, message, code = 'REQUEST_FAILED') { json(res, status, { ok: false, message, code }); }
function html(res, status, value) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(value);
}
function canonicalEnvelope(payload, privateKey = updatePrivateKey, extra = {}) {
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
  const signer = createSign('RSA-SHA256'); signer.update(bytes); signer.end();
  return { algorithm: 'SHA256withRSA', payload: bytes.toString('base64'), signature: signer.sign(privateKey).toString('base64'), ...extra };
}
function sha256(value) { return createHash('sha256').update(value).digest('base64url'); }
function sha256Hex(value) { return createHash('sha256').update(value).digest('hex'); }
function safePart(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._-]{1,200}$/.test(value)) throw new Error(`Invalid ${label}`);
  return value;
}
function safePath(...parts) {
  const path = resolve(root, ...parts);
  if (path !== root && !path.startsWith(root + sep)) throw new Error('Path escapes data directory');
  return path;
}
function readJson(path, fallback = null) { return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : fallback; }
function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${id(6)}.tmp`;
  writeFileSync(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  renameSync(temporary, path);
}
async function body(request, limit = 1024 * 1024) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > limit) throw new Error('Request is too large'); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
async function jsonBody(request) { return JSON.parse((await body(request)).toString('utf8')); }
function admin(request) {
  const supplied = request.headers.authorization?.replace(/^Bearer\s+/i, '') || '';
  const a = Buffer.from(supplied), b = Buffer.from(adminToken);
  return a.length === b.length && timingSafeEqual(a, b);
}
function sendFile(res, path, contentType = 'application/octet-stream') {
  if (!existsSync(path)) return error(res, 404, 'Not found');
  const bytes = readFileSync(path);
  res.writeHead(200, {
    'content-type': contentType,
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'accept-ranges': 'bytes',
    'x-content-type-options': 'nosniff'
  });
  res.end(bytes);
}
function fileHash(path) {
  if (!existsSync(path)) throw new Error('File not found');
  return { sha256: sha256Hex(readFileSync(path)), size: readFileSync(path).length };
}

// ---- ECDSA P-256 (secp256r1) proof verification -----------------------------

function spkiPem(base64UrlDer) {
  const der = Buffer.from(base64UrlDer, 'base64url');
  if (der.length < 60 || der.length > 96) throw new Error('Invalid public key encoding');
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  return '-----BEGIN PUBLIC KEY-----\n' + lines.join('\n') + '\n-----END PUBLIC KEY-----';
}

function keyIdForSpki(base64UrlDer) {
  return sha256(Buffer.from(base64UrlDer, 'base64url'));
}

function verifyEcdsaP1363(pem, message, signatureB64Url) {
  try {
    const signature = Buffer.from(signatureB64Url, 'base64url');
    if (signature.length !== 64) return false;
    const verifier = createVerify('SHA256');
    verifier.update(Buffer.from(message, 'utf8'));
    verifier.end();
    return verifier.verify({ key: pem, format: 'pem', type: 'spki', dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}

// ---- Canonical proof messages (must match LauncherProofKeyManager.kt) -------

function canonicalProof(lines) { return lines.join('\n'); }
function registrationCanonical(nonce, installationId, deviceId, flavor, accessVersion, keyId, publicKey) {
  return canonicalProof(['moodtools-proof-register-v1', `nonce=${nonce}`, `installationId=${installationId}`,
    `deviceId=${deviceId}`, `flavor=${flavor}`, `accessVersion=${accessVersion}`, `keyId=${keyId}`, `publicKey=${publicKey}`]);
}
function moduleAuthorizationCanonical(nonce, installationId, deviceId, flavor, accessVersion, packageName, slug, abi, bootstrap, keyId) {
  return canonicalProof(['moodtools-module-authorize-v1', `nonce=${nonce}`, `installationId=${installationId}`,
    `deviceId=${deviceId}`, `flavor=${flavor}`, `accessVersion=${accessVersion}`, `packageName=${packageName}`,
    `slug=${slug}`, `abi=${abi}`, `bootstrap=${bootstrap}`, `keyId=${keyId}`]);
}
function privateCatalogAuthorizationCanonical(nonce, installationId, deviceId, flavor, accessVersion, keyId) {
  return canonicalProof(['moodtools-private-catalog-authorize-v1', `nonce=${nonce}`, `installationId=${installationId}`,
    `deviceId=${deviceId}`, `flavor=${flavor}`, `accessVersion=${accessVersion}`, `keyId=${keyId}`]);
}
function recoveryBindingCanonical(nonce, installationId, deviceId, recoveryId, flavor, accessVersion, keyId) {
  return canonicalProof(['moodtools-recovery-bind-v1', `nonce=${nonce}`, `installationId=${installationId}`,
    `deviceId=${deviceId}`, `recoveryId=${recoveryId}`, `flavor=${flavor}`, `accessVersion=${accessVersion}`, `keyId=${keyId}`]);
}
function modulePayloadCanonical(nonce, method, path, keyId, capabilityHash) {
  return canonicalProof(['moodtools-module-payload-v1', `nonce=${nonce}`, `method=${method}`,
    `path=${path}`, `keyId=${keyId}`, `capabilityHash=${capabilityHash}`]);
}
function attestationEvidenceCanonical(nonce, installationId, deviceId, flavor, accessVersion, keyId, chainHash) {
  return canonicalProof(['moodtools-proof-attestation-evidence-v1', `nonce=${nonce}`, `installationId=${installationId}`,
    `deviceId=${deviceId}`, `flavor=${flavor}`, `accessVersion=${accessVersion}`, `keyId=${keyId}`, `chainHash=${chainHash}`]);
}

// ---- Device / account state --------------------------------------------------

function devicePath(deviceId) { return safePath('state', 'devices', `${safePart(deviceId, 'deviceId')}.json`); }
function loadDevice(deviceId) { return readJson(devicePath(deviceId)); }
function saveDevice(device) { writeJson(devicePath(device.deviceId), device); }
function findDeviceByDigitalKey(digitalKey) {
  return allDevices().find((device) => device.digitalKey === digitalKey) || null;
}
function findDeviceByProofKey(keyId) {
  return allDevices().find((device) => device.proofKeyId === keyId) || null;
}
function allDevices() {
  const directory = safePath('state', 'devices');
  if (!existsSync(directory)) return [];
  return readdirSync(directory).filter((name) => name.endsWith('.json')).map((name) =>
    readJson(join(directory, name))).filter(Boolean);
}
function touchDevice(input, digitalKey) {
  const deviceId = safePart(input.deviceId, 'deviceId');
  let device = loadDevice(deviceId) || { deviceId };
  device.installationId = safePart(input.installationId || device.installationId || deviceId, 'installationId');
  device.recoveryId = safePart(input.recoveryId || device.recoveryId || deviceId, 'recoveryId');
  device.flavor = safePart(input.flavor || device.flavor || 'root', 'flavor');
  device.accessVersion = Number(input.accessVersion || device.accessVersion || 4);
  device.digitalKey = digitalKey;
  if (input.proofKeyId) device.proofKeyId = safePart(input.proofKeyId, 'proofKeyId');
  saveDevice(device);
  return device;
}
function resolveProofKeyId(device, input) {
  if (input.proofKeyId && safePart(input.proofKeyId, 'proofKeyId') === device?.proofKeyId) return device.proofKeyId;
  return device?.proofKeyId || (input.proofKeyId ? safePart(input.proofKeyId, 'proofKeyId') : null);
}

// ---- Capability tokens ---------------------------------------------------------

function capability(request) {
  const token = request.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!token || !/^[A-Za-z0-9_.-]{80,4096}$/.test(token)) return null;
  const stored = readJson(safePath('state', 'capabilities.json'), {});
  const claim = stored[token];
  return claim && claim.expiresAt > now() ? claim : null;
}
function saveCapability(claim) {
  const path = safePath('state', 'capabilities.json'); const all = readJson(path, {}); all[id(64)] = claim;
  for (const [key, value] of Object.entries(all)) if (value.expiresAt <= now()) delete all[key];
  const token = Object.keys(all).at(-1); writeJson(path, all); return token;
}
function capabilityHash(token) { return sha256(token); }

// ---- Nonce challenges -----------------------------------------------------------

const PROOF_VERSION = 1;
const PROOF_NONCE_TTL_SECONDS = 120;
function newChallenge(device, purpose, keyId, canonicalBuilder) {
  const nonce = id(32);
  const canonical = canonicalBuilder(nonce);
  device.challenges = device.challenges || {};
  for (const [k, v] of Object.entries(device.challenges)) if (v.expiresAt <= now()) delete device.challenges[k];
  device.challenges[nonce] = { purpose, canonical, keyId, nonce, expiresAt: now() + PROOF_NONCE_TTL_SECONDS, used: false };
  saveDevice(device);
  return nonce;
}
function verifyProof(device, input, purpose, publicKeyPem) {
  if (!device || !input || !input.proof || input.proof.version !== PROOF_VERSION) return false;
  const proof = input.proof;
  if (!proof.keyId || !proof.nonce || !proof.signature) return false;
  const challenge = device.challenges?.[proof.nonce];
  if (!challenge || challenge.purpose !== purpose || challenge.used || challenge.expiresAt <= now()) return false;
  if (challenge.keyId !== proof.keyId) return false;
  const pem = publicKeyPem || device.proofPublicKeyPem;
  if (!pem) return false;
  if (!verifyEcdsaP1363(pem, challenge.canonical, proof.signature)) return false;
  challenge.used = true;
  saveDevice(device);
  return true;
}

// ---- Lease issuance ---------------------------------------------------------------

const LEASE_KEY_ID = 'launcher-lease-rsa-2026-01';
const OFFLINE_LEASE_AUDIENCE = 'moodtools-launcher-offline-lease';
function issueOfflineLease({ digitalKey, deviceId, flavor, proofKeyId, issuedAt, expiresAt }) {
  const payload = { schema: 1, audience: OFFLINE_LEASE_AUDIENCE, leaseVersion: 1, accessVersion: 4,
    proofVersion: PROOF_VERSION, grantId: id(18), deviceId, flavor, proofKeyId, digitalKeySha256: sha256(digitalKey),
    issuedAt, expiresAt };
  return canonicalEnvelope(payload, leasePrivateKey, { keyId: LEASE_KEY_ID });
}
function issueLeaseResponse({ digitalKey, deviceId, flavor, proofKeyId, recoveryBound }) {
  const issuedAt = now(); const expiresAt = issuedAt + 7 * 24 * 60 * 60;
  return { ok: true, digitalKey, issuedAt, expiresAt, proofKeyId, recoveryBound,
    offlineLease: issueOfflineLease({ digitalKey, deviceId, flavor, proofKeyId, issuedAt, expiresAt }) };
}
function privateLeaseResponse({ scope, device, grantExpiresAt }) {
  const issuedAt = now();
  const offlineExpiresAt = issuedAt + 7 * 24 * 60 * 60;
  const expiry = grantExpiresAt > offlineExpiresAt ? grantExpiresAt : offlineExpiresAt;
  const payload = { schema: 1, audience: 'moodtools-private-module-lease', leaseVersion: 1, accessVersion: 4,
    proofVersion: PROOF_VERSION, grantId: id(18), scope, deviceId: device.deviceId, recoveryId: device.recoveryId,
    flavor: device.flavor, proofKeyId: device.proofKeyId, issuedAt, expiresAt: offlineExpiresAt,
    grantExpiresAt: expiry };
  return { ok: true, approved: true, offlineLease: canonicalEnvelope(payload, leasePrivateKey, { keyId: LEASE_KEY_ID }) };
}

// ---- Catalog / module data ----------------------------------------------------------

function catalog() {
  return readJson(safePath('catalog', 'public.json'), { schema: 1, audience: 'moodtools-standalone', modules: [] });
}
function catalogModule(slug) {
  const module = catalog().modules.find((item) => item.slug === slug);
  if (!module) throw new Error('Module not found in catalog');
  return module;
}
function moduleDirectory(slug, build) { return safePath('modules', safePart(slug, 'slug'), String(Number(build))); }
function moduleManifest(slug, build, abi) {
  const manifest = readJson(join(moduleDirectory(slug, build), 'manifest.json'));
  if (!manifest) throw new Error('Module build not found');
  if (abi && !manifest.files?.native?.[abi]) throw new Error('Module ABI not found');
  return manifest;
}

// ---- Launcher releases ----------------------------------------------------------------

function stableRelease() { return readJson(safePath('releases', 'stable.json')); }
function testRelease(flavor) { return readJson(safePath('releases', `test-${flavor}.json`)); }
function launcherChangelog() { return readJson(safePath('releases', 'changelog.json')); }
function apkPath(flavor, build) { return safePath('releases', 'apk', safePart(flavor, 'flavor'), `${String(Number(build))}.apk`); }
function gamePath(slug, versionCode, ext) {
  return safePath('games', safePart(slug, 'slug'), `${String(Number(versionCode))}.${ext === 'apks' ? 'apks' : 'apk'}`);
}

// ---- Grants (release verification web flow) -------------------------------------------

function issueGrant(slug, build, packageName, nonce) {
  const grant = id(32);
  const path = safePath('state', 'grants', `${grant}.json`);
  writeJson(path, { grant, slug: safePart(slug, 'slug'), build: Number(build), packageName, nonce, issuedAt: now(), expiresAt: now() + 10 * 60 });
  return grant;
}
function consumeGrant(grant, slug, build) {
  const path = safePath('state', 'grants', `${safePart(grant, 'grant')}.json`);
  const stored = readJson(path);
  if (!stored || stored.expiresAt <= now()) return false;
  if (stored.slug !== slug || String(stored.build) !== String(build)) return false;
  return true;
}

// ---- Private catalog -------------------------------------------------------------------

function privateCatalogPayloads() {
  const directory = safePath('catalog', 'private');
  if (!existsSync(directory)) return [];
  return readdirSync(directory).filter((name) => name.endsWith('.json')).map((name) =>
    readJson(join(directory, name))).filter((item) => item && item.scope);
}
function privateCatalogForScope(scope) { return readJson(safePath('catalog', 'private', `${safePart(scope, 'scope')}.json`)); }

// ---- Play store / legacy update overrides -------------------------------------------------

function playStoreVersions() { return readJson(safePath('state', 'play-store.json'), {}); }
function modUpdateChannel() { return readJson(safePath('state', 'mod-update.json'), {}); }

// ---- Content type helpers ------------------------------------------------------------------

function contentTypeForPath(path) {
  if (path.endsWith('.png')) return 'image/png';
  if (path.endsWith('.jpg') || path.endsWith('.jpeg')) return 'image/jpeg';
  if (path.endsWith('.webp')) return 'image/webp';
  if (path.endsWith('.apk') || path.endsWith('.apks')) return 'application/vnd.android.package-archive';
  if (path.endsWith('.dex')) return 'application/octet-stream';
  if (path.endsWith('.so')) return 'application/octet-stream';
  return 'application/octet-stream';
}

// ---- HTML pages for web flows --------------------------------------------------------------

function unlockPage(query) {
  const params = Object.entries(query).map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('\n');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve launcher device</title><style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111}
.card{border:1px solid #ddd;border-radius:12px;padding:1.5rem}
button{width:100%;padding:.8rem;border:0;border-radius:8px;background:#0b7a3b;color:#fff;font-size:1rem;cursor:pointer}
code{background:#f3f4f6;padding:.15rem .4rem;border-radius:4px}
</style></head><body><div class="card"><h2>Approve this device for Jester Mods</h2>
<p>Review the requested installation and approve it to issue a digital key for this device.</p>
<form method="post" action="/launcher/unlock">${params}<button type="submit">Approve device</button></form>
</div></body></html>`;
}
function releaseGatePage({ slug, build, nonce, packageName }) {
  const hidden = [
    ['slug', slug], ['build', build], ['nonce', nonce || ''], ['packageName', packageName || '']
  ].map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('\n');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify add-on release</title><style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111}
.card{border:1px solid #ddd;border-radius:12px;padding:1.5rem}
button{width:100%;padding:.8rem;border:0;border-radius:8px;background:#0b7a3b;color:#fff;font-size:1rem;cursor:pointer}
code{background:#f3f4f6;padding:.15rem .4rem;border-radius:4px}
</style></head><body><div class="card"><h2>Verify add-on release</h2>
<p>Release <code>${escapeHtml(slug)}</code> build <code>${escapeHtml(build)}</code> requires release verification before it can be installed.</p>
<form method="post" action="/mod-update-release/${escapeHtml(slug)}/${escapeHtml(build)}">${hidden}<button type="submit">Approve for this device</button></form>
</div></body></html>`;
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, serviceOrigin);
    const path = url.pathname;
    const method = request.method;

    // ---- Health -------------------------------------------------------------------
    if (method === 'GET' && path === '/health') {
      return json(response, 200, { ok: true, developmentMode, backend: 'node', time: now() });
    }

    // ---- Public catalog --------------------------------------------------------------
    if (method === 'GET' && path === '/api/launcher-modules') {
      return json(response, 200, canonicalEnvelope(catalog()));
    }

    // ---- Lease recovery / renewal ------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/recover') {
      const input = await jsonBody(request);
      const deviceId = safePart(input.deviceId, 'deviceId');
      const proofKeyId = input.proofKeyId ? safePart(input.proofKeyId, 'proofKeyId') : null;
      const digitalKey = id(72);
      touchDevice(input, digitalKey);
      const device = loadDevice(deviceId);
      device.proofKeyId = proofKeyId;
      device.recoveryBound = true;
      saveDevice(device);
      return json(response, 200, issueLeaseResponse({ digitalKey, deviceId, flavor: device.flavor, proofKeyId, recoveryBound: true }));
    }

    if (method === 'POST' && path === '/api/launcher/access') {
      const input = await jsonBody(request);
      const digitalKey = typeof input.digitalKey === 'string' ? input.digitalKey : null;
      if (!digitalKey || digitalKey.length < 80) return error(response, 400, 'A valid digital key is required');
      const device = findDeviceByDigitalKey(digitalKey);
      const deviceId = device ? device.deviceId : safePart(input.deviceId, 'deviceId');
      if (!device) touchDevice(input, digitalKey);
      const proofKeyId = resolveProofKeyId(device, input) || id(32);
      return json(response, 200, issueLeaseResponse({ digitalKey, deviceId, flavor: device?.flavor || safePart(input.flavor, 'flavor'), proofKeyId, recoveryBound: device?.recoveryBound ?? true }));
    }

    // ---- Proof challenge / registration ---------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/proof/challenge') {
      const input = await jsonBody(request);
      const deviceId = safePart(input.deviceId, 'deviceId');
      const keyId = safePart(input.keyId || input.proofKeyId, 'keyId');
      const purpose = safePart(input.purpose || 'register', 'purpose');
      const flavor = safePart(input.flavor, 'flavor');
      const accessVersion = Number(input.accessVersion || 4);
      const installationId = safePart(input.installationId || deviceId, 'installationId');
      let device = loadDevice(deviceId);
      if (!device) { device = { deviceId, installationId, flavor, accessVersion }; saveDevice(device); }
      if (purpose === 'register') {
        if (device.proofKeyId === keyId && device.proofPublicKeyPem) {
          return json(response, 200, { ok: true, registered: true, proofVersion: PROOF_VERSION, keyId, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
        }
        const publicKey = input.publicKey ? safePart(input.publicKey, 'publicKey') : null;
        if (publicKey && keyIdForSpki(publicKey) !== keyId) return error(response, 400, 'Proof key identifier does not match the supplied public key');
        const nonce = newChallenge(device, 'register', keyId, (n) =>
          registrationCanonical(n, installationId, deviceId, flavor, accessVersion, keyId, publicKey || ''));
        return json(response, 200, { ok: true, registered: false, proofVersion: PROOF_VERSION, keyId, nonce, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
      }
      if (purpose === 'module-authorize') {
        const packageName = safePart(input.packageName, 'packageName');
        const slug = safePart(input.slug, 'slug');
        const abi = safePart(input.abi, 'abi');
        const bootstrap = Number(input.bootstrap || 1);
        const nonce = newChallenge(device, purpose, keyId, (n) =>
          moduleAuthorizationCanonical(n, installationId, deviceId, flavor, accessVersion, packageName, slug, abi, bootstrap, keyId));
        return json(response, 200, { ok: true, registered: true, proofVersion: PROOF_VERSION, keyId, nonce, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
      }
      if (purpose === 'private-catalog') {
        const nonce = newChallenge(device, purpose, keyId, (n) =>
          privateCatalogAuthorizationCanonical(n, installationId, deviceId, flavor, accessVersion, keyId));
        return json(response, 200, { ok: true, registered: true, proofVersion: PROOF_VERSION, keyId, nonce, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
      }
      if (purpose === 'recovery-bind') {
        const recoveryId = safePart(input.recoveryId || deviceId, 'recoveryId');
        const nonce = newChallenge(device, purpose, keyId, (n) =>
          recoveryBindingCanonical(n, installationId, deviceId, recoveryId, flavor, accessVersion, keyId));
        return json(response, 200, { ok: true, registered: true, proofVersion: PROOF_VERSION, keyId, nonce, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
      }
      return error(response, 400, `Unsupported proof purpose: ${purpose}`);
    }

    if (method === 'POST' && path === '/api/launcher/proof/register') {
      const input = await jsonBody(request);
      const deviceId = safePart(input.deviceId, 'deviceId');
      const device = loadDevice(deviceId);
      if (!device) return error(response, 404, 'Device is not registered');
      const publicKey = safePart(input.publicKey, 'publicKey');
      const keyId = keyIdForSpki(publicKey);
      if (input.proof?.keyId && input.proof.keyId !== keyId) return error(response, 400, 'Proof key identifier mismatch');
      const success = verifyProof(device, input, 'register', spkiPem(publicKey));
      if (!success) return error(response, 401, 'Invalid proof signature');
      device.proofKeyId = keyId;
      device.proofPublicKeyPem = spkiPem(publicKey);
      saveDevice(device);
      return json(response, 200, { ok: true, registered: true, proofVersion: PROOF_VERSION, keyId });
    }

    // ---- Module authorization (standalone) ------------------------------------------------
    if (method === 'POST' && path === '/api/launcher-module') {
      const input = await jsonBody(request);
      const slug = safePart(input.slug, 'slug');
      const module = catalogModule(slug);
      const build = Number(input.build) > 0 ? Number(input.build) : Number(module.build);
      const abi = safePart(input.abi, 'abi');
      const manifest = moduleManifest(slug, build, abi);
      const packageName = safePart(input.packageName || manifest.packageName || module.packageName, 'packageName');
      if (!developmentMode) {
        const device = findDeviceByDigitalKey(safePart(input.digitalKey, 'digitalKey'));
        const valid = verifyProof(device, input, 'module-authorize');
        if (!valid) return error(response, 401, 'Invalid proof signature');
        if (device.proofKeyId && (input.proof.keyId !== device.proofKeyId)) return error(response, 403, 'Proof key is not registered to this device');
      }
      const expiresAt = now() + 600;
      const token = saveCapability({ slug, build, abi, expiresAt, packageName });
      const proofKeyId = input.proof?.keyId || null;
      return json(response, 200, { ok: true, capability: token, expiresAt, proofRequired: true, proofVersion: PROOF_VERSION,
        proofKeyId, attestationRequired: false, privateScope: manifest.privateScope || null, manifest: canonicalEnvelope(manifest) });
    }

    // ---- Payload proof challenge -------------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher-module-proof') {
      const claim = capability(request);
      if (!claim) return error(response, 401, 'A valid module capability is required');
      const input = await jsonBody(request);
      const methodName = input.method === 'HEAD' ? 'HEAD' : 'GET';
      const proofPath = typeof input.path === 'string' && /^\/api\/launcher-module-payload\/[A-Za-z0-9._/-]{1,400}$/.test(input.path)
        ? input.path : null;
      if (!proofPath) return error(response, 400, 'Invalid payload path');
      const keyId = safePart(input.keyId, 'keyId');
      const device = findDeviceByProofKey(keyId);
      if (!device) return error(response, 404, 'Proof key is not registered');
      const hash = capabilityHash(capabilityToken(request));
      const nonce = newChallenge(device, 'payload', keyId, (n) => modulePayloadCanonical(n, methodName, proofPath, keyId, hash));
      return json(response, 200, { ok: true, proofVersion: PROOF_VERSION, keyId, nonce, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
    }

    // ---- Module payload delivery ---------------------------------------------------------------
    const payloadMatch = path.match(/^\/api\/launcher-module-payload\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\/(dex\/classes\.dex|native\/(arm64-v8a|armeabi-v7a))$/);
    if (method === 'GET' && payloadMatch) {
      const claim = capability(request);
      if (!claim) return error(response, 401, 'A valid module capability is required');
      const [, slug, build, kind, abi] = payloadMatch;
      if (claim.slug !== slug || String(claim.build) !== build || (abi && claim.abi !== abi)) return error(response, 403, 'Capability scope mismatch');
      if (!developmentMode) {
        const keyId = request.headers['x-moodtools-proof-key'];
        const nonce = request.headers['x-moodtools-proof-nonce'];
        const signature = request.headers['x-moodtools-proof-signature'];
        const device = keyId ? findDeviceByProofKey(safePart(keyId, 'keyId')) : null;
        const challenge = device?.challenges?.[nonce];
        const valid = device && challenge && !challenge.used && challenge.expiresAt > now() &&
          challenge.purpose === 'payload' && challenge.keyId === keyId && challenge.canonical ===
          modulePayloadCanonical(nonce, 'GET', path, keyId, capabilityHash(capabilityToken(request))) &&
          verifyEcdsaP1363(device.proofPublicKeyPem, challenge.canonical, signature);
        if (!valid) return error(response, 401, 'A valid payload proof is required');
        challenge.used = true;
        saveDevice(device);
      }
      return sendFile(response, safePath('modules', slug, build, kind === 'dex/classes.dex' ? 'classes.dex' : `native-${abi}.so`), contentTypeForPath(kind));
    }

    // ---- Module changelog ---------------------------------------------------------------------
    const changelogMatch = path.match(/^\/api\/launcher-module-changelog\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)$/);
    if (method === 'GET' && changelogMatch) {
      const [, slug, build] = changelogMatch;
      const manifest = moduleManifest(slug, Number(build));
      const stored = readJson(join(moduleDirectory(slug, build), 'changelog.json'));
      const payload = stored || {
        schema: 1, audience: 'moodtools-standalone-module-changelog', slug, packageName: manifest.packageName,
        currentBuild: Number(build), supportedVersions: manifest.moduleConfig?.supportedVersions || [],
        entries: [{ build: Number(build), version: manifest.version || String(Number(build)), updateType: 'minor', notes: manifest.notes || '', publishedAt: now() }]
      };
      return json(response, 200, canonicalEnvelope(payload));
    }

    // ---- Module features ------------------------------------------------------------------------
    const featuresMatch = path.match(/^\/api\/launcher-module-features\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)$/);
    if (method === 'GET' && featuresMatch) {
      const [, slug, build] = featuresMatch;
      const manifest = moduleManifest(slug, Number(build));
      const stored = readJson(join(moduleDirectory(slug, build), 'features.json'));
      const payload = stored || {
        schema: 1, audience: 'moodtools-standalone-module-features', slug, packageName: manifest.packageName,
        build: Number(build), groups: []
      };
      return json(response, 200, canonicalEnvelope(payload));
    }

    // ---- Module icon -----------------------------------------------------------------------------
    const iconMatch = path.match(/^\/api\/launcher-module-icon\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)(?:\/[0-9a-f]{64})?$/);
    if (method === 'GET' && iconMatch) {
      const [, slug, build] = iconMatch;
      const icon = safePath('modules', slug, build, 'icon.png');
      if (!existsSync(icon)) return error(response, 404, 'Module icon not found');
      return sendFile(response, icon, 'image/png');
    }

    // ---- Launcher self-update -------------------------------------------------------------------
    if (method === 'GET' && path === '/api/launcher-release') {
      const release = stableRelease();
      if (!release) return error(response, 404, 'No stable launcher release is published');
      return json(response, 200, canonicalEnvelope(release));
    }
    const testReleaseMatch = path.match(/^\/api\/launcher-test-release\/(root|nonroot)$/);
    if (method === 'GET' && testReleaseMatch) {
      const release = testRelease(testReleaseMatch[1]);
      if (!release) return error(response, 404, 'No test launcher release is published');
      return json(response, 200, canonicalEnvelope(release));
    }
    if (method === 'GET' && path === '/api/launcher-changelog') {
      const changelog = launcherChangelog();
      if (!changelog) return error(response, 404, 'No launcher changelog is published');
      return json(response, 200, canonicalEnvelope(changelog));
    }
    const launchDownload = path.match(/^\/api\/launcher-download\/(\d+)\/(root|nonroot)\.apk$/);
    if (method === 'GET' && launchDownload) {
      const [, build, flavor] = launchDownload;
      return sendFile(response, apkPath(flavor, build), 'application/vnd.android.package-archive');
    }
    const launchTestDownload = path.match(/^\/api\/launcher-test-download\/(\d+)\/(root|nonroot)\.apk$/);
    if (method === 'GET' && launchTestDownload) {
      const [, build, flavor] = launchTestDownload;
      return sendFile(response, apkPath(flavor, build), 'application/vnd.android.package-archive');
    }
    if (method === 'GET' && path === '/download/jester-moods-launcher') {
      const requested = url.searchParams.get('file') || '';
      const flavor = requested === 'Jester-Moods-Root.apk' ? 'root' : requested === 'Jester-Moods-NonRoot.apk' ? 'nonroot' : null;
      const release = stableRelease();
      if (!flavor || !release) return error(response, 404, 'Not found');
      const entry = release.files?.[flavor];
      if (!entry) return error(response, 404, 'Not found');
      const downloadMatch = entry.path?.match(/^\/api\/launcher-download\/(\d+)\/(root|nonroot)\.apk$/);
      const build = downloadMatch ? downloadMatch[1] : release.build;
      return sendFile(response, apkPath(flavor, build), 'application/vnd.android.package-archive');
    }

    // ---- Legacy module update channel -------------------------------------------------------------
    if (method === 'GET' && path === '/api/mod-update') {
      const packageName = safePart(url.searchParams.get('package') || '', 'packageName');
      const abi = safePart(url.searchParams.get('abi') || '', 'abi');
      const bootstrap = Number(url.searchParams.get('bootstrap') || 1);
      const channel = modUpdateChannel()[packageName];
      if (!channel) return error(response, 404, 'No update is available for this add-on');
      const slug = safePart(channel.slug, 'slug');
      const build = Number(channel.build);
      const manifest = moduleManifest(slug, build, abi);
      const native = manifest.files.native[abi];
      const dex = manifest.files.dex;
      const updateType = channel.updateType === 'release' ? 'release' : 'minor';
      const requiredReleaseBuild = channel.requiredReleaseBuild ? Number(channel.requiredReleaseBuild) : (updateType === 'release' ? build : 0);
      const payload = {
        schema: 3, minimumBootstrap: 1, packageName, slug, build, version: channel.version || manifest.version || String(build),
        notes: channel.notes || manifest.notes || '', updateType, requiredReleaseBuild,
        releasePath: `/mod-update-release/${slug}/${build}`,
        files: {
          native: { [abi]: { path: `/api/mod-update-payload/native/${slug}/${build}/${abi}`, ...manifest.files.native[abi] } },
          dex: { path: `/api/mod-update-payload/dex/${slug}/${build}/classes.dex`, ...manifest.files.dex }
        }
      };
      return json(response, 200, canonicalEnvelope(payload));
    }
    const modPayloadMatch = path.match(/^\/api\/mod-update-payload\/(native|dex)\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\/([A-Za-z0-9._-]+)$/);
    if (method === 'GET' && modPayloadMatch) {
      const [, kind, slug, build, file] = modPayloadMatch;
      const grant = request.headers['x-moodtools-update-grant'];
      if (grant) {
        if (!/^[A-Za-z0-9_.-]+$/.test(grant) || !consumeGrant(grant, slug, Number(build))) {
          return error(response, 403, 'The release grant is invalid or expired');
        }
      }
      const target = kind === 'dex' ? 'classes.dex' : file === 'classes.dex' ? 'classes.dex' : `native-${file}.so`;
      const full = safePath('modules', slug, build, target);
      return sendFile(response, full, contentTypeForPath(full));
    }

    // ---- Release verification web flow (legacy gate) ------------------------------------------------
    const releaseGate = path.match(/^\/mod-update-release\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)$/);
    if (releaseGate) {
      const [, slug, build] = releaseGate;
      if (method === 'GET') {
        const packageName = moduleManifest(slug, Number(build)).packageName || slug;
        return html(response, 200, releaseGatePage({ slug, build, nonce: url.searchParams.get('nonce') || '', packageName }));
      }
      if (method === 'POST') {
        const input = Object.fromEntries(url.searchParams);
        const submitted = await jsonBody(request).catch(() => null) || input || {};
        const nonce = safePart(submitted.nonce || url.searchParams.get('nonce') || '', 'nonce');
        const packageName = safePart(submitted.packageName || moduleManifest(slug, Number(build)).packageName || slug, 'packageName');
        const grant = issueGrant(slug, build, packageName, nonce);
        const target = `moodtools-update://resume/${encodeURIComponent(packageName)}?grant=${encodeURIComponent(grant)}&nonce=${encodeURIComponent(nonce)}&build=${build}`;
        return html(response, 200, `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${escapeHtml(target)}"></head><body><p>Approved. Opening Jester Mods&hellip;</p><a href="${escapeHtml(target)}">Open Jester Mods</a></body></html>`);
      }
    }

    // ---- Play Store version checks --------------------------------------------------------------------
    const playVersion = path.match(/^\/api\/launcher-play-store-version\/([A-Za-z0-9_.]{3,200})$/);
    if (method === 'GET' && playVersion) {
      const packageName = playVersion[1];
      const stored = playStoreVersions()[packageName];
      if (stored) {
        return json(response, 200, { ok: true, packageName, version: stored.version ?? null, versionCode: stored.versionCode ?? null,
          listingUpdatedAt: stored.listingUpdatedAt ?? 0, updateAvailable: stored.updateAvailable ?? null,
          checkedAt: stored.checkedAt || now(), stale: Boolean(stored.stale) });
      }
      return json(response, 200, { ok: true, packageName, version: null, versionCode: null, listingUpdatedAt: 0,
        updateAvailable: null, checkedAt: now(), stale: true });
    }
    if (method === 'POST' && path === '/api/launcher-play-store-versions') {
      const input = await jsonBody(request);
      const packageNames = Array.isArray(input.packageNames) ? input.packageNames : [];
      if (packageNames.length > 2000) return error(response, 400, 'Too many package names');
      const versions = playStoreVersions();
      const results = packageNames.filter((name) => typeof name === 'string' && /^[A-Za-z0-9_.]{3,200}$/.test(name)).map((packageName) => {
        const stored = versions[packageName];
        return stored
          ? { ok: true, packageName, version: stored.version ?? null, versionCode: stored.versionCode ?? null,
              listingUpdatedAt: stored.listingUpdatedAt ?? 0, updateAvailable: stored.updateAvailable ?? null,
              checkedAt: stored.checkedAt || now(), stale: Boolean(stored.stale) }
          : { ok: true, packageName, version: null, versionCode: null, listingUpdatedAt: 0, updateAvailable: null,
              checkedAt: now(), stale: true };
      });
      return json(response, 200, { ok: true, schema: 1, results });
    }

    // ---- Game downloads -------------------------------------------------------------------------------
    const gameDownload = path.match(/^\/api\/launcher-game-download\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\.(apk|apks)$/);
    if (method === 'GET' && gameDownload) {
      const [, slug, versionCode, ext] = gameDownload;
      return sendFile(response, gamePath(slug, versionCode, ext), 'application/vnd.android.package-archive');
    }

    // ---- Private access ---------------------------------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/private-access') {
      const input = await jsonBody(request);
      const device = loadDevice(safePart(input.deviceId, 'deviceId'));
      const digitalKey = safePart(input.digitalKey, 'digitalKey');
      if (!device || device.digitalKey !== digitalKey) return error(response, 401, 'Active launcher access is required');
      const scope = safePart(input.scope, 'scope');
      const proofKeyId = resolveProofKeyId(device, input);
      device.proofKeyId = proofKeyId || device.proofKeyId;
      device.recoveryBound = device.recoveryBound ?? true;
      saveDevice(device);
      if (!privateCatalogForScope(scope)) return json(response, 200, { ok: false, approved: false, message: 'This scope is not approved for this device' });
      return json(response, 200, privateLeaseResponse({ scope, device, grantExpiresAt: now() + 365 * 24 * 60 * 60 }));
    }

    // ---- Private catalog --------------------------------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/private-catalog') {
      const input = await jsonBody(request);
      const device = findDeviceByDigitalKey(safePart(input.digitalKey, 'digitalKey'));
      if (!developmentMode) {
        if (!device || !verifyProof(device, input, 'private-catalog')) return error(response, 401, 'Invalid proof signature');
      }
      const payloads = privateCatalogPayloads();
      const expiresAt = now() + 600;
      const capabilityTokenForPrivate = saveCapability({ private: true, expiresAt });
      return json(response, 200, {
        ok: true,
        catalogs: payloads.map((payload) => canonicalEnvelope(payload)),
        capability: capabilityTokenForPrivate,
        expiresAt
      });
    }

    // ---- Recovery binding -------------------------------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/recovery/bind') {
      const input = await jsonBody(request);
      const device = findDeviceByDigitalKey(safePart(input.digitalKey, 'digitalKey'));
      if (!developmentMode) {
        if (!device || !verifyProof(device, input, 'recovery-bind')) return error(response, 401, 'Invalid proof signature');
      }
      if (!device) return error(response, 404, 'Device is not registered');
      device.recoveryBound = true;
      device.recoveryId = safePart(input.recoveryId || device.recoveryId || device.deviceId, 'recoveryId');
      saveDevice(device);
      return json(response, 200, { ok: true, recoveryBound: true, proofKeyId: device.proofKeyId });
    }

    // ---- Attestation (self-hosted: accepted) -----------------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/proof/attestation/challenge') {
      const input = await jsonBody(request);
      const keyId = safePart(input.keyId || input.proofKeyId, 'keyId');
      return json(response, 200, { ok: true, registered: true, accepted: true, proofVersion: PROOF_VERSION, keyId, expiresAt: now() + PROOF_NONCE_TTL_SECONDS });
    }
    if (method === 'POST' && path === '/api/launcher/proof/attest') {
      const input = await jsonBody(request);
      const deviceId = safePart(input.deviceId, 'deviceId');
      const device = loadDevice(deviceId);
      const chainHash = input.attestation?.chainHash ? safePart(input.attestation.chainHash, 'chainHash') : id(32);
      const proofKeyId = input.proof?.keyId || device?.proofKeyId || id(32);
      return json(response, 200, { ok: true, registered: true, accepted: true, attestationVersion: 1, proofKeyId, chainHash });
    }

    // ---- Redeem (unlock return) -------------------------------------------------------------------------------
    if (method === 'POST' && path === '/api/launcher/redeem') {
      const input = await jsonBody(request);
      const token = safePart(input.token, 'token');
      const tokenPath = safePath('state', 'tokens', `${token}.json`);
      const pending = readJson(tokenPath);
      if (!pending || pending.used || pending.expiresAt <= now()) return error(response, 403, 'The unlock token is invalid or expired');
      if (input.challenge !== pending.challenge) return error(response, 403, 'The unlock challenge does not match');
      const deviceId = safePart(input.deviceId, 'deviceId');
      const publicKey = safePart(input.publicKey, 'publicKey');
      const keyId = keyIdForSpki(publicKey);
      if (input.proofKeyId !== keyId) return error(response, 400, 'Proof key identifier mismatch');
      const canonical = recoveryBindingCanonical(token, safePart(input.installationId || deviceId, 'installationId'), deviceId,
        safePart(input.recoveryId || deviceId, 'recoveryId'), safePart(input.flavor, 'flavor'), Number(input.accessVersion || 4), keyId);
      if (!verifyEcdsaP1363(spkiPem(publicKey), canonical, input.proof?.signature || '')) return error(response, 401, 'Invalid proof signature');
      const digitalKey = id(72);
      const device = loadDevice(deviceId) || { deviceId };
      device.digitalKey = digitalKey;
      device.installationId = safePart(input.installationId || deviceId, 'installationId');
      device.recoveryId = safePart(input.recoveryId || deviceId, 'recoveryId');
      device.flavor = safePart(input.flavor, 'flavor');
      device.proofKeyId = keyId;
      device.proofPublicKeyPem = spkiPem(publicKey);
      device.recoveryBound = true;
      saveDevice(device);
      pending.used = true;
      writeJson(tokenPath, pending);
      return json(response, 200, issueLeaseResponse({ digitalKey, deviceId, flavor: device.flavor, proofKeyId: keyId, recoveryBound: true }));
    }

    // ---- Unlock web flow -------------------------------------------------------------------------------------
    if (path === '/launcher/unlock') {
      if (method === 'GET') {
        return html(response, 200, unlockPage(Object.fromEntries(url.searchParams)));
      }
      if (method === 'POST') {
        const submitted = await jsonBody(request).catch(() => Object.fromEntries(url.searchParams));
        const challenge = safePart(submitted.challenge || url.searchParams.get('challenge') || '', 'challenge');
        const deviceId = safePart(submitted.device || submitted.deviceId || url.searchParams.get('device') || '', 'deviceId');
        const installationId = safePart(submitted.installation || submitted.installationId || url.searchParams.get('installation') || deviceId, 'installationId');
        const token = id(32);
        const tokenPath = safePath('state', 'tokens', `${token}.json`);
        writeJson(tokenPath, { token, challenge, deviceId, installationId, expiresAt: now() + 20 * 60, used: false });
        const target = `moodtools-launcher://unlock?token=${encodeURIComponent(token)}&challenge=${encodeURIComponent(challenge)}`;
        return html(response, 200, `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${escapeHtml(target)}"></head><body><p>Device approved. Opening Jester Mods&hellip;</p><a href="${escapeHtml(target)}">Open Jester Mods</a></body></html>`);
      }
      return error(response, 405, 'Method not allowed');
    }

    // ---- Admin: catalog -------------------------------------------------------------------------------------
    if (method === 'POST' && path === '/admin/catalog') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const value = await jsonBody(request);
      if (value.schema !== 1 || value.audience !== 'moodtools-standalone' || !Array.isArray(value.modules)) throw new Error('Invalid catalog schema');
      writeJson(safePath('catalog', 'public.json'), value);
      return json(response, 200, { ok: true });
    }

    // ---- Admin: module upload --------------------------------------------------------------------------------
    if (method === 'POST' && path === '/admin/module') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request);
      const slug = safePart(input.slug, 'slug'); const build = Number(input.build); const abi = safePart(input.abi, 'abi');
      if (!Number.isSafeInteger(build) || build < 1 || !input.manifest || !input.dexBase64 || !input.nativeBase64) throw new Error('Invalid module upload');
      const directory = moduleDirectory(slug, build); mkdirSync(directory, { recursive: true, mode: 0o700 });
      const dexBytes = Buffer.from(input.dexBase64, 'base64');
      const nativeBytes = Buffer.from(input.nativeBase64, 'base64');
      writeFileSync(join(directory, 'classes.dex'), dexBytes, { mode: 0o600 });
      writeFileSync(join(directory, `native-${abi}.so`), nativeBytes, { mode: 0o600 });
      const manifest = {
        ...input.manifest,
        packageName: input.manifest.packageName || slug,
        version: input.manifest.version || String(build),
        moduleConfig: input.manifest.moduleConfig || {
          packageName: slug, title: slug, supportedVersions: [], supportedAbis: [abi], dexFile: 'classes.dex',
          nativeFile: 'libmenu_native.so', entryPoint: ''
        },
        files: {
          native: { [abi]: { path: `/api/launcher-module-payload/${slug}/${build}/native/${abi}`, size: nativeBytes.length, sha256: sha256Hex(nativeBytes) } },
          dex: { path: `/api/launcher-module-payload/${slug}/${build}/dex/classes.dex`, size: dexBytes.length, sha256: sha256Hex(dexBytes) }
        }
      };
      writeJson(join(directory, 'manifest.json'), manifest);
      return json(response, 201, { ok: true });
    }

    // ---- Admin: module meta (changelog / features / icon) -------------------------------------------------------
    if (method === 'POST' && path === '/admin/module-meta') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request);
      const slug = safePart(input.slug, 'slug'); const build = Number(input.build);
      const directory = moduleDirectory(slug, build);
      if (!Number.isSafeInteger(build) || build < 1) throw new Error('Invalid module build');
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      if (input.changelog && typeof input.changelog === 'object') writeJson(join(directory, 'changelog.json'), input.changelog);
      if (input.features && typeof input.features === 'object') writeJson(join(directory, 'features.json'), input.features);
      if (input.iconBase64) {
        const iconBytes = Buffer.from(input.iconBase64, 'base64');
        writeFileSync(join(directory, 'icon.png'), iconBytes, { mode: 0o600 });
      }
      return json(response, 200, { ok: true });
    }

    // ---- Admin: binary upload (apk / icon / game / payload) --------------------------------------------------------
    if (method === 'POST' && path === '/admin/upload') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request, 512 * 1024 * 1024);
      const relative = typeof input.path === 'string' ? input.path : null;
      if (!relative || relative.includes('..') || !/^[A-Za-z0-9_./-]+$/.test(relative)) throw new Error('Invalid upload path');
      const target = safePath(relative);
      const bytes = Buffer.from(typeof input.base64 === 'string' ? input.base64 : '', 'base64');
      if (!bytes.length) throw new Error('Empty upload');
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, bytes, { mode: 0o600 });
      return json(response, 201, { ok: true, sha256: sha256Hex(bytes), size: bytes.length });
    }

    // ---- Admin: release metadata -------------------------------------------------------------------------------------
    if (method === 'POST' && path === '/admin/release') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request);
      const kind = input.kind === 'test' ? 'test' : input.kind === 'changelog' ? 'changelog' : 'stable';
      if (kind === 'changelog') {
        if (!Array.isArray(input.entries)) throw new Error('Invalid changelog');
        writeJson(safePath('releases', 'changelog.json'), { schema: 1, audience: 'moodtools-standalone-launcher-changelog', currentBuild: Number(input.currentBuild), entries: input.entries });
      } else if (kind === 'test') {
        const flavor = safePart(input.flavor, 'flavor');
        writeJson(safePath('releases', `test-${flavor}.json`), { schema: 1, audience: 'moodtools-standalone-launcher-test', build: Number(input.build), version: String(input.version), flavor, notes: input.notes || '', file: input.file });
      } else {
        if (!input.files?.root || !input.files?.nonroot) throw new Error('Both flavor files are required');
        writeJson(safePath('releases', 'stable.json'), { schema: 1, audience: 'moodtools-standalone-launcher', build: Number(input.build), version: String(input.version), notes: input.notes || '', files: input.files });
      }
      return json(response, 200, { ok: true });
    }

    // ---- Admin: play store version map --------------------------------------------------------------------------------
    if (method === 'POST' && path === '/admin/play-store') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request);
      if (!input.versions || typeof input.versions !== 'object') throw new Error('Invalid play store map');
      writeJson(safePath('state', 'play-store.json'), input.versions);
      return json(response, 200, { ok: true });
    }

    // ---- Admin: legacy mod-update channel -----------------------------------------------------------------------------
    if (method === 'POST' && path === '/admin/mod-update') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request);
      if (!input.channel || typeof input.channel !== 'object') throw new Error('Invalid module update channel');
      writeJson(safePath('state', 'mod-update.json'), input.channel);
      return json(response, 200, { ok: true });
    }

    // ---- Admin: private catalog ----------------------------------------------------------------------------------------
    if (method === 'POST' && path === '/admin/private-catalog') {
      if (!admin(request)) return error(response, 401, 'Admin authorization required');
      const input = await jsonBody(request);
      const scope = safePart(input.scope, 'scope');
      if (input.catalog?.schema !== 1 || input.catalog?.audience !== 'moodtools-standalone-private') throw new Error('Invalid private catalog');
      writeJson(safePath('catalog', 'private', `${scope}.json`), { ...input.catalog, scope });
      return json(response, 200, { ok: true });
    }

    return error(response, 404, 'Not found');
  } catch (cause) {
    console.error(cause);
    return error(response, 400, cause.message || 'Invalid request');
  }
});

// Returns the raw capability token from the Authorization header (used to hash a claim).
function capabilityToken(request) {
  return (request.headers.authorization?.replace(/^Bearer\s+/i, '') || '').trim();
}

server.listen(port, host, () => console.log(`Launcher backend listening on http://${host}:${port} (developmentMode=${developmentMode})`));