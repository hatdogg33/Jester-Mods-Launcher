var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/admin.js
function adminPage() {
  return new Response(`<!doctype html><meta name="viewport" content="width=device-width">
<title>voidmod1 admin</title><style>body{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;background:#10141c;color:#e8edf5}input,textarea,button{font:inherit;padding:.6rem;margin:.3rem 0;width:100%;box-sizing:border-box}textarea{min-height:16rem;font-family:monospace}button{cursor:pointer;background:#477dff;color:white;border:0;border-radius:5px}.card{background:#192131;padding:1rem;margin:1rem 0;border-radius:8px}#status{white-space:pre-wrap}</style>
<h1>voidmod1 admin</h1><div class="card"><label>Admin token</label><input id="token" type="password" autocomplete="current-password"><button onclick="save()">Save token</button></div>
<div class="card"><h2>Public catalog</h2><p>Paste the unsigned catalog payload JSON.</p><textarea id="catalog">{"schema":1,"audience":"moodtools-standalone","modules":[]}</textarea><button onclick="publish()">Publish catalog</button></div>
<div class="card"><h2>Result</h2><div id="status">Ready.</div></div>
<script>const token=document.querySelector('#token'),status=document.querySelector('#status');token.value=sessionStorage.getItem('voidmod1-admin-token')||'';function save(){sessionStorage.setItem('voidmod1-admin-token',token.value);status.textContent='Token saved for this browser tab.'}async function publish(){try{const r=await fetch('/admin/catalog',{method:'POST',headers:{'content-type':'application/json','x-admin-token':token.value},body:document.querySelector('#catalog').value});status.textContent=await r.text()}catch(e){status.textContent=e.toString()}}<\/script>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
__name(adminPage, "adminPage");

// src/index-kv.js
var enc = new TextEncoder();
var b64 = /* @__PURE__ */ __name((bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))), "b64");
var b64url = /* @__PURE__ */ __name((bytes) => b64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""), "b64url");
var fromB64url = /* @__PURE__ */ __name((s) => Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0)), "fromB64url");
var now = /* @__PURE__ */ __name(() => Math.floor(Date.now() / 1e3), "now");
var random = /* @__PURE__ */ __name((n = 48) => crypto.getRandomValues(new Uint8Array(n)).reduce((s, b) => s + b.toString(16).padStart(2, "0"), ""), "random");
var json = /* @__PURE__ */ __name((v, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } }), "json");
var html = /* @__PURE__ */ __name((v, status = 200) => new Response(v, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } }), "html");
var fail = /* @__PURE__ */ __name((m, s = 400) => json({ ok: false, message: m, code: "REQUEST_FAILED" }, s), "fail");
var part = /* @__PURE__ */ __name((v, n) => {
  if (typeof v !== "string" || !/^[A-Za-z0-9._-]{1,200}$/.test(v)) throw Error(`Invalid ${n}`);
  return v;
}, "part");
var payloadPath = /* @__PURE__ */ __name((v) => typeof v === "string" && /^\/api\/launcher-module-payload\/[A-Za-z0-9._/-]{1,400}$/.test(v) ? v : null, "payloadPath");
var pemBytes = /* @__PURE__ */ __name((pem) => Uint8Array.from(atob(pem.replace(/-----(BEGIN|END) PRIVATE KEY-----|\s/g, "")), (c) => c.charCodeAt(0)), "pemBytes");
async function key(pem) {
  return crypto.subtle.importKey("pkcs8", pemBytes(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}
__name(key, "key");
async function signed(payload, pem, extra = {}) {
  const bytes = enc.encode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", await key(pem), bytes);
  return { algorithm: "SHA256withRSA", payload: b64(bytes), signature: b64(sig), ...extra };
}
__name(signed, "signed");
async function sha256(text) {
  return b64url(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}
__name(sha256, "sha256");
async function sha256Hex(bytes) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");
async function read(env, k, fallback = null) {
  const v = await env.STATE.get(k, "json");
  return v ?? fallback;
}
__name(read, "read");
async function bytes_at(env, k) {
  const v = await env.STATE.get(k, "arrayBuffer");
  return v ? new Uint8Array(v) : null;
}
__name(bytes_at, "bytes_at");
async function body(req) {
  return req.json();
}
__name(body, "body");
async function formOrJson(req, params) {
  const text = await req.text();
  if (!text) return Object.fromEntries(params);
  try {
    return { ...Object.fromEntries(params), ...JSON.parse(text) };
  } catch {
  }
  const merged = Object.fromEntries(params);
  for (const [k, v] of new URLSearchParams(text)) merged[k] = v;
  return merged;
}
__name(formOrJson, "formOrJson");
function file(bytes, contentType) {
  return bytes ? new Response(bytes, { headers: { "content-type": contentType, "cache-control": "no-store", "x-content-type-options": "nosniff" } }) : fail("Not found", 404);
}
__name(file, "file");
function authorized(request, env) {
  const a = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || request.headers.get("x-admin-token") || "";
  const b = env.ADMIN_TOKEN || "";
  if (!a || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
__name(authorized, "authorized");
async function verifyEcdsa(publicKeyB64Url, message, signatureB64Url) {
  try {
    const signature = fromB64url(signatureB64Url);
    if (signature.length !== 64) return false;
    const publicKey = await crypto.subtle.importKey("spki", fromB64url(publicKeyB64Url), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, enc.encode(message));
  } catch {
    return false;
  }
}
__name(verifyEcdsa, "verifyEcdsa");
async function enrollment(env, x) {
  const deviceId = part(x.deviceId, "deviceId");
  const keyId = part(x.keyId || x.proofKeyId || "dev-proof-key", "proofKeyId");
  let device = await read(env, `device:${deviceId}`, null);
  if (!device) {
    device = { deviceId, proofKeyId: keyId };
    await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
  }
  if (x.publicKey) {
    device.proofKeyId = keyId;
    device.proofPublicKey = part(x.publicKey, "publicKey");
    await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
  }
  return device;
}
__name(enrollment, "enrollment");
async function deviceByProofKey(env, keyId) {
  const list = await env.STATE.list({ prefix: "device:" });
  for (const entry of list.keys) {
    const device = await env.STATE.get(entry.name, "json");
    if (device && device.proofKeyId === keyId) return device;
  }
  return null;
}
__name(deviceByProofKey, "deviceByProofKey");
async function deviceByDigitalKey(env, digitalKey) {
  const list = await env.STATE.list({ prefix: "device:" });
  for (const entry of list.keys) {
    const device = await env.STATE.get(entry.name, "json");
    if (device && device.digitalKey === digitalKey) return device;
  }
  return null;
}
__name(deviceByDigitalKey, "deviceByDigitalKey");
async function lease(env, x) {
  const deviceId = part(x.deviceId, "deviceId");
  let device = await read(env, `device:${deviceId}`, null) || { deviceId };
  const flavor = part(x.flavor || device.flavor || "root", "flavor");
  const proofKeyId = part(x.proofKeyId || device.proofKeyId || "dev-proof-key", "proofKeyId");
  const digitalKey = x.digitalKey?.length >= 80 ? x.digitalKey : random(72);
  const issuedAt = now(), expiresAt = issuedAt + 604800;
  const digest = b64url(await crypto.subtle.digest("SHA-256", enc.encode(digitalKey)));
  const offlineLease = await signed({ schema: 1, audience: "moodtools-launcher-offline-lease", leaseVersion: 1, accessVersion: 4, proofVersion: 1, grantId: random(18), deviceId, flavor, proofKeyId, digitalKeySha256: digest, issuedAt, expiresAt }, env.LEASE_SIGNING_PRIVATE_KEY, { keyId: "launcher-lease-rsa-2026-01" });
  device.installationId = part(x.installationId || device.installationId || deviceId, "installationId");
  device.recoveryId = part(x.recoveryId || device.recoveryId || deviceId, "recoveryId");
  device.flavor = flavor;
  device.proofKeyId = proofKeyId;
  device.digitalKey = digitalKey;
  device.accessVersion = Number(x.accessVersion || device.accessVersion || 4);
  device.recoveryBound = device.recoveryBound ?? true;
  await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
  return { ok: true, digitalKey, issuedAt, expiresAt, recoveryBound: true, proofKeyId, offlineLease };
}
__name(lease, "lease");
function unlockPage(params) {
  const hidden = Object.entries(params).map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join("\n");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve launcher device</title><style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#111}
.card{border:1px solid #ddd;border-radius:12px;padding:1.5rem}
button{width:100%;padding:.8rem;border:0;border-radius:8px;background:#0b7a3b;color:#fff;font-size:1rem;cursor:pointer}
code{background:#f3f4f6;padding:.15rem .4rem;border-radius:4px}
</style></head><body><div class="card"><h2>Approve this device for Jester Mods</h2>
<p>Review the requested installation and approve it to issue a digital key for this device.</p>
<form method="post" action="/launcher/unlock">${hidden}<button type="submit">Approve device</button></form>
</div></body></html>`;
}
__name(unlockPage, "unlockPage");
function releaseGatePage({ slug, build, nonce, packageName }) {
  const hidden = [["slug", slug], ["build", build], ["nonce", nonce || ""], ["packageName", packageName || ""]].map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join("\n");
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
__name(releaseGatePage, "releaseGatePage");
function redirectHtml(target) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${escapeHtml(target)}"></head><body><p>Approved. Opening Jester Mods&hellip;</p><a href="${escapeHtml(target)}">Open Jester Mods</a></body></html>`;
}
__name(redirectHtml, "redirectHtml");
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}
__name(escapeHtml, "escapeHtml");
var modulePayloadRe = /^\/api\/launcher-module-payload\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\/(dex\/classes\.dex|native\/(arm64-v8a|armeabi-v7a))$/;
var changelogRe = /^\/api\/launcher-module-changelog\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)$/;
var featuresRe = /^\/api\/launcher-module-features\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)$/;
var iconRe = /^\/api\/launcher-module-icon\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)(?:\/[0-9a-f]{64})?$/;
var testReleaseRe = /^\/api\/launcher-test-release\/(root|nonroot)$/;
var launchDownloadRe = /^\/api\/launcher-download\/(\d+)\/(root|nonroot)\.apk$/;
var launchTestDownloadRe = /^\/api\/launcher-test-download\/(\d+)\/(root|nonroot)\.apk$/;
var modPayloadRe = /^\/api\/mod-update-payload\/(native|dex)\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\/([A-Za-z0-9._-]+)$/;
var releaseGateRe = /^\/mod-update-release\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)$/;
var playVersionRe = /^\/api\/launcher-play-store-version\/([A-Za-z0-9_.]{3,200})$/;
var gameDownloadRe = /^\/api\/launcher-game-download\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\.(apk|apks)$/;
var apkUploadRe = /^releases\/apk\/(root|nonroot)\/(\d+)\.apk$/;
var gameUploadRe = /^games\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\.(apk|apks)$/;
var moduleFileRe = /^modules\/([a-z0-9][a-z0-9-]{0,63})\/(\d+)\/(classes\.dex|native-([a-z0-9_-]+)\.so|icon\.png)$/;
var index_kv_default = { async fetch(req, env) {
  try {
    const u = new URL(req.url), p = u.pathname, params = u.searchParams, method = req.method;
    const strict = (env.DEVELOPMENT_MODE ?? "true") === "false";
    if (method === "GET" && p === "/admin") return adminPage();
    if (method === "GET" && p === "/health") return json({ ok: true, kvOnly: true, time: now(), strict });
    if (method === "GET" && p === "/api/launcher-modules") {
      const catalog = await read(env, "catalog:public", { schema: 1, audience: "moodtools-standalone", modules: [] });
      return json(await signed(catalog, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    if (method === "POST" && (p === "/api/launcher/access" || p === "/api/launcher/recover")) return json(await lease(env, await body(req)));
    if (method === "POST" && p === "/api/launcher/proof/challenge") {
      const x = await body(req);
      const keyId = part(x.keyId || x.proofKeyId || "dev-proof-key", "proofKeyId");
      const purpose = part(x.purpose || "register", "purpose");
      const device = await enrollment(env, x);
      if (purpose === "register") {
        const registered = !!(device && device.proofPublicKey && device.proofKeyId === keyId);
        return json({ ok: true, registered, proofVersion: 1, keyId, nonce: registered ? null : random(32), expiresAt: registered ? null : now() + 300 });
      }
      return json({ ok: true, registered: true, proofVersion: 1, keyId, nonce: random(32), expiresAt: now() + 300 });
    }
    if (method === "POST" && p === "/api/launcher/proof/register") {
      const x = await body(req);
      const keyId = part(x.keyId || x.proof?.keyId || "dev-proof-key", "proofKeyId");
      await enrollment(env, { ...x, keyId });
      return json({ ok: true, registered: true, proofVersion: 1, keyId });
    }
    if (method === "POST" && p === "/api/launcher-module") {
      const x = await body(req);
      const slug = part(x.slug, "slug"), abi = part(x.abi, "abi");
      const item = (await read(env, "catalog:public", { modules: [] })).modules.find((m2) => m2.slug === slug);
      if (!item) return fail("Unknown module", 404);
      const build = Number(x.build) > 0 ? Number(x.build) : Number(item.build || 1);
      const manifest = await read(env, `module:${slug}:${build}:manifest`);
      if (!manifest) return fail("Module manifest missing", 404);
      if (abi && manifest.files && !manifest.files.native?.[abi]) return fail("Module ABI not found", 404);
      const capability = random(64), expiresAt = now() + 600;
      await env.STATE.put(`cap:${capability}`, JSON.stringify({ slug, build, abi, expiresAt, packageName: String(x.packageName || manifest.packageName || item.packageName || slug) }), { expirationTtl: 600 });
      return json({ ok: true, capability, expiresAt, proofRequired: true, proofVersion: 1, proofKeyId: part(x.proof?.keyId || x.keyId || "dev-proof-key", "proofKeyId"), attestationRequired: false, privateScope: manifest.privateScope || null, manifest: await signed(manifest, env.UPDATE_SIGNING_PRIVATE_KEY) });
    }
    let m = p.match(modulePayloadRe);
    if (method === "GET" && m) {
      const cap = req.headers.get("authorization")?.replace(/^Bearer\s+/i, ""), claim = cap && await read(env, `cap:${cap}`);
      if (!claim || claim.expiresAt <= now()) return fail("A valid module capability is required", 401);
      const [, slug, build, kind, abi] = m;
      if (claim.slug !== slug || String(claim.build) !== build || abi && claim.abi !== abi) return fail("Capability scope mismatch", 403);
      if (strict) {
        const keyId = req.headers.get("x-moodtools-proof-key"), nonce = req.headers.get("x-moodtools-proof-nonce"), signature = req.headers.get("x-moodtools-proof-signature");
        const device = keyId ? await deviceByProofKey(env, part(keyId, "keyId")) : null;
        if (!device || !device.proofPublicKey) return fail("A valid payload proof is required", 401);
        const canonical = ["moodtools-module-payload-v1", `nonce=${nonce}`, "method=GET", `path=${p}`, `keyId=${keyId}`, `capabilityHash=${await sha256(cap)}`].join("\n");
        if (!await verifyEcdsa(device.proofPublicKey, canonical, signature)) return fail("A valid payload proof is required", 401);
      }
      const value = await bytes_at(env, `module:${slug}:${build}:${kind === "dex/classes.dex" ? "dex" : `native:${abi}`}`);
      return file(value, "application/octet-stream");
    }
    if (method === "POST" && p === "/api/launcher-module-proof") {
      const cap = req.headers.get("authorization")?.replace(/^Bearer\s+/i, ""), claim = cap && await read(env, `cap:${cap}`);
      if (!claim || claim.expiresAt <= now()) return fail("A valid module capability is required", 401);
      const x = await body(req);
      const proofPath = payloadPath(x.path);
      if (!proofPath) return fail("Invalid payload path", 400);
      const keyId = part(x.keyId, "keyId");
      if (!strict) return json({ ok: true, proofVersion: 1, keyId, nonce: random(32), expiresAt: now() + 300 });
      const device = await deviceByProofKey(env, keyId);
      if (!device) return fail("Proof key is not registered", 404);
      return json({ ok: true, proofVersion: 1, keyId, nonce: random(32), expiresAt: now() + 300 });
    }
    m = p.match(changelogRe);
    if (method === "GET" && m) {
      const [, slug, build] = m;
      const manifest = await read(env, `module:${slug}:${build}:manifest`);
      if (!manifest) return fail("Module build not found", 404);
      const stored = await read(env, `module:${slug}:${build}:changelog`);
      const payload = stored || { schema: 1, audience: "moodtools-standalone-module-changelog", slug, packageName: manifest.packageName, currentBuild: Number(build), supportedVersions: manifest.moduleConfig?.supportedVersions || [], entries: [{ build: Number(build), version: manifest.version || String(Number(build)), updateType: "minor", notes: manifest.notes || "", publishedAt: now() }] };
      return json(await signed(payload, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    m = p.match(featuresRe);
    if (method === "GET" && m) {
      const [, slug, build] = m;
      const manifest = await read(env, `module:${slug}:${build}:manifest`);
      if (!manifest) return fail("Module build not found", 404);
      const stored = await read(env, `module:${slug}:${build}:features`);
      const payload = stored || { schema: 1, audience: "moodtools-standalone-module-features", slug, packageName: manifest.packageName, build: Number(build), groups: [] };
      return json(await signed(payload, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    m = p.match(iconRe);
    if (method === "GET" && m) {
      const [, slug, build] = m;
      const value = await bytes_at(env, `module:${slug}:${build}:icon`);
      return file(value, "image/png");
    }
    if (method === "GET" && p === "/api/launcher-release") {
      const release = await read(env, "release:stable");
      if (!release) return fail("No stable launcher release is published", 404);
      return json(await signed(release, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    m = p.match(testReleaseRe);
    if (method === "GET" && m) {
      const release = await read(env, `release:test:${m[1]}`);
      if (!release) return fail("No test launcher release is published", 404);
      return json(await signed(release, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    if (method === "GET" && p === "/api/launcher-changelog") {
      const changelog = await read(env, "release:changelog");
      if (!changelog) return fail("No launcher changelog is published", 404);
      return json(await signed(changelog, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    m = p.match(launchDownloadRe);
    if (method === "GET" && m) return file(await bytes_at(env, `release:apk:${m[2]}:${m[1]}`), "application/vnd.android.package-archive");
    m = p.match(launchTestDownloadRe);
    if (method === "GET" && m) return file(await bytes_at(env, `release:apk:${m[2]}:${m[1]}`), "application/vnd.android.package-archive");
    if (method === "GET" && p === "/download/jester-moods-launcher") {
      const requested = params.get("file") || "";
      const flavor = requested === "Jester-Moods-Root.apk" ? "root" : requested === "Jester-Moods-NonRoot.apk" ? "nonroot" : null;
      const release = await read(env, "release:stable");
      const entry = flavor && release?.files?.[flavor];
      if (!entry) return fail("Not found", 404);
      const match = entry.path?.match(/^\/api\/launcher-download\/(\d+)\/(root|nonroot)\.apk$/);
      const build = match ? match[1] : release.build;
      return file(await bytes_at(env, `release:apk:${flavor}:${build}`), "application/vnd.android.package-archive");
    }
    if (method === "GET" && p === "/api/mod-update") {
      const packageName = part(params.get("package") || "", "packageName");
      const abi = part(params.get("abi") || "", "abi");
      const bootstrap = Number(params.get("bootstrap") || 1);
      const channel = (await read(env, "state:mod-update", {}))[packageName];
      if (!channel) return fail("No update is available for this add-on", 404);
      const slug = part(channel.slug, "slug");
      const build = Number(channel.build);
      const manifest = await read(env, `module:${slug}:${build}:manifest`);
      if (!manifest) return fail("Module build not found", 404);
      const native = manifest.files?.native?.[abi];
      const dex = manifest.files?.dex;
      if (!native || !dex) return fail("Module ABI not found", 404);
      const updateType = channel.updateType === "release" ? "release" : "minor";
      const requiredReleaseBuild = channel.requiredReleaseBuild ? Number(channel.requiredReleaseBuild) : updateType === "release" ? build : 0;
      const payload = {
        schema: 3,
        minimumBootstrap: 1,
        packageName,
        slug,
        build,
        version: channel.version || manifest.version || String(build),
        notes: channel.notes || manifest.notes || "",
        updateType,
        requiredReleaseBuild,
        releasePath: `/mod-update-release/${slug}/${build}`,
        files: {
          native: { [abi]: { path: `/api/mod-update-payload/native/${slug}/${build}/${abi}`, ...native } },
          dex: { path: `/api/mod-update-payload/dex/${slug}/${build}/classes.dex`, ...dex }
        }
      };
      return json(await signed(payload, env.UPDATE_SIGNING_PRIVATE_KEY));
    }
    m = p.match(modPayloadRe);
    if (method === "GET" && m) {
      const [, kind, slug, build, fileArg] = m;
      const grant = req.headers.get("x-moodtools-update-grant");
      if (grant) {
        const stored = await env.STATE.get(`grant:${grant}`, "json");
        if (!stored || stored.expiresAt <= now() || stored.slug !== slug || String(stored.build) !== String(build)) return fail("The release grant is invalid or expired", 403);
      }
      const target = kind === "dex" ? "dex" : fileArg === "classes.dex" ? "dex" : `native:${fileArg}`;
      return file(await bytes_at(env, `module:${slug}:${build}:${target}`), "application/octet-stream");
    }
    m = p.match(releaseGateRe);
    if (m) {
      const [, slug, build] = m;
      if (method === "GET") {
        const manifest = await read(env, `module:${slug}:${build}:manifest`);
        const packageName = manifest?.packageName || slug;
        return html(releaseGatePage({ slug, build, nonce: params.get("nonce") || "", packageName }));
      }
      if (method === "POST") {
        const submitted = await formOrJson(req, params);
        const nonce = part(submitted.nonce || params.get("nonce") || "", "nonce");
        const manifest = await read(env, `module:${slug}:${build}:manifest`);
        const packageName = part(submitted.packageName || manifest?.packageName || slug, "packageName");
        const grant = random(32);
        await env.STATE.put(`grant:${grant}`, JSON.stringify({ slug, build: Number(build), packageName, nonce, issuedAt: now(), expiresAt: now() + 600 }), { expirationTtl: 600 });
        const target = `moodtools-update://resume/${encodeURIComponent(packageName)}?grant=${encodeURIComponent(grant)}&nonce=${encodeURIComponent(nonce)}&build=${build}`;
        return html(redirectHtml(target));
      }
    }
    m = p.match(playVersionRe);
    if (method === "GET" && m) {
      const packageName = m[1];
      const stored = (await read(env, "state:play-store", {}))[packageName];
      if (stored) return json({ ok: true, packageName, version: stored.version ?? null, versionCode: stored.versionCode ?? null, listingUpdatedAt: stored.listingUpdatedAt ?? 0, updateAvailable: stored.updateAvailable ?? null, checkedAt: stored.checkedAt || now(), stale: Boolean(stored.stale) });
      return json({ ok: true, packageName, version: null, versionCode: null, listingUpdatedAt: 0, updateAvailable: null, checkedAt: now(), stale: true });
    }
    if (method === "POST" && p === "/api/launcher-play-store-versions") {
      const x = await body(req);
      const packageNames = Array.isArray(x.packageNames) ? x.packageNames : [];
      if (packageNames.length > 2e3) return fail("Too many package names", 400);
      const versions = await read(env, "state:play-store", {});
      const results = packageNames.filter((n) => typeof n === "string" && /^[A-Za-z0-9_.]{3,200}$/.test(n)).map((packageName) => {
        const stored = versions[packageName];
        return stored ? { ok: true, packageName, version: stored.version ?? null, versionCode: stored.versionCode ?? null, listingUpdatedAt: stored.listingUpdatedAt ?? 0, updateAvailable: stored.updateAvailable ?? null, checkedAt: stored.checkedAt || now(), stale: Boolean(stored.stale) } : { ok: true, packageName, version: null, versionCode: null, listingUpdatedAt: 0, updateAvailable: null, checkedAt: now(), stale: true };
      });
      return json({ ok: true, schema: 1, results });
    }
    m = p.match(gameDownloadRe);
    if (method === "GET" && m) return file(await bytes_at(env, `game:${m[1]}:${m[2]}`), "application/vnd.android.package-archive");
    if (method === "POST" && p === "/api/launcher/private-access") {
      const x = await body(req);
      const deviceId = part(x.deviceId, "deviceId");
      const digitalKey = String(x.digitalKey || "");
      const device = await read(env, `device:${deviceId}`, null);
      if (!device || device.digitalKey !== digitalKey) return fail("Active launcher access is required", 401);
      const scope = part(x.scope, "scope");
      if (!await read(env, `catalog:private:${scope}`)) return json({ ok: false, approved: false, message: "This scope is not approved for this device" });
      const proofKeyId = part(x.proofKeyId || device.proofKeyId || "dev-proof-key", "proofKeyId");
      device.proofKeyId = proofKeyId;
      await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
      const issuedAt = now(), grantExpiresAt = issuedAt + 365 * 24 * 60 * 60, offlineExpiresAt = issuedAt + 7 * 24 * 60 * 60;
      const offlineLease = await signed({ schema: 1, audience: "moodtools-private-module-lease", leaseVersion: 1, accessVersion: 4, proofVersion: 1, grantId: random(18), scope, deviceId, recoveryId: device.recoveryId || deviceId, flavor: device.flavor || x.flavor || "root", proofKeyId, issuedAt, expiresAt: offlineExpiresAt, grantExpiresAt }, env.LEASE_SIGNING_PRIVATE_KEY, { keyId: "launcher-lease-rsa-2026-01" });
      device.digitalKey = digitalKey;
      device.flavor = device.flavor || x.flavor || "root";
      device.recoveryBound = device.recoveryBound ?? true;
      await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
      return json({ ok: true, approved: true, offlineLease });
    }
    if (method === "POST" && p === "/api/launcher/private-catalog") {
      const x = await body(req);
      const list = await env.STATE.list({ prefix: "catalog:private:" });
      const payloads = [];
      for (const entry of list.keys) {
        const v = await env.STATE.get(entry.name, "json");
        if (v && v.scope) payloads.push(v);
      }
      if (strict) {
        const device = await deviceByDigitalKey(env, String(x.digitalKey || ""));
        if (!device) return fail("Invalid proof signature", 401);
      }
      const capability = random(64), expiresAt = now() + 600;
      await env.STATE.put(`cap:${capability}`, JSON.stringify({ private: true, expiresAt }), { expirationTtl: 600 });
      return json({ ok: true, catalogs: await Promise.all(payloads.map((payload) => signed(payload, env.UPDATE_SIGNING_PRIVATE_KEY))), capability, expiresAt });
    }
    if (method === "POST" && p === "/api/launcher/recovery/bind") {
      const x = await body(req);
      const deviceId = part(x.deviceId, "deviceId");
      let device = await read(env, `device:${deviceId}`, null);
      if (!device) return fail("Device is not registered", 404);
      device.recoveryBound = true;
      device.recoveryId = part(x.recoveryId || device.recoveryId || deviceId, "recoveryId");
      await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
      return json({ ok: true, recoveryBound: true, proofKeyId: device.proofKeyId });
    }
    if (method === "POST" && p === "/api/launcher/proof/attestation/challenge") {
      const x = await body(req);
      const keyId = part(x.keyId || x.proofKeyId || "dev-proof-key", "keyId");
      return json({ ok: true, registered: true, accepted: true, proofVersion: 1, keyId, expiresAt: now() + 300 });
    }
    if (method === "POST" && p === "/api/launcher/proof/attest") {
      const x = await body(req);
      const deviceId = part(x.deviceId, "deviceId");
      const device = await read(env, `device:${deviceId}`, null);
      const chainHash = x.attestation?.chainHash ? part(x.attestation.chainHash, "chainHash") : random(32);
      const proofKeyId = x.proof?.keyId || device?.proofKeyId || random(32);
      return json({ ok: true, registered: true, accepted: true, attestationVersion: 1, proofKeyId, chainHash: x.attestation?.chainHash || chainHash });
    }
    if (method === "POST" && p === "/api/launcher/redeem") {
      const x = await body(req);
      const token = part(x.token, "token");
      const pending = await env.STATE.get(`unlock:${token}`, "json");
      if (!pending || pending.used || pending.expiresAt <= now()) return fail("The unlock token is invalid or expired", 403);
      if (x.challenge !== pending.challenge) return fail("The unlock challenge does not match", 403);
      const deviceId = part(x.deviceId, "deviceId");
      const publicKey = part(x.publicKey, "publicKey");
      const keyId = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64url(publicKey))));
      if (x.proofKeyId !== keyId) return fail("Proof key identifier mismatch", 400);
      if (strict) {
        const canonical = ["moodtools-recovery-bind-v1", `nonce=${token}`, `installationId=${part(x.installationId || deviceId, "installationId")}`, `deviceId=${deviceId}`, `recoveryId=${part(x.recoveryId || deviceId, "recoveryId")}`, `flavor=${part(x.flavor, "flavor")}`, `accessVersion=${Number(x.accessVersion || 4)}`, `keyId=${keyId}`].join("\n");
        if (!await verifyEcdsa(publicKey, canonical, x.proof?.signature || "")) return fail("Invalid proof signature", 401);
      }
      const digitalKey = random(72);
      const device = await read(env, `device:${deviceId}`, null) || { deviceId };
      device.digitalKey = digitalKey;
      device.installationId = part(x.installationId || deviceId, "installationId");
      device.recoveryId = part(x.recoveryId || deviceId, "recoveryId");
      device.flavor = part(x.flavor, "flavor");
      device.proofKeyId = keyId;
      device.proofPublicKey = publicKey;
      device.recoveryBound = true;
      await env.STATE.put(`device:${deviceId}`, JSON.stringify(device));
      pending.used = true;
      await env.STATE.put(`unlock:${token}`, JSON.stringify(pending));
      const issuedAt = now(), expiresAt = issuedAt + 604800;
      const offlineLease = await signed({ schema: 1, audience: "moodtools-launcher-offline-lease", leaseVersion: 1, accessVersion: 4, proofVersion: 1, grantId: random(18), deviceId, flavor: device.flavor, proofKeyId: keyId, digitalKeySha256: await sha256(digitalKey), issuedAt, expiresAt }, env.LEASE_SIGNING_PRIVATE_KEY, { keyId: "launcher-lease-rsa-2026-01" });
      return json({ ok: true, digitalKey, issuedAt, expiresAt, recoveryBound: true, proofKeyId: keyId, offlineLease });
    }
    if (p === "/launcher/unlock") {
      if (method === "GET") return html(unlockPage(Object.fromEntries(params)));
      if (method === "POST") {
        const submitted = await formOrJson(req, params);
        const challenge = part(submitted.challenge || params.get("challenge") || "", "challenge");
        const deviceId = part(submitted.device || submitted.deviceId || params.get("device") || "", "deviceId");
        const installationId = part(submitted.installation || submitted.installationId || params.get("installation") || deviceId, "installationId");
        const token = random(32);
        await env.STATE.put(`unlock:${token}`, JSON.stringify({ token, challenge, deviceId, installationId, expiresAt: now() + 20 * 60, used: false }), { expirationTtl: 1200 });
        const target = `moodtools-launcher://unlock?token=${encodeURIComponent(token)}&challenge=${encodeURIComponent(challenge)}`;
        return html(redirectHtml(target));
      }
      return fail("Method not allowed", 405);
    }
    if (method === "POST" && p === "/admin/catalog") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      if (x.schema !== 1 || x.audience !== "moodtools-standalone" || !Array.isArray(x.modules)) throw Error("Invalid catalog schema");
      await env.STATE.put("catalog:public", JSON.stringify(x));
      return json({ ok: true });
    }
    if (method === "POST" && p === "/admin/module") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      const slug = part(x.slug, "slug"), build = String(Number(x.build)), abi = part(x.abi, "abi");
      if (!x.manifest || !x.dexBase64 || !x.nativeBase64 || Number(x.build) < 1) throw Error("manifest, dexBase64, and nativeBase64 are required");
      const dexBytes = Uint8Array.from(atob(x.dexBase64), (c) => c.charCodeAt(0));
      const nativeBytes = Uint8Array.from(atob(x.nativeBase64), (c) => c.charCodeAt(0));
      const manifest = {
        ...x.manifest,
        packageName: x.manifest.packageName || slug,
        version: x.manifest.version || build,
        moduleConfig: x.manifest.moduleConfig || { packageName: slug, title: slug, supportedVersions: [], supportedAbis: [abi], dexFile: "classes.dex", nativeFile: "libmenu_native.so", entryPoint: "" },
        files: {
          native: { [abi]: { path: `/api/launcher-module-payload/${slug}/${build}/native/${abi}`, size: nativeBytes.length, sha256: await sha256Hex(nativeBytes) } },
          dex: { path: `/api/launcher-module-payload/${slug}/${build}/dex/classes.dex`, size: dexBytes.length, sha256: await sha256Hex(dexBytes) }
        }
      };
      await env.STATE.put(`module:${slug}:${build}:manifest`, JSON.stringify(manifest));
      await env.STATE.put(`module:${slug}:${build}:dex`, dexBytes);
      await env.STATE.put(`module:${slug}:${build}:native:${abi}`, nativeBytes);
      return json({ ok: true }, 201);
    }
    if (method === "POST" && p === "/admin/module-meta") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      const slug = part(x.slug, "slug"), build = String(Number(x.build));
      if (Number(x.build) < 1) throw Error("Invalid module build");
      if (x.changelog && typeof x.changelog === "object") await env.STATE.put(`module:${slug}:${build}:changelog`, JSON.stringify(x.changelog));
      if (x.features && typeof x.features === "object") await env.STATE.put(`module:${slug}:${build}:features`, JSON.stringify(x.features));
      if (x.iconBase64) await env.STATE.put(`module:${slug}:${build}:icon`, Uint8Array.from(atob(x.iconBase64), (c) => c.charCodeAt(0)));
      return json({ ok: true });
    }
    if (method === "POST" && p === "/admin/upload") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      const relative = typeof x.path === "string" ? x.path : "";
      const bytes = Uint8Array.from(atob(typeof x.base64 === "string" ? x.base64 : ""), (c) => c.charCodeAt(0));
      if (!relative || relative.includes("..") || !bytes.length) throw Error("Invalid upload");
      let apkM = relative.match(apkUploadRe), gameM = relative.match(gameUploadRe), moduleM = relative.match(moduleFileRe);
      let key2 = null;
      if (apkM) key2 = `release:apk:${apkM[1]}:${apkM[2]}`;
      else if (gameM) key2 = `game:${gameM[1]}:${gameM[2]}`;
      else if (moduleM) {
        if (moduleM[4]) key2 = `module:${moduleM[1]}:${moduleM[2]}:native:${moduleM[4]}`;
        else if (moduleM[3] === "classes.dex") key2 = `module:${moduleM[1]}:${moduleM[2]}:dex`;
        else if (moduleM[3] === "icon.png") key2 = `module:${moduleM[1]}:${moduleM[2]}:icon`;
      }
      if (!key2) throw Error("Unsupported KV upload path");
      await env.STATE.put(key2, bytes);
      return json({ ok: true, sha256: await sha256Hex(bytes), size: bytes.length }, 201);
    }
    if (method === "POST" && p === "/admin/release") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      const kind = x.kind === "test" ? "test" : x.kind === "changelog" ? "changelog" : "stable";
      if (kind === "changelog") {
        if (!Array.isArray(x.entries)) throw Error("Invalid changelog");
        await env.STATE.put("release:changelog", JSON.stringify({ schema: 1, audience: "moodtools-standalone-launcher-changelog", currentBuild: Number(x.currentBuild), entries: x.entries }));
      } else if (kind === "test") {
        const flavor = part(x.flavor, "flavor");
        await env.STATE.put(`release:test:${flavor}`, JSON.stringify({ schema: 1, audience: "moodtools-standalone-launcher-test", build: Number(x.build), version: String(x.version), flavor, notes: x.notes || "", file: x.file }));
      } else {
        if (!x.files?.root || !x.files?.nonroot) throw Error("Both flavor files are required");
        await env.STATE.put("release:stable", JSON.stringify({ schema: 1, audience: "moodtools-standalone-launcher", build: Number(x.build), version: String(x.version), notes: x.notes || "", files: x.files }));
      }
      return json({ ok: true });
    }
    if (method === "POST" && p === "/admin/play-store") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      if (!x.versions || typeof x.versions !== "object") throw Error("Invalid play store map");
      await env.STATE.put("state:play-store", JSON.stringify(x.versions));
      return json({ ok: true });
    }
    if (method === "POST" && p === "/admin/mod-update") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      if (!x.channel || typeof x.channel !== "object") throw Error("Invalid module update channel");
      await env.STATE.put("state:mod-update", JSON.stringify(x.channel));
      return json({ ok: true });
    }
    if (method === "POST" && p === "/admin/private-catalog") {
      if (!authorized(req, env)) return fail("Admin authorization required", 401);
      const x = await body(req);
      const scope = part(x.scope, "scope");
      if (x.catalog?.schema !== 1 || x.catalog?.audience !== "moodtools-standalone-private") throw Error("Invalid private catalog");
      await env.STATE.put(`catalog:private:${scope}`, JSON.stringify({ ...x.catalog, scope }));
      return json({ ok: true });
    }
    return fail("Not found", 404);
  } catch (e) {
    return fail(e.message || "Invalid request");
  }
} };
export {
  index_kv_default as default
};
//# sourceMappingURL=index-kv.js.map
