# Self-hosted launcher backend

This is a dependency-free Node 18+ backend for a **fork you control**. It owns
catalog signing, offline access leases, module manifests, capability-gated
payload delivery, and a bearer-token-protected administrative API. It does not
contain the original operator's signing keys, data, game modules, or backend.

## Important boundaries

- This server is for your own authorized applications and modules.
- It starts in `DEVELOPMENT_MODE=true`: it checks request shape and capability
  scope but does not independently verify Android Keystore proof signatures or
  attestation chains. Do not expose it publicly in that mode.
- The Android client will only trust responses signed by public keys compiled
  into that client. Generate new keys and make a new fork build; an official APK
  cannot be redirected to or made to trust this server.
- Place it behind a TLS reverse proxy. Android clients in this repository reject
  cleartext HTTP and enforce the configured host allowlist.

## Start

```sh
cd backend
cp .env.example .env
npm run keys
# export the values in .env into your shell, then:
npm start
```

Node intentionally does not load `.env` files automatically. In PowerShell:

```powershell
$env:HOST='127.0.0.1'
$env:PORT='8787'
$env:DATA_DIR='./data'
$env:ADMIN_TOKEN='<long random value>'
$env:DEVELOPMENT_MODE='true'
$env:UPDATE_SIGNING_PRIVATE_KEY='./keys/update-private.pem'
$env:LEASE_SIGNING_PRIVATE_KEY='./keys/lease-private.pem'
npm start
```

`npm run keys` emits two public DER Base64 files. Replace the fork's update and
access-lease public-key BuildConfig values with those contents, then replace all
`jester.moodtools.workers.dev` base URLs and host checks with your TLS hostname.
Build a new debug APK afterward.

## APIs

Public endpoints: `GET /health`, `GET /api/launcher-modules`, access recovery,
access refresh, proof challenge/registration, module authorization, and scoped
module payload routes. Responses which the launcher verifies are signed as:

```json
{"algorithm":"SHA256withRSA","payload":"base64","signature":"base64"}
```

Admin endpoints require `Authorization: Bearer $ADMIN_TOKEN`:

- `POST /admin/catalog` — save a public catalog payload (not an envelope).
- `POST /admin/module` — upload one module build as JSON with `slug`, `build`,
  `abi`, `manifest`, `dexBase64`, and `nativeBase64`.

The supplied manifest must match the launcher's strict module schema. Use
`ModuleIntegrityVerifier.kt` as the authoritative contract; it must include
signed module configuration and SHA-256/size entries for both payloads.

## Production hardening

Before deployment, implement verification of the Android Keystore ECDSA proof
canonical messages, replay-safe nonce persistence, recovery binding, Android
attestation certificate chain/extension validation, storage/database backups,
rate limits, audit logs, TLS, key rotation, and an authenticated admin UI/API.
Set `DEVELOPMENT_MODE=false`; the module-authorization route intentionally
refuses service until proof verification is supplied.
