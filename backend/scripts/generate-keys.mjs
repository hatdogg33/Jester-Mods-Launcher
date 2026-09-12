import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const directory = resolve(process.argv[2] || 'keys');
mkdirSync(directory, { recursive: true, mode: 0o700 });

function generate(name) {
  const privatePath = resolve(directory, `${name}-private.pem`);
  const publicPath = resolve(directory, `${name}-public.der.base64`);
  if (existsSync(privatePath) || existsSync(publicPath)) {
    throw new Error(`${name} key already exists in ${directory}; refusing to overwrite it.`);
  }
  const pair = generateKeyPairSync('rsa', { modulusLength: 3072 });
  writeFileSync(privatePath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  writeFileSync(publicPath, pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') + '\n', { mode: 0o644 });
  console.log(`${name}: ${publicPath}`);
}

generate('update');
generate('lease');
console.log('Copy update-public.der.base64 and lease-public.der.base64 into your forked launcher BuildConfig values.');
