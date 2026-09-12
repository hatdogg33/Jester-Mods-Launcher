# voidmod1 Cloudflare Worker

This Worker is the Cloudflare deployment target for the self-hosted launcher
fork. It requires a KV namespace named `voidmod1-state`, an R2 bucket named
`voidmod1-artifacts`, and two secrets containing PKCS#8 RSA private-key PEM:

```sh
npx wrangler kv namespace create voidmod1-state
npx wrangler r2 bucket create voidmod1-artifacts
npx wrangler secret put UPDATE_SIGNING_PRIVATE_KEY
npx wrangler secret put LEASE_SIGNING_PRIVATE_KEY
npx wrangler deploy
```

Do not deploy until the `STATE` namespace ID in `wrangler.toml` has been
replaced. Use a newly rotated `CF_API_TOKEN` through the environment; never put
it in this repository or chat.

The Worker is intentionally development-only until proof-signature and Android
Keystore attestation validation are enabled server-side.
