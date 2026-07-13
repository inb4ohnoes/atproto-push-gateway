# Aery deployment

This profile runs separate production and development gateways on the same VPS.
The split is required because one gateway process has one APNs endpoint and topic.

## Hostnames

| Environment | Service DID | Origin |
| --- | --- | --- |
| Production | `did:web:bsky-push.getaery.app` | `127.0.0.1:18081` |
| Development | `did:web:bsky-push-dev.getaery.app` | `127.0.0.1:18082` |

Both public hostnames must use HTTPS and proxy to the matching loopback origin.
Do not expose either container port directly to the internet.

## Required secrets

- Apple Push Services `.p12` certificate at `deployment/aery/secrets/apns.p12`
- a long random origin-verification secret injected by Cloudflare

The certificate and `.env` file are excluded from both Git and the Docker build context.

## Install

1. Copy `.env.example` to `.env` and replace every placeholder.
2. Create `secrets/apns.p12` with mode `0600`. Set `APNS_P12_PASSWORD`
   directly in the Compose environment if a future certificate has a password.
3. Authenticate the VPS to the private or public container registry as needed.
4. Pull the immutable image and start both services:

   ```sh
   docker compose -p aery-atproto-push --env-file .env -f compose.yaml pull
   docker compose -p aery-atproto-push --env-file .env -f compose.yaml up -d
   ```

   On Ubuntu 20.04 hosts with standalone Compose, replace `docker compose`
   with `docker-compose`. Compose 1.25 does not support `--env-file`, so export
   the variables from `.env` before running it.

5. Configure the reverse proxy and Cloudflare before attempting registration.
6. Verify both health endpoints locally and through their public hostnames.

## Cloudflare contract

Cloudflare must add `X-Origin-Verify` with the configured secret to origin requests.
Do not cache, challenge, or transform `/xrpc/*` or `/.well-known/did.json`.
Use Full (strict) TLS and prevent direct origin access where possible.

The health endpoint intentionally bypasses origin verification so local Docker and
VPS monitoring can use it. Keep the public health response free of secrets.

## Operations

- Pin `AERY_PUSH_IMAGE` to an immutable release or digest.
- Back up each SQLite volume with a SQLite-safe snapshot method.
- Monitor the health response, Jetstream cursor age, drops, push errors, disk,
  memory, container restarts, and backup completion.
- Validate development delivery before registering a production device.
- Keep the existing Mastodon relay on its current ports and network.

The production-scale reliability requirements and rollout checklist are tracked in
[Aery issue #103](https://github.com/inb4ohnoes/aery/issues/103).
