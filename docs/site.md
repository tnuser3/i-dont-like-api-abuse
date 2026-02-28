# Site

Next.js application with API routes, risk assessment, and VM-based challenges.

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | /api/challenge | Obtain encryption credentials (id, encryptedPublicKey) |
| POST | /api/challenge | Submit entropy + fingerprint; receive encrypted challenge |
| POST | /api/challenge/verify | Submit solved integer; verify and consume challenge |
| GET | /api/manager/requests | List recent API requests (paginated) |
| GET | /api/manager/fingerprints | List stored device fingerprints |

See [api-endpoints.md](./api-endpoints.md) for request/response formats, flow descriptions, and error handling.

## Client Flow

1. **GET /api/challenge** — Receives `{ id, encryptedPublicKey }`.
2. Derive session key from `id`; decrypt `encryptedPublicKey` to get public key, signing key, token.
3. **POST /api/challenge** — Encrypt body with public key. Body includes entropy (fingerprint, behaviour) and FingerprintJS payload (signed). Receives `{ id, credential }`.
4. Decrypt credential to get `encryptedWasm`, `key`, `operations`, `input`, `token`.
5. Decrypt WASM, load VM, run operations on input, read uint32 at offset 0.
6. **POST /api/challenge/verify** — Encrypted body `{ token, solved }`. Receives `{ ok }`.

## Configuration

| Env var | Purpose |
|---------|---------|
| CHALLENGE_VERIFY_SECRET | JWT signing key (min 32 chars) |
| REDIS_URL | Redis connection (default: redis://localhost:6379) |
| RISK_DEBUG | Set to 1 for risk assessor debug logs |

## Data Layout

- `data/crypto_utils.wasm` — VM WASM module
- `data/bytecodes.json` — Opcode mapping and VM state (from compiler build)
- `data/asn-base-scores.json` — ASN base risk scores (JSON object)

## VM Integration

- `loadVmFromChallenge()` — Decrypt WASM, instantiate, configure imports
- `vmRunWithOperations()` — Execute operations with params as key
- `readU32LE()` — Read solved integer from output buffer
