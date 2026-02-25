# Site

Next.js application with API routes and VM integration.

## APIs

### POST /api/entropy

Validates client fingerprint and behaviour.

**Request:** `{ fingerprint, entropyHex, timestamp, behaviour, extraSeed? }`

**Response:** `{ ok, flags, score, reasons? }`

- `ok` — true if score < 0.7
- `flags` — rateLimitExceeded, syntheticTimestamps, automationPattern, fingerprintAnomaly, score
- `reasons` — Mismatch reasons when fingerprint anomaly

### GET /api/challenge

Returns a new challenge.

**Response:** `{ encryptedWasm, key, operations, input, token }`

- `encryptedWasm` — Base64 of iv ‖ ciphertext ‖ tag (ChaCha20-Poly1305)
- `key` — Base64 decryption key
- `operations` — `[{ op, params }]`; op = opcode byte
- `input` — Base64 4-byte input
- `token` — JWT for verification

### POST /api/challenge/verify

Verifies the solved integer.

**Request:** `{ token, solved }`

**Response:** `{ ok }` or `{ ok: false, error }`

Token is verified; expected value is fetched from Redis and compared. Challenge is consumed (getAndDel).

## Configuration

| Env var | Purpose |
|---------|---------|
| CHALLENGE_VERIFY_SECRET | JWT signing key (min 32 chars) |
| REDIS_URL | Redis connection (default: redis://localhost:6379) |

## Data layout

- `site/data/` — `crypto_utils.wasm`, `bytecodes.json` (copied from compiler build)
- Used at runtime by challenge route (read file) and verify (bytecodes for run)

## VM integration

- **loadVmFromChallenge()** — Decrypts WASM with key, instantiates, sets up chacha_poly_decrypt import
- **vmRunWithOperations()** — Applies each op with params as key
- **readU32LE()** — Reads solved integer from buffer
