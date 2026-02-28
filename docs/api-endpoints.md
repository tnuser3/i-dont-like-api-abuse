# API Endpoints

All API routes run risk assessment and adaptive rate limiting before handling. Requests can be blocked with `429` (rate limit) or `403` (risk score) before any route logic executes.

---

## GET /api/challenge

**Purpose:** Obtain encryption credentials to start the challenge flow.

**Flow:**
1. `processRequest(request)` — Rate limit check and header risk assessment (UA, origin, referer, sec-ch-ua, via). Returns 429 or 403 if blocked.
2. `logRouteRequest` — Record the request for the manager dashboard.
3. `createPublicKeySession()` — Generate a new key-session pair (id + ephemeral public key). Used for ECDH to derive a shared secret for request/response encryption.
4. Respond with `{ id, encryptedPublicKey }` — The client uses `id` to derive the session key and `encryptedPublicKey` to get the public key for encrypting the challenge POST body.

**Response:** `200` `{ id: string, encryptedPublicKey: string }`

**Errors:** `429` rate limited, `403` blocked by risk, `500` server error

---

## POST /api/challenge

**Purpose:** Submit entropy + fingerprint, receive encrypted challenge (WASM, operations, input, token).

**Request body (outer):** `{ id: string, body: string }` — `id` is the session id from GET; `body` is ChaCha20-Poly1305 encrypted JSON.

**Decrypted body:**
```json
{
  "entropy": {
    "fingerprint": { /* ClientFingerprint */ },
    "entropyHex": "...",
    "timestamp": number,
    "behaviour": { "events": [...], "flags": {...} }
  },
  "fingerprint": {
    "payload": { /* FingerprintJS payload */ },
    "timestamp": number,
    "signature": string,
    "token": string
  }
}
```

**Flow (in order):**

1. **processRequest** — Same as GET; blocks before any parsing.

2. **Parse envelope** — Require `id` and `body`; decrypt with session key from `id`. On decryption failure → `400`.

3. **Validate entropy** — `validateEntropyPayload(b.entropy)` checks fingerprint shape, entropyHex format, timestamp, behaviour events and flags. Missing/invalid → `400`.

4. **Validate fingerprint** — `validateFingerprintPayload(b.fingerprint)` checks visitorId, components, timestamp, signature, token. Missing/invalid → `400`.

5. **WebGL + header risk** — Combine WebGL renderer/vendor score with header risk from `processRequest`. If `headerScore + webglScore >= 0.45` → `403 Blocked`.

6. **Verify fingerprint signature** — HMAC-SHA256 over payload + timestamp using challenge token. Invalid → `401`.

7. **Store fingerprint** — Persist device fingerprint for manager/analytics.

8. **Cross-reference entropy** — Compare fingerprint to request headers (UA, screen, timezone, etc.), validate entropyHex and timestamp. Produces `crossScore` and `reasons`.

9. **Analyse behaviour** — Inspect behaviour events for rate patterns, synthetic timestamps, automation signals. Produces `behaviourScore` and flags.

10. **Entropy threshold** — If `crossScore + behaviourScore >= 0.7` → `403 Entropy validation failed`.

11. **Score storage** — Optional: store cumulative entropy score by fingerprint hash for abuse tracking.

12. **Create challenge** — `createFullChallenge()`:
    - Load `crypto_utils.wasm` and `bytecodes.json`
    - Encrypt WASM with ChaCha20-Poly1305; generate random key
    - Build random opcode sequence (layers, shuffled); generate random input bytes
    - Run server-side VM to compute expected uint32 result
    - Store `challenge:{id}` → expected in Redis (5 min TTL)
    - Store `fp:sign:{id}` → signing key for fingerprint verification
    - Sign JWT with challengeId
    - Create encryption session, encrypt the response
    - Return `{ id, credential }` — credential is encrypted `{ encryptedWasm, key, operations, input, token, signingKey }`

**Response:** `200` `{ id: string, credential: string }`

**Errors:** `400` invalid payload/decryption, `401` fingerprint verification failed, `403` blocked or entropy failed, `429` rate limited, `500` server error

---

## POST /api/challenge/verify

**Purpose:** Submit the solved integer; verify against stored expected value and consume the challenge.

**Request body (outer):** `{ id: string, body: string }` — Encrypted; decrypted body must be `{ token: string, solved: number }`.

**Flow:**

1. **processRequest** — Rate limit and risk check.

2. **Parse envelope** — Same pattern as challenge POST; decrypt with session key.

3. **Validate fields** — `token` required (JWT); `solved` required as uint32 (0–4294967295).

4. **Verify JWT** — Extract `challengeId` from token; invalid/expired → `401`.

5. **Fetch expected** — `getAndDel(\`challenge:${challengeId}\`)` — Atomic get + delete. Null → challenge missing or already used → `400`.

6. **Compare** — `solvedNum === expected` → `200 { ok: true }`, else `200 { ok: false }` (no error string to avoid leaking information).

**Response:** `200` `{ ok: boolean, error?: string }`

**Errors:** `400` invalid payload / challenge not found or used, `401` invalid token, `429` rate limited, `403` blocked, `500` server error

---

## GET /api/manager/requests

**Purpose:** List recent API requests for the manager dashboard.

**Flow:**

1. **processRequest** — Same risk/rate-limit gate.

2. **Query params** — `page` (default 1), `limit` (default 50, clamped 10–100).

3. **getRecentRequests** — Redis `lRange` on `manager:requests`; returns paginated entries (path, method, timestamp, userAgent, referer, ip, visitorId).

4. Respond with `{ requests, total, page, limit }`.

**Response:** `200` `{ requests: Array, total: number, page: number, limit: number }`

**Errors:** `429`, `403`, `500`

---

## GET /api/manager/fingerprints

**Purpose:** List stored device fingerprints for the manager dashboard.

**Flow:**

1. **processRequest** — Same risk/rate-limit gate.

2. **scanKeys** — Redis `SCAN` for `fp:dev:*` (max 500 keys).

3. **Load devices** — For each key, `get` the stored device (visitorId from key suffix, lastSeen, etc.).

4. **Sort** — By `lastSeen` descending.

5. Respond with `{ fingerprints: Array }`.

**Response:** `200` `{ fingerprints: Array<StoredDevice & { visitorId }> }`

**Errors:** `429`, `403`, `500`

---

## Risk Assessment (shared by all routes)

Before any route runs, `processRequest(request)`:

1. **extractRiskInput** — IP (x-forwarded-for / x-real-ip), userAgent, origin, referer, sec-ch-ua, via.

2. **enforceRequestRate(ip)** — Tiered rate limit per IP (e.g. 45–75 req/30s initially; stricter after violations). Over limit → record violation, block if strikes ≥ 6. Returns 429 with Retry-After.

3. **assessRequest** — Header scoring (UA bot patterns, origin, referer, sec-ch-ua headless, via proxy chain) + ASN score (base from JSON + dynamic from blocked IP count). Score ≥ 0.45 → 403 Blocked.

4. If allowed, returns `{ blocked: false, input, assessment }`; routes proceed with handler logic.

---

## Data Files

| Path | Purpose |
|------|---------|
| `data/crypto_utils.wasm` | VM implementation; loaded by challenge route, encrypted for client |
| `data/bytecodes.json` | Opcode mapping, vm, vm_inv; used by server to generate ops and compute expected |
| `data/asn-base-scores.json` | ASN → base risk score (0–0.4); multiplied by 0.2 when loaded |

---

## Environment

| Variable | Purpose |
|----------|---------|
| `CHALLENGE_VERIFY_SECRET` | JWT signing secret (min 32 chars) |
| `REDIS_URL` | Redis connection (default: redis://localhost:6379) |
| `RISK_DEBUG` | Set to `1` to enable risk assessor debug logs |
| `DEBUG` | Include `risk` to enable risk assessor debug logs |
