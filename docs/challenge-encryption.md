# Challenge Encryption

Request and response bodies are encrypted using X25519 ECDH key exchange and ChaCha20-Poly1305. The client never sends plaintext; the server never exposes the challenge in cleartext.

## Key Derivation

Session keys are derived from the session `id` using HKDF-SHA256:

```typescript
// key-session.ts
const HKDF_INFO = new TextEncoder().encode("challenge-id-key");

export function deriveKeyFromId(id: string): Uint8Array {
  const ikm = new TextEncoder().encode(id);
  return hkdf(sha256, ikm, undefined, HKDF_INFO, 32);
}
```

`id` is a 32-character hex string (16 random bytes). Same `id` → same 32-byte key.

## GET /api/challenge Flow

1. Server generates `id` (random hex) and an X25519 keypair.
2. Server stores private key and signing key in Redis under `session:{id}` (5 min TTL).
3. Server encrypts `{ publicKey, signingKey, token }` with the derived session key.
4. Client receives `{ id, encryptedPublicKey }`; derives key; decrypts to get the server's public key.

```typescript
// key-session-server.ts
export async function createPublicKeySession(): Promise<{
  id: string;
  encryptedPublicKey: string;
}> {
  const id = randomBytes(16).toString("hex");
  const keypair = x25519.keygen();
  const signingKey = randomBytes(32);
  const token = id;

  await set(`session:${id}`, {
    privateKey: toBase64(keypair.secretKey),
    signingKey: signingKey.toString("base64"),
    token,
  }, { exSeconds: SESSION_TTL_SEC });
  // ...

  const payload = {
    publicKey: toBase64(keypair.publicKey),
    signingKey: signingKey.toString("base64"),
    token,
  };
  const sessionKey = deriveKeyFromId(id);
  const encryptedPublicKey = encryptPayload(sessionKey, payload);

  return { id, encryptedPublicKey };
}
```

## Client → Server Request Encryption

The client encrypts POST bodies using the server's public key:

1. Generate ephemeral X25519 keypair.
2. Compute shared secret: `x25519.getSharedSecret(ephemeral.secretKey, serverPublicKey)`.
3. Encrypt JSON body with ChaCha20-Poly1305 using shared secret and random 12-byte IV.
4. Pack: `IV (12) || ephemeralPublicKey (32) || ciphertext+tag`.

```typescript
// key-session.ts
export function encryptRequestBody(serverPublicKey: Uint8Array, body: unknown): string {
  const ephemeral = x25519.keygen();
  const shared = x25519.getSharedSecret(ephemeral.secretKey, serverPublicKey);
  const plaintext = new TextEncoder().encode(JSON.stringify(body));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const chacha = chacha20poly1305(shared, iv);
  const combined = chacha.encrypt(plaintext);

  const packed = new Uint8Array(IV_LEN + ephemeral.publicKey.length + combined.length);
  packed.set(iv, 0);
  packed.set(ephemeral.publicKey, IV_LEN);
  packed.set(combined, IV_LEN + ephemeral.publicKey.length);

  return toBase64(packed);
}
```

## Server Decryption

The server uses the stored private key to derive the same shared secret:

```typescript
// key-session-server.ts
export async function decryptRequestBody(
  id: string,
  encryptedBodyBase64: string
): Promise<unknown> {
  const sessionRaw = await get<Record<string, string>>(`session:${id}`);
  if (!sessionRaw?.privateKey) {
    throw new Error("Session not found or expired");
  }
  const privateKey = fromBase64(sessionRaw.privateKey);

  const packed = fromBase64(encryptedBodyBase64);
  const iv = packed.subarray(0, IV_LEN);
  const ephemeralPublicKey = packed.subarray(IV_LEN, IV_LEN + X25519_PUBLIC_KEY_LEN);
  const combined = packed.subarray(IV_LEN + X25519_PUBLIC_KEY_LEN);

  const shared = x25519.getSharedSecret(privateKey, ephemeralPublicKey);
  const chacha = chacha20poly1305(shared, iv);
  const plaintext = chacha.decrypt(combined);

  return JSON.parse(new TextDecoder().decode(plaintext));
}
```

## Response Encryption

Challenge responses are encrypted with a new session key (derived from a new random `id`):

```typescript
// key-session-server.ts
export function encryptPayloadForResponse<T>(sessionKey: Uint8Array, data: T): string {
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const iv = randomBytes(IV_LEN);
  const chacha = chacha20poly1305(sessionKey, iv);
  const combined = chacha.encrypt(plaintext);

  const packed = new Uint8Array(IV_LEN + combined.length);
  packed.set(iv, 0);
  packed.set(combined, IV_LEN);

  return toBase64(packed);
}
```

Response format: `IV (12) || ciphertext || tag (16)`. The client derives the session key from `id` and decrypts.

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| IV_LEN | 12 | ChaCha20-Poly1305 nonce |
| TAG_LEN | 16 | Poly1305 auth tag |
| X25519_PUBLIC_KEY_LEN | 32 | Ephemeral public key in packed body |
| SESSION_TTL_SEC | 300 | Session expiry (5 min) |

## Security Properties

- **Forward secrecy (per request)** — Ephemeral client keypair; shared secret differs per POST.
- **Authentication** — ChaCha20-Poly1305 provides authenticated encryption.
- **No long-term shared secret** — Server private key is per-session; client uses server public key only for that session.
