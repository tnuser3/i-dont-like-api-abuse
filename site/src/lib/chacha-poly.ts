/**
 * ChaCha20-Poly1305 AEAD encryption utilities
 * Uses Node.js built-in crypto (server-side only)
 */

import { randomBytes } from "node:crypto";

export const CHACHA_KEY_LENGTH = 32; // 256 bits
export const CHACHA_IV_LENGTH = 12; // 96 bits (IETF variant)
export const CHACHA_AUTH_TAG_LENGTH = 16; // 128 bits

/** Encrypt plaintext with ChaCha20-Poly1305; returns ciphertext || authTag */
export async function chachaEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
  iv?: Uint8Array
): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array; iv: Uint8Array }> {
  const { createCipheriv } = await import("node:crypto");
  if (key.length !== CHACHA_KEY_LENGTH) throw new Error(`Key must be ${CHACHA_KEY_LENGTH} bytes`);
  const nonce = iv ?? randomBytes(CHACHA_IV_LENGTH);
  const cipher = createCipheriv("chacha20-poly1305", Buffer.from(key), Buffer.from(nonce), {
    authTagLength: CHACHA_AUTH_TAG_LENGTH,
  });
  if (aad && aad.length > 0)
    cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext)),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: new Uint8Array(ciphertext),
    authTag: new Uint8Array(authTag),
    iv: new Uint8Array(nonce),
  };
}

/** Decrypt ciphertext with ChaCha20-Poly1305 */
export async function chachaDecrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const { createDecipheriv } = await import("node:crypto");
  if (key.length !== CHACHA_KEY_LENGTH) throw new Error(`Key must be ${CHACHA_KEY_LENGTH} bytes`);
  if (iv.length !== CHACHA_IV_LENGTH) throw new Error(`IV must be ${CHACHA_IV_LENGTH} bytes`);
  if (authTag.length !== CHACHA_AUTH_TAG_LENGTH)
    throw new Error(`Auth tag must be ${CHACHA_AUTH_TAG_LENGTH} bytes`);
  const decipher = createDecipheriv(
    "chacha20-poly1305",
    Buffer.from(key),
    Buffer.from(iv),
    { authTagLength: CHACHA_AUTH_TAG_LENGTH }
  );
  decipher.setAuthTag(Buffer.from(authTag));
  if (aad && aad.length > 0)
    decipher.setAAD(Buffer.from(aad), { plaintextLength: ciphertext.length });
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertext)),
    decipher.final(),
  ]);
  return new Uint8Array(plaintext);
}

/** Pack encrypted result into single buffer: iv || ciphertext || authTag */
export function packChachaResult(
  ciphertext: Uint8Array,
  authTag: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  const out = new Uint8Array(iv.length + ciphertext.length + authTag.length);
  out.set(iv, 0);
  out.set(ciphertext, iv.length);
  out.set(authTag, iv.length + ciphertext.length);
  return out;
}

/** Unpack single buffer into iv, ciphertext, authTag */
export function unpackChachaResult(
  packed: Uint8Array
): { iv: Uint8Array; ciphertext: Uint8Array; authTag: Uint8Array } {
  if (packed.length < CHACHA_IV_LENGTH + CHACHA_AUTH_TAG_LENGTH)
    throw new Error("Packed buffer too short");
  const iv = packed.subarray(0, CHACHA_IV_LENGTH);
  const authTag = packed.subarray(packed.length - CHACHA_AUTH_TAG_LENGTH);
  const ciphertext = packed.subarray(CHACHA_IV_LENGTH, packed.length - CHACHA_AUTH_TAG_LENGTH);
  return { iv, ciphertext, authTag };
}

/** One-shot encrypt: returns packed iv || ciphertext || authTag */
export async function chachaEncryptPacked(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const { ciphertext, authTag, iv } = await chachaEncrypt(key, plaintext, aad);
  return packChachaResult(ciphertext, authTag, iv);
}

/** One-shot decrypt from packed buffer */
export async function chachaDecryptPacked(
  key: Uint8Array,
  packed: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const { iv, ciphertext, authTag } = unpackChachaResult(packed);
  return chachaDecrypt(key, ciphertext, authTag, iv, aad);
}
