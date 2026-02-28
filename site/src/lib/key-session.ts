import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";

const HKDF_INFO = new TextEncoder().encode("challenge-id-key");
const IV_LEN = 12;
const TAG_LEN = 16;
const X25519_PUBLIC_KEY_LEN = 32;

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export function deriveKeyFromId(id: string): Uint8Array {
  const ikm = new TextEncoder().encode(id);
  return hkdf(sha256, ikm, undefined, HKDF_INFO, 32);
}

export function decryptPayload<T>(sessionKey: Uint8Array, credentialBase64: string): T {
  const packed = fromBase64(credentialBase64);
  if (packed.length < IV_LEN + TAG_LEN) {
    throw new Error("Invalid credential: too short");
  }
  const iv = packed.subarray(0, IV_LEN);
  const combined = packed.subarray(IV_LEN);

  const chacha = chacha20poly1305(sessionKey, iv);
  const plaintext = chacha.decrypt(combined);

  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as T;
}

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

export function decryptCredential(
  sessionKey: Uint8Array,
  credentialBase64: string
): Record<string, string> {
  return decryptPayload(sessionKey, credentialBase64) as Record<string, string>;
}

export { IV_LEN, TAG_LEN, X25519_PUBLIC_KEY_LEN };
export { fromBase64, toBase64 };
