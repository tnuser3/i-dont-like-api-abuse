import { randomBytes } from "node:crypto";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { set, get } from "./redis";
import { toBase64 } from "./encoding";
import {
  deriveKeyFromId,
  IV_LEN,
  TAG_LEN,
  X25519_PUBLIC_KEY_LEN,
  fromBase64,
} from "./key-session";

const SESSION_TTL_SEC = 5 * 60;

export interface SessionData {
  privateKey: Uint8Array;
  signingKey: string;
  token: string;
}

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
  } satisfies Record<string, string>, { exSeconds: SESSION_TTL_SEC });
  await set(`fp:sign:${id}`, signingKey.toString("base64"), { exSeconds: SESSION_TTL_SEC });

  const payload = {
    publicKey: toBase64(keypair.publicKey),
    signingKey: signingKey.toString("base64"),
    token,
  };
  const sessionKey = deriveKeyFromId(id);
  const encryptedPublicKey = encryptPayload(sessionKey, payload);

  return { id, encryptedPublicKey };
}

function encryptPayload(sessionKey: Uint8Array, data: Record<string, string>): string {
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const iv = randomBytes(IV_LEN);
  const chacha = chacha20poly1305(sessionKey, iv);
  const combined = chacha.encrypt(plaintext);

  const packed = new Uint8Array(IV_LEN + combined.length);
  packed.set(iv, 0);
  packed.set(combined, IV_LEN);

  return toBase64(packed);
}

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
  if (
    packed.length <
    IV_LEN + X25519_PUBLIC_KEY_LEN + TAG_LEN
  ) {
    throw new Error("Invalid encrypted body: too short");
  }
  const iv = packed.subarray(0, IV_LEN);
  const ephemeralPublicKey = packed.subarray(IV_LEN, IV_LEN + X25519_PUBLIC_KEY_LEN);
  const combined = packed.subarray(IV_LEN + X25519_PUBLIC_KEY_LEN);

  const shared = x25519.getSharedSecret(privateKey, ephemeralPublicKey);
  const chacha = chacha20poly1305(shared, iv);
  const plaintext = chacha.decrypt(combined);

  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as unknown;
}

export async function getSession(id: string): Promise<SessionData | null> {
  const raw = await get<Record<string, string>>(`session:${id}`);
  if (!raw?.privateKey || !raw.signingKey || !raw.token) return null;
  return {
    privateKey: fromBase64(raw.privateKey),
    signingKey: raw.signingKey,
    token: raw.token,
  };
}

export async function createEncryptionSession(): Promise<{
  id: string;
  sessionKey: Uint8Array;
}> {
  const id = randomBytes(16).toString("hex");
  const sessionKey = deriveKeyFromId(id);
  return { id, sessionKey };
}

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
