"use client";

import type { FingerprintPayload } from "./fingerprint";
import type { ChallengeResponse } from "@/lib/vm-inject";

let cachedVisitorId: string | null = null;
let cachedSession: { id: string; publicKey: Uint8Array } | null = null;

export function getVisitorHeaders(): Record<string, string> {
  return cachedVisitorId ? { "X-Visitor-ID": cachedVisitorId } : {};
}

export async function collectFingerprint(): Promise<FingerprintPayload | null> {
  if (typeof window === "undefined") return null;
  try {
    const FingerprintJS = await import("@fingerprintjs/fingerprintjs");
    const fp = await FingerprintJS.load({ monitoring: false });
    const result = await fp.get();
    const components = result.components as FingerprintPayload["components"];
    cachedVisitorId = result.visitorId;
    return {
      visitorId: result.visitorId,
      components,
      confidence: result.confidence,
      version: result.version,
    };
  } catch (err) {
    console.error("Fingerprint collection failed:", err);
    return null;
  }
}

async function signPayload(
  signingKeyBase64: string,
  message: string
): Promise<string> {
  const keyBytes = Uint8Array.from(
    atob(signingKeyBase64),
    (c) => c.charCodeAt(0)
  );
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const msgBytes = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

export async function requestChallenge(baseUrl = ""): Promise<ChallengeResponse> {
  const credRes = await fetch(`${baseUrl}/api/challenge`, {
    headers: getVisitorHeaders(),
  });
  if (!credRes.ok) throw new Error(`Challenge credentials failed: ${credRes.status}`);
  const credentials = (await credRes.json()) as { id: string; encryptedPublicKey: string };

  const { deriveKeyFromId, decryptPayload, encryptRequestBody } = await import("@/lib/key-session");
  const sessionKey = deriveKeyFromId(credentials.id);
  const decrypted = decryptPayload<{
    publicKey: string;
    signingKey: string;
    token: string;
  }>(sessionKey, credentials.encryptedPublicKey);

  const publicKey = Uint8Array.from(atob(decrypted.publicKey), (c) => c.charCodeAt(0));
  const signingKey = decrypted.signingKey;
  const token = decrypted.token;
  if (!signingKey || !token) throw new Error("Invalid credential: missing signingKey or token");

  cachedSession = { id: credentials.id, publicKey };

  const fingerprintPayload = await collectFingerprint();
  if (!fingerprintPayload) throw new Error("Fingerprint collection failed");

  const timestamp = Date.now();
  const message = JSON.stringify(fingerprintPayload) + "|" + String(timestamp);
  const signature = await signPayload(signingKey, message);

  const { createEntropyPayload, toHex } = await import("@/lib/entropy");
  const entropyPayload = createEntropyPayload();

  const body = {
    entropy: {
      fingerprint: entropyPayload.fingerprint,
      entropyHex: toHex(entropyPayload.entropy),
      timestamp: entropyPayload.timestamp,
      behaviour: entropyPayload.behaviour,
    },
    fingerprint: {
      payload: fingerprintPayload,
      timestamp,
      signature,
      token,
    },
  };

  const encryptedBody = encryptRequestBody(publicKey, body);

  const res = await fetch(`${baseUrl}/api/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Visitor-ID": fingerprintPayload.visitorId,
    },
    body: JSON.stringify({ id: credentials.id, body: encryptedBody }),
  });

  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `Challenge failed: ${res.status}`);
  }

  const data = (await res.json()) as
    | ChallengeResponse
    | { id: string; credential: string };

  if ("credential" in data) {
    const { deriveKeyFromId, decryptPayload } = await import("@/lib/key-session");
    const sessionKey = deriveKeyFromId(data.id);
    return decryptPayload<ChallengeResponse>(sessionKey, data.credential);
  }

  return data as ChallengeResponse;
}

export async function encryptedPost(
  url: string,
  body: unknown,
  headers?: Record<string, string>
): Promise<Response> {
  if (!cachedSession) throw new Error("Call requestChallenge first");
  const { encryptRequestBody } = await import("@/lib/key-session");
  const encryptedBody = encryptRequestBody(cachedSession.publicKey, body);
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...getVisitorHeaders(),
      ...headers,
    },
    body: JSON.stringify({ id: cachedSession.id, body: encryptedBody }),
  });
}

