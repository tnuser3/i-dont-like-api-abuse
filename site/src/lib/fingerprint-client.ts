"use client";

import type { FingerprintPayload, FingerprintResponse } from "./fingerprint";

export async function collectFingerprint(): Promise<FingerprintPayload | null> {
  if (typeof window === "undefined") return null;
  try {
    const FingerprintJS = await import("@fingerprintjs/fingerprintjs");
    const fp = await FingerprintJS.load({ monitoring: false });
    const result = await fp.get();
    const components = result.components as FingerprintPayload["components"];
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

export async function submitFingerprint(
  token: string,
  signingKey: string,
  baseUrl = ""
): Promise<FingerprintResponse | null> {
  const payload = await collectFingerprint();
  if (!payload) return null;

  const timestamp = Date.now();
  const message = JSON.stringify(payload) + "|" + String(timestamp);
  const signature = await signPayload(signingKey, message);

  const res = await fetch(`${baseUrl}/api/fingerprint`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      payload,
      timestamp,
      signature,
      token,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(
      (err as { error?: string }).error ?? "Fingerprint submit failed"
    );
  }

  return res.json() as Promise<FingerprintResponse>;
}
