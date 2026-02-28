# Fingerprint (FingerprintJS + Server Verification)

The client uses [FingerprintJS](https://fingerprint.com/open-source/) to collect a fingerprint and components. The server verifies the payload with HMAC-SHA256, links devices by component hashes, and assesses components for suspicious patterns (e.g. Chromium in headless).

## Client Collection

```typescript
// fingerprint-client.ts
export async function collectFingerprint(): Promise<FingerprintPayload | null> {
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
}
```

`visitorId` is a stable identifier; `components` includes keys such as `screenFrame`, `webglVendor`, `webglRenderer`, `audio`, `canvas`, `fonts`, etc.

## FingerprintPayload

```typescript
// fingerprint.ts
export interface FingerprintPayload {
  visitorId: string;
  components: FingerprintComponents;
  confidence?: { score: number };
  version?: string;
}

export interface FingerprintComponent {
  value?: unknown;
  error?: unknown;
  duration?: number;
}
```

## Server Verification (HMAC)

The server stores a signing key per session (from `/api/challenge`). The client signs `payload | timestamp` with HMAC-SHA256 and sends `{ payload, timestamp, signature, token }`:

```typescript
// fingerprint.ts
export async function verifySignedFingerprint(body: {
  payload: unknown;
  timestamp: number;
  signature: string;
  token: string;
}): Promise<FingerprintPayload> {
  const signingKeyB64 = await get<string>(`${FP_PREFIX}:sign:${token}`);
  const message = JSON.stringify(payload) + "|" + String(timestamp);
  const expectedSig = createHmac("sha256", keyBuf).update(message).digest("base64");
  if (!timingSafeEqual(sigBuf, expBuf)) {
    throw new Error("Invalid signed fingerprint: signature mismatch");
  }
  // ...
}
```

`token` ties the fingerprint to the challenge session; signing key is fetched from Redis.

## Device Linking

Components are hashed per key to link the same device across sessions:

```typescript
// fingerprint.ts
function hashComponent(key: string, comp: FingerprintComponent): string | null {
  const str = `${key}:${JSON.stringify(val)}`;
  return crc32(new TextEncoder().encode(str)).toString(36);
}

function extractComponentHashes(components: FingerprintComponents): string[] {
  const hashes: string[] = [];
  for (const [key, comp] of Object.entries(components)) {
    const h = hashComponent(key, comp);
    if (h) hashes.push(`${key}:${h}`);
  }
  return hashes;
}
```

`findMatchingDevice` scores devices by overlapping component hashes. If score ≥ `MIN_COMPONENT_OVERLAP` (3), the device is linked to that record.

## storeFingerprint

```typescript
// fingerprint.ts
export async function storeFingerprint(payload: FingerprintPayload): Promise<FingerprintResponse> {
  const componentHashes = extractComponentHashes(components);
  const matchedDeviceId = await findMatchingDevice(componentHashes);
  const deviceId = matchedDeviceId ?? randomUUID();
  const linked = !!matchedDeviceId;

  const record: StoredDevice = {
    deviceId,
    visitorIds: [visitorId],
    components,
    componentHashes,
    firstSeen: now,
    lastSeen: now,
  };

  for (const ch of componentHashes) {
    await sAdd(`${COMP_PREFIX}:${ch}`, deviceId);
  }
  return { deviceId, linked, firstVisit: !linked };
}
```

## Component Assessment (Risk Scorer)

The challenge route runs `assessFingerprintComponents` and `assessWebGLRenderer`:

```typescript
// request-risk-assessor.ts
export function assessFingerprintComponents(
  components: Record<string, { value?: unknown; error?: unknown; duration?: number }>,
  webglVendor: string | null | undefined
): { score: number; reasons: string[] } {
  let screenFrameAllZeros = false;
  const screenFrameComp = components["screenFrame"];
  if (screenFrameComp?.value !== undefined) {
    const v = screenFrameComp.value;
    // Parse "[0,0,0,0]" or array
    const m = v.match(/^\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\]$/);
    if (m) arr = [parseFloat(m[1]), ...];
    screenFrameAllZeros = !!arr && arr.every((n) => n === 0);
  }
  const isGoogleInc = /^Google\s*Inc\.?$/i.test(vendor);
  if (screenFrameAllZeros && isGoogleInc) {
    score += 0.5;
    reasons.push("chomium_screen_frame");
  }
  return { score, reasons };
}
```

| Condition | Score | Reason |
|-----------|-------|--------|
| `screenFrame` = [0,0,0,0] **and** `webglVendor` = "Google Inc." | +0.5 | chromium_screen_frame |

WebGL renderer is assessed separately via `assessWebGLRenderer` (SwiftShader, ANGLE, etc.).

## Integration in Challenge Flow

1. Client calls `GET /api/challenge` → receives `{ id, encryptedPublicKey }` including session signing key.
2. Client collects FingerprintJS payload; signs with session signing key.
3. Client POSTs `{ entropy, fingerprint: { payload, timestamp, signature, token } }`.
4. Server: `verifySignedFingerprint` → `storeFingerprint` → `assessFingerprintComponents` + `assessWebGLRenderer`.
5. Fingerprint scores feed into total risk; threshold exceeded → `403`.

## Redis Keys

| Key | Purpose |
|-----|---------|
| `fp:sign:{token}` | Session signing key (HMAC) |
| `fp:dev:{visitorId}` | Stored device record |
| `fp:ch:{hash}` | Component hash → device IDs (set) |
| `fp:devid:{deviceId}` | Device ID → visitor IDs (set) |

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| MIN_COMPONENT_OVERLAP | 3 | Devices linked if ≥3 component hashes match |
| DEVICE_TTL_SEC | 90 days | Device record TTL |
| TIMESTAMP_MAX_AGE_MS | 5 min | Max age of fingerprint timestamp |
| TIMESTAMP_MAX_FUTURE_MS | 60 s | Max future skew for timestamp |
