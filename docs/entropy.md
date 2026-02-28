# Entropy (Client Fingerprint & Behaviour)

Entropy combines a deterministic client fingerprint with behaviour events. The server recomputes entropy from the fingerprint and compares it to the client's `entropyHex` to detect spoofing or automation.

## ClientFingerprint

Collected in the browser via `collectFingerprint()`:

```typescript
// entropy.ts
export interface ClientFingerprint {
  timestamp: number;
  perfOrigin: number;
  userAgent: string;
  language: string;
  languages: string[];
  platform: string;
  hardwareConcurrency: number;
  deviceMemory?: number;
  screenWidth: number;
  screenHeight: number;
  availWidth: number;
  availHeight: number;
  colorDepth: number;
  pixelRatio: number;
  timezoneOffset: number;
  timezone: string;
  touchSupport: boolean;
  cookieEnabled: boolean;
  canvasHash?: number;
  webglHash?: number;
  webglVendor?: string;
  webglRenderer?: string;
  webgl2Hash?: number;
  audioHash?: number;
  fontsHash?: number;
  pluginsHash?: number;
  webdriver?: boolean;
  innerWidth?: number;
  innerHeight?: number;
  outerWidth?: number;
  outerHeight?: number;
}
```

## Hash Sources

| Field | Source |
|-------|--------|
| canvasHash | 2D canvas with text/shape; CRC32 of toDataURL() |
| webglHash | WebGL UNMASKED_VENDOR + UNMASKED_RENDERER; CRC32 |
| webgl2Hash | WebGL2 params (MAX_TEXTURE_SIZE, RENDERER, etc.); CRC32 |
| audioHash | AudioContext sampleRate, baseLatency, state |
| fontsHash | Measured widths of test string in 11 fonts |
| pluginsHash | navigator.plugins names + mimeTypes.length |

## Entropy Derivation

Deterministic bytes from fingerprint + optional extra seed:

```typescript
// entropy.ts
export function deriveEntropy(
  fingerprint: ClientFingerprint,
  extraSeed?: string | Uint8Array,
  outputLength = 32
): Uint8Array {
  const base = fingerprintToBytes(fingerprint);
  let combined = new Uint8Array(base.length);
  combined.set(base);

  if (extraSeed !== undefined) {
    const extra = typeof extraSeed === "string"
      ? new TextEncoder().encode(extraSeed)
      : extraSeed;
    const newCombined = new Uint8Array(combined.length + extra.length);
    newCombined.set(combined);
    newCombined.set(extra, combined.length);
    combined = newCombined;
  }

  const out = new Uint8Array(outputLength);
  let hash = crc32(combined);

  for (let i = 0; i < outputLength; i += 4) {
    hash = (hash * 1664525 + 1013904223) >>> 0;
    out[i] = (hash >>> 24) & 0xff;
    if (i + 1 < outputLength) out[i + 1] = (hash >>> 16) & 0xff;
    if (i + 2 < outputLength) out[i + 2] = (hash >>> 8) & 0xff;
    if (i + 3 < outputLength) out[i + 3] = hash & 0xff;
  }
  return out;
}
```

`fingerprintToBytes` serializes fingerprint fields to a pipe-delimited string and encodes to bytes. CRC32 seeds an LCG to expand to 32 bytes.

## Cross-Reference (Server)

Compares fingerprint to request headers and recomputed entropy:

```typescript
// entropy.ts
export function crossReferenceEntropy(
  fingerprint: ClientFingerprint,
  headers: Headers,
  clientTimestamp: number,
  entropyHex: string,
  extraSeed?: string
): { score: number; reasons: string[] } {
  let score = 0;
  const reasons: string[] = [];

  // User-Agent vs fingerprint.userAgent
  if (normClient !== normHeader) {
    score += USER_AGENT_MISMATCH;  // 0.35
    reasons.push("user_agent_mismatch");
  }

  // Accept-Language vs fingerprint.language
  if (clientLang && !headerLangs.some(h => h === clientLang)) {
    score += LANGUAGE_MISMATCH;   // 0.25
    reasons.push("language_mismatch");
  }

  // Timestamp drift > 2 min
  if (drift > MAX_TIMESTAMP_DRIFT_MS) {
    score += TIMESTAMP_DRIFT;     // 0.3
    reasons.push("timestamp_drift");
  }

  // navigator.webdriver
  if (fingerprint.webdriver) {
    score += 0.5;
    reasons.push("webdriver_detected");
  }

  // Recomputed entropy vs received entropyHex
  const expected = deriveEntropy(fingerprint, extraSeed);
  const received = fromHex(entropyHex);
  if (expected.length !== received.length || !bytesMatch) {
    score += ENTROPY_MISMATCH;    // 0.4
    reasons.push("entropy_mismatch");
  }

  return { score, reasons };
}
```

## Behaviour Analysis

Events: `{ type: string, timestamp: number }[]`. Server analyses intervals:

```typescript
// entropy.ts
export function analyseBehaviour(events: BehaviourEvent[]): { score: number; flags: Partial<SuspiciousFlags> } {
  flags.rateLimitExceeded = events.length >= 30;   // +0.4
  flags.syntheticTimestamps = intervals.some(d => d < 300);  // +0.3
  flags.automationPattern = stdDev < 5 && intervals.length >= 3;  // +0.3
  // ...
}
```

| Flag | Trigger | Score |
|------|---------|-------|
| rateLimitExceeded | ≥30 events in 60s | 0.4 |
| syntheticTimestamps | Any interval < 300ms | 0.3 |
| automationPattern | Std dev of intervals < 5ms (≥3 events) | 0.3 |

## Total Score & Threshold

`totalScore = crossScore + behaviourScore`. If `totalScore >= 0.7` → `403 Entropy validation failed`.

## createEntropyPayload (Client)

Builds fingerprint, derives entropy, and records behaviour:

```typescript
// entropy.ts / fingerprint-client
const entropyPayload = createEntropyPayload();
// { fingerprint, entropyHex: toHex(entropy), timestamp, behaviour: { events, flags } }
```

The client's `getBehaviourTracker()` records events (e.g. "challenge_request") during the challenge flow.
