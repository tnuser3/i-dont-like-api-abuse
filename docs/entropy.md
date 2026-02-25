# Entropy

Client-side fingerprint and behaviour tracking for abuse detection.

## Fingerprint

Collected values: timestamp, perfOrigin, userAgent, language, languages, platform, hardwareConcurrency, deviceMemory, screen dimensions, colorDepth, pixelRatio, timezone, touchSupport, cookieEnabled, canvasHash, webglHash.

## Entropy derivation

`deriveEntropy(fingerprint, extraSeed?)` — Deterministic bytes from fingerprint + optional seed. Uses CRC32-based expansion to produce 32 bytes. Server recomputes and compares to detect spoofing.

## Behaviour tracker

- **record(type)** — Logs event with timestamp
- **analyse()** — Returns SuspiciousFlags
- **getEvents()** — Events in 60s window for server submission

## Suspicious flags

| Flag | Trigger |
|------|---------|
| rateLimitExceeded | ≥30 events in window |
| syntheticTimestamps | Inter-event interval < 50ms |
| automationPattern | Intervals with std dev < 5ms (≥3 events) |
| fingerprintAnomaly | User-Agent mismatch, language mismatch, timestamp drift > 2min, entropy mismatch |

## Server cross-reference

- User-Agent header vs fingerprint.userAgent
- Accept-Language vs fingerprint.language
- Server time vs client timestamp (drift > 2 min)
- Recomputed entropy vs received entropyHex

## Score

0–1; higher = more suspicious. Threshold 0.7 for `ok: false`. Scores can be persisted in Redis by fingerprint hash (24h TTL) for abuse tracking.
