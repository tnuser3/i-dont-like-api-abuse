# Architecture

## Overview

The system combines several layers to deter API abuse:

1. **Request risk assessment** — Per-request scoring on headers (UA, origin, referer, sec-ch-ua, via), ASN, and WebGL renderer. Blocks when score ≥ 0.45.
2. **Adaptive rate limiting** — Tiered limits (e.g. 45–75 req/30s); stricter after violations; exponential block duration.
3. **Entropy validation** — Client fingerprint and behaviour scoring before challenges; threshold 0.7.
4. **Random bytecode VM** — Opcode mapping and S-box regenerated per build (CSPRNG).
5. **Encrypted WASM delivery** — ChaCha20-Poly1305; key only in challenge response.
6. **Stateless verification** — JWT + Redis; expected result stored server-side.

## Data Flow

```
Client                              Server
   |                                   |
   |-- GET /api/challenge ----------->|  Risk check, rate limit
   |<-- { id, encryptedPublicKey } ---|  Create key session
   |                                   |
   |  Derive session key               |
   |  Collect fingerprint + entropy    |
   |                                   |
   |-- POST /api/challenge ---------->|  Risk check, decrypt
   |   { id, body }                    |  Validate entropy, fingerprint
   |                                   |  WebGL + header risk
   |                                   |  Cross-reference, behaviour
   |<-- { id, credential } -----------|  Create challenge, encrypt response
   |                                   |
   |  Decrypt credential               |
   |  Decrypt WASM, load VM             |
   |  Run operations on input          |
   |  Read uint32 at offset 0          |
   |                                   |
   |-- POST /api/challenge/verify ---->|  Risk check, decrypt
   |   { id, body } { token, solved }  |  Verify JWT, get expected
   |<-- { ok } -----------------------|  Compare, consume challenge
```

## Components

| Component | Role |
|-----------|------|
| **request-risk-assessor** | Header scoring, ASN base + dynamic scores, WebGL checks; rate limit enforcement |
| **microsoft.botsay** | Generates random opcode_action, vm, vm_inv; compiles to WASM |
| **bytecodes.json** | Opcode→action mapping, vm, vm_inv; shared by server and embedded in WASM |
| **crypto_utils.wasm** | VM implementation; sbox/opcode_action baked in at compile time |
| **vm-inject** | Loads WASM, ChaCha decrypt, vm_run; client-side |
| **vm-encoder** | run() for server verification |
| **jwt-challenge** | Sign/verify challenge tokens; challengeId in payload |
| **key-session-server** | ECDH key exchange; encrypt/decrypt request/response bodies |
| **Redis** | challenge:{id} → expected; fp:sign:{id} → signing key; risk:* keys; manager:requests |

## Security Properties

- **Unique opcodes** — Each action gets a distinct byte; no collisions
- **Rejection sampling** — Fisher-Yates with CSPRNG; no modulo bias
- **No client secrets** — Key and token only in challenge response; one-time use
- **Server-authoritative** — Expected value never sent to client; verify compares server-side
- **Per-request gates** — All routes run risk and rate-limit checks first
