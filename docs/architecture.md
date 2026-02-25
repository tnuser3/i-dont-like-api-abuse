# Architecture

## Overview

The system combines several layers to deter API abuse:

1. **Entropy validation** — Client fingerprint and behaviour scoring before challenges
2. **Random bytecode VM** — Opcode mapping and S-box regenerated per build (CSPRNG)
3. **Encrypted WASM delivery** — ChaCha20-Poly1305; key only in challenge response
4. **Stateless verification** — JWT + Redis; expected result stored server-side

## Data flow

```
Client                          Server
   |                               |
   |-- POST /api/entropy --------->|  Fingerprint + entropy + behaviour
   |<-- { ok, score } -------------|  Cross-check headers, analyse events
   |                               |
   |-- GET /api/challenge -------->|  Load bytecodes, encrypt WASM
   |<-- { encryptedWasm, key,      |  Generate ops, compute expected,
   |     operations, input, token }|  Store expected in Redis, sign JWT
   |                               |
   |  Decrypt WASM, load VM        |
   |  Run operations on input     |
   |  Read uint32 LE at offset 0   |
   |                               |
   |-- POST /api/challenge/verify->|  Verify JWT, get expected from Redis
   |   { token, solved }           |  Compare solved === expected
   |<-- { ok } --------------------|
```

## Components

| Component | Role |
|-----------|------|
| **microsoft.botsay** | Generates random opcode_action, vm, vm_inv; injects into C; compiles to WASM |
| **bytecodes.json** | Opcode→action mapping, vm S-box, vm_inv; shared by server (verify) and embedded in WASM |
| **crypto_utils.wasm** | VM implementation; sbox/opcode_action baked in at compile time |
| **vm-inject** | Loads WASM, ChaCha decrypt, vm_run; client-side |
| **vm-encoder** | run() for server verification; encode() for inverse ops |
| **jwt-challenge** | Sign/verify challenge tokens; challengeId in payload |
| **Redis** | challenge:{id} → expected uint32; 5 min TTL; consumed on verify |

## Security properties

- **Unique opcodes** — Each action gets a distinct byte; no collisions
- **Rejection sampling** — Fisher-Yates with CSPRNG; no modulo bias
- **No client secrets** — Key and token only in challenge response; one-time use
- **Server-authoritative** — Expected value never sent to client; verify compares server-side
