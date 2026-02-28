# VM (Bytecode Virtual Machine)

A custom bytecode VM runs a sequence of operations on a buffer. The opcode→action mapping, S-box (`vm`), and inverse S-box (`vm_inv`) are regenerated per build—making replay or static analysis ineffective without the specific bytecodes.

## Architecture

```
bytecodes.json                    crypto_utils.wasm
┌─────────────────────┐          ┌─────────────────────┐
│ opcode_action[256]  │          │ vm[256], vm_inv[256]│
│ vm[256], vm_inv[256]│          │ opcode_action[256]  │
│ bytecodes (hex→name)│          │ vm_run(buf,...)     │
└──────────┬──────────┘          └──────────┬──────────┘
           │                                 │
           │         vm-encoder.ts           │  vm-inject.ts
           │    (server: run, encode)         │  (client: load, run)
           └─────────────┬───────────────────┘
                         │
                   Same bytecodes
```

## Operations (Action Indices)

| Idx | Action | Effect | Params |
|-----|--------|--------|--------|
| 0 | vm_apply | buf[i] = vm[buf[i]] | — |
| 1 | vm_apply_inv | buf[i] = vm_inv[buf[i]] | — |
| 2 | xor_buf | buf ^= key (cyclic) | key bytes |
| 3 | xor_inplace | buf ^= key (cyclic) | key bytes |
| 4 | crc32 | Last 4 bytes = CRC32 of preceding | — |
| 5 | adler32 | Last 4 bytes = Adler32 of preceding | — |
| 6 | xor_checksum | Last byte = XOR of preceding | — |
| 7 | to_hex | Binary → hex string (2x length) | — |
| 8 | from_hex | Hex string → binary | — |
| 9 | read_u32be | — (no-op in forward) | — |
| 10 | write_u32be | LE↔BE per u32 | — |
| 11 | read_u32le | — | — |
| 12 | write_u32le | LE↔BE per u32 | — |
| 13 | rotl32 | Rotate left | key[0]&31 = shift |
| 14 | rotr32 | Rotate right | key[0]&31 = shift |
| 15 | swap32 | Byte-swap each u32 | — |
| 16 | get_bit | No-op | — |
| 17 | set_bit | Set/clear bit in each u32 | key[0]=bit, key[1]=on |
| 18 | chacha_decrypt | ChaCha20-Poly1305 decrypt | key,iv,tag in key |

## Server: vm-encoder.run()

Computes the expected result by applying operations in order. Used to verify client solutions:

```typescript
// vm-encoder.ts
export function run(
  buffer: Uint8Array,
  operations: EncoderOperation[],
  bytecodes: BytecodesForEncoder,
): Uint8Array {
  const opcodeAction = bytecodes.opcode_action;
  let buf = new Uint8Array(buffer);

  for (let i = 0; i < operations.length; i++) {
    const { op, params } = operations[i]!;
    const idx = op <= 255 ? opcodeAction[op] : 255;
    if (idx === 255) continue;

    buf = new Uint8Array(applyForwardOp(idx, buf, params, bytecodes));
  }

  return buf;
}
```

Each operation maps `op` (opcode byte) to an action index via `opcode_action`. Index 255 = no-op (filtered out at build time).

## Client: vm-inject

1. Load WASM and bytecodes JSON.
2. Provide `chacha_poly_decrypt` import (JS ChaCha20-Poly1305) so the WASM can decrypt.
3. Map action names to opcodes from bytecodes.
4. Run `vm_run` in WASM on the input buffer.

```typescript
// vm-inject.ts - WASM import for chacha_decrypt
const imports: WebAssembly.Imports = {
  env: {
    chacha_poly_decrypt: (out, outlen, ct, ctlen, key, iv, tag, _aad, _aadlen) => {
      const mem = memoryRef.current;
      if (!mem) return -1;
      return chachaPolyDecrypt(mem, out, outlen, ct, ctlen, key, iv, tag);
    },
  },
};
```

## C Implementation (crypto_utils.c)

```c
int vm_run(uint8_t* buf, size_t buf_len, const uint8_t* actions, size_t actions_len,
           const uint8_t* key, size_t key_len) {
  for (size_t i = 0; i < actions_len; i++) {
    uint8_t idx = opcode_action[actions[i]];
    if (idx == 255) continue;
    switch (idx) {
      case 0: vm_apply(buf, buf_len); break;
      case 1: vm_apply_inv(buf, buf_len); break;
      case 2:
      case 3: /* xor with key */ break;
      case 4: /* crc32 to last 4 bytes */ break;
      // ...
      case 18: /* chacha_decrypt via imported chacha_poly_decrypt */ break;
    }
  }
  return 0;
}
```

`vm` and `vm_inv` are 256-byte S-boxes (random permutation and its inverse). Injected at compile time by the C# compiler.

## Challenge Flow

1. **Server** picks 8–15 operations (layered, shuffled), random params, 4-byte input.
2. **Server** runs `vm-encoder.run(input, operations, bytecodes)` → expected uint32 at offset 0.
3. **Server** stores expected in Redis; signs JWT with challengeId.
4. **Client** receives encrypted WASM, key, operations, input, token.
5. **Client** decrypts WASM, loads VM, runs `vmRunWithOperations(data, operations)`.
6. **Client** reads `readU32LE(data, 0)` → solved.
7. **Client** POSTs `{ token, solved }`; server verifies.

## encode() vs run()

- **run()** — Forward application; matches WASM behaviour. Server computes expected.
- **encode()** — Inverse operations in reverse order. Produces ciphertext that, when run, yields plaintext. Used for inverse/challenge-building logic.

```typescript
// vm-encoder.ts
export function encode(
  plaintext: Uint8Array,
  operations: EncoderOperation[],
  bytecodes: BytecodesForEncoder,
): Uint8Array {
  let buf = new Uint8Array(plaintext);
  for (let i = operations.length - 1; i >= 0; i--) {
    buf = new Uint8Array(applyInverseOp(idx, buf, params, bytecodes));
  }
  return buf;
}
```
