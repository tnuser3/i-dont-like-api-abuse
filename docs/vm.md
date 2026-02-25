# VM

The VM applies a sequence of byte operations to a buffer. Each operation is identified by an opcode byte; the mapping is random per build.

## vm_run signature

```c
int vm_run(uint8_t* buf, size_t buf_len, const uint8_t* actions, size_t actions_len, const uint8_t* key, size_t key_len);
```

- `buf` — Mutable buffer; modified in place
- `actions` — Array of opcode bytes
- `key` — Optional; used by xor, rotl/rotr, set_bit, chacha_decrypt

## Operations

| Action | Effect |
|--------|--------|
| vm_apply | buf[i] = vm[buf[i]] |
| vm_apply_inv | buf[i] = vm_inv[buf[i]] |
| xor_buf / xor_inplace | buf ^= key (cyclically) |
| crc32 | Last 4 bytes = CRC32 of preceding |
| adler32 | Last 4 bytes = Adler32 of preceding |
| xor_checksum | Last byte = XOR of preceding |
| to_hex | Binary → hex string (in-place, 2x length) |
| from_hex | Hex string → binary (in-place, ½ length) |
| read_u32be / write_u32be | Big-endian 32-bit |
| read_u32le / write_u32le | Little-endian 32-bit |
| rotl32 / rotr32 | Rotate; key[0] & 31 = shift amount |
| swap32 | Byte-swap 32-bit words |
| get_bit | No-op in vm_run |
| set_bit | key[0]=bit, key[1]=on; set bit in each u32 |
| chacha_decrypt | key layout: 32B key, 12B iv, 16B tag; decrypt buf |

## Challenge flow

1. Server picks 8–15 operations (layered), random params, 4-byte input
2. Server runs `vm-encoder.run(input, operations, bytecodes)` → expected uint32
3. Server stores expected in Redis; signs JWT with challengeId
4. Client receives encrypted WASM, key, operations, input, token
5. Client decrypts WASM, loads VM, runs `vmRunWithOperations(data, operations)`
6. Client reads `readU32LE(data, 0)` → solved
7. Client sends `{ token, solved }` to verify
8. Server verifies JWT, fetches expected from Redis, compares

## vm-encoder

- **run()** — Forward ops; matches WASM vm_run; used server-side for expected
- **encode()** — Inverse ops in reverse; produces ciphertext that client decodes

The encoder uses the same bytecodes (vm, vm_inv, opcode_action) as the WASM build.
