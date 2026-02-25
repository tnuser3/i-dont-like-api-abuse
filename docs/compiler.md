# Compiler

The `microsoft.botsay` C# project generates cryptographically random bytecode and compiles a C VM to WebAssembly.

## Build output

- `build/crypto_utils.c` — Injected C source
- `build/crypto_utils.wasm` — Compiled WASM module
- `build/bytecodes.json` — Opcode mapping, vm, vm_inv

## Pipeline

1. **BytecodeGen.Generate()** — Produces:
   - `opcodeAction[256]` — byte → action index (255 = no-op)
   - `vm[256]` — random permutation (S-box)
   - `vmInv[256]` — inverse permutation
   - `mapping` — hex opcode → action name

2. **BytecodeGen.WriteBytecodesJson()** — Writes bytecodes.json

3. **CWasmInjector.Inject()** — Replaces placeholders in C source:
   - `{{OPCODE_ACTION}}` → opcode_action array
   - `{{VM}}` → vm array
   - `{{VM_INV}}` → vm_inv array

4. **CWasmInjector.CompileToWasm()** — Runs clang:
   ```
   clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--allow-undefined -Os -o crypto_utils.wasm crypto_utils.c
   ```

## Actions (index → name)

| Index | Action |
|-------|--------|
| 0 | vm_apply |
| 1 | vm_apply_inv |
| 2 | xor_buf |
| 3 | xor_inplace |
| 4 | crc32 |
| 5 | adler32 |
| 6 | xor_checksum |
| 7 | to_hex |
| 8 | from_hex |
| 9 | read_u32be |
| 10 | write_u32be |
| 11 | read_u32le |
| 12 | write_u32le |
| 13 | rotl32 |
| 14 | rotr32 |
| 15 | swap32 |
| 16 | get_bit |
| 17 | set_bit |
| 18 | chacha_decrypt |

## Running the compiler

```bash
dotnet run --project compiler/microsoft.botsay
dotnet run --project compiler/microsoft.botsay -- compiler/microsoft.botsay/build
```

The `copy-vm-assets` script copies `crypto_utils.wasm` and `bytecodes.json` from `compiler/.../build` to `site/data`.
