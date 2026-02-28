# C# Compiler (BytecodeGen + CWasmInjector)

The compiler is a C# console app that generates randomised bytecodes, injects them into C source, and compiles to `crypto_utils.wasm`. Each build produces a different opcode→action mapping and S-box pair—no two deployments are identical.

## Project Layout

```
compiler/microsoft.botsay/
├── Program.cs           Entry point: generate → inject → compile
├── Lib/
│   ├── BytecodeGen.cs   Generate opcode_action, vm, vm_inv, bytecodes.json
│   ├── CWasmInjector.cs Inject placeholders, compile C → WASM (clang/emcc)
│   ├── CSourceStrings.cs C source templates with {{OPCODE_ACTION}}, {{VM}}, {{VM_INV}}
│   └── SboxUtils.cs     AES S-box generation (if used)
└── build/
    ├── crypto_utils.c   Injected C source (after build)
    ├── crypto_utils.wasm
    └── bytecodes.json   Opcode hex → action name
```

## Program Flow

```csharp
// Program.cs
var (opcodeAction, vm, vmInv, mapping) = BytecodeGen.Generate();
BytecodeGen.WriteBytecodesJson(outDir, opcodeAction, vm, vmInv, mapping);

string cSource = CSourceStrings.GetAll();
var injections = new CWasmInjections()
    .WithSbox("OPCODE_ACTION", opcodeAction)
    .WithSbox("VM", vm)
    .WithSbox("VM_INV", vmInv);

string injected = CWasmInjector.Inject(cSource, injections);
File.WriteAllText(cPath, injected);

var (success, _, stdout, stderr) = CWasmInjector.CompileToWasm(injected, wasmPath, options);
```

## BytecodeGen.Generate()

1. Shuffle bytes 0–255; assign first 19 to the 19 actions.
2. Build `opcode_action[256]`: `opcode_action[opcode] = action_index` (255 = no-op).
3. Shuffle 0–255 again for `vm` S-box; compute inverse `vm_inv` s.t. `vm_inv[vm[i]] = i`.
4. Return `(opcodeAction, vm, vmInv, mapping)` where `mapping["0x42"] = "vm_apply"` etc.

```csharp
// BytecodeGen.cs
public static readonly string[] Actions =
{
    "vm_apply", "vm_apply_inv", "xor_buf", "xor_inplace", "crc32", "adler32", "xor_checksum",
    "to_hex", "from_hex", "read_u32be", "write_u32be", "read_u32le", "write_u32le",
    "rotl32", "rotr32", "swap32", "get_bit", "set_bit", "chacha_decrypt",
};

public static (byte[] OpcodeAction, byte[] Vm, byte[] VmInv, Dictionary<string, string> Mapping) Generate()
{
    var all = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
    SecureShuffle(all);
    var pool = all.Take(Actions.Length).ToArray();
    // opcode_action[pool[i]] = i
    var vm = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
    SecureShuffle(vm);
    var vmInv = new byte[256];
    for (int i = 0; i < 256; i++) vmInv[vm[i]] = (byte)i;
    return (opcodeAction, vm, vmInv, mapping);
}
```

## CWasmInjector.Inject()

Replaces placeholders in the C source:

| Placeholder | Format | Example |
|-------------|--------|---------|
| `{{SBOX:NAME}}` | `{0x13,0x4a,...}` | S-box byte array |
| `{{STR:NAME}}` | `"escaped string"` | C string |
| `{{INT:NAME}}` | `42` | Integer literal |
| `{{CALL:NAME}}` | Inline C code | Custom call |

```csharp
// CWasmInjector.cs
private static string SboxToCArray(byte[] sbox)
{
    var sb = new StringBuilder("{");
    for (int i = 0; i < sbox.Length; i++) {
        if (i > 0) sb.Append(',');
        sb.AppendFormat("0x{0:x2}", sbox[i]);
    }
    return sb.Append('}').ToString();
}
```

## C Source Placeholders

```c
// CSourceStrings.cs - Sbox
static const uint8_t vm[256]={{VM}};
static const uint8_t vm_inv[256]={{VM_INV}};

// Main
static const uint8_t opcode_action[256]={{OPCODE_ACTION}};
```

After injection, `{{VM}}` becomes `{0x13,0x4a,0xe0,...}`.

## Compile to WASM

Uses clang (default) or emcc:

```csharp
// clang (default)
clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--allow-undefined
      -Wl,--export=to_hex -Wl,--export=vm_run ... -Os -o crypto_utils.wasm crypto_utils.c
```

Exported functions: `to_hex`, `from_hex`, `vm_apply`, `vm_apply_inv`, `vm_get`, `vm_get_inv`, `xor_buf`, `crc32`, `adler32`, `xor_checksum`, `read_u32be`, `write_u32be`, `read_u32le`, `write_u32le`, `rotl32`, `rotr32`, `swap32`, `vm_run`, `chacha_decrypt`.

## bytecodes.json

```json
{
  "bytecodes": {
    "0x0f": "chacha_decrypt",
    "0x44": "vm_apply",
    "0xa5": "vm_apply_inv",
    ...
  },
  "opcode_action": [255,255,...,12,...,255],
  "vm": [19,74,224,...],
  "vm_inv": [155,51,132,...]
}
```

The site loads `bytecodes.json` and `crypto_utils.wasm`. The server uses the same bytecodes (copied at build time) for `vm-encoder` so it can compute expected solutions.

## Build Integration

```bash
npm run build
```

Runs `dotnet run --project compiler/microsoft.botsay` with `site/public` (or similar) as output; copies `crypto_utils.wasm` and `bytecodes.json` into the site's public folder for serving.

## Security Properties

- **Build-time randomness** — SecureShuffle uses `RandomNumberGenerator`; each `dotnet run` yields different bytecodes.
- **No runtime key** — Opcodes and S-boxes are embedded in the binary; no external config needed.
- **Opaque to replay** — Captured WASM + bytecodes from one deployment cannot solve challenges from another deployment without the matching server bytecodes.
