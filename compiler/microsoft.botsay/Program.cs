using Lib;

string outDir = args.Length > 0 ? args[0] : Path.Combine(Directory.GetCurrentDirectory(), "build");
outDir = Path.GetFullPath(outDir);
Directory.CreateDirectory(outDir);

string cPath = Path.Combine(outDir, "crypto_utils.c");
string wasmPath = Path.Combine(outDir, "crypto_utils.wasm");

var (opcodeAction, vm, vmInv, mapping) = BytecodeGen.Generate();
BytecodeGen.WriteBytecodesJson(outDir, opcodeAction, vm, vmInv, mapping);

string cSource = CSourceStrings.GetAll();
var injections = new CWasmInjections()
    .WithSbox("OPCODE_ACTION", opcodeAction)
    .WithSbox("VM", vm)
    .WithSbox("VM_INV", vmInv);

string injected = CWasmInjector.Inject(cSource, injections);
File.WriteAllText(cPath, injected);
Console.WriteLine($"Wrote {cPath}");

var options = new CWasmCompileOptions()
    .ExportFunction("to_hex")
    .ExportFunction("from_hex")
    .ExportFunction("vm_apply")
    .ExportFunction("vm_apply_inv")
    .ExportFunction("vm_get")
    .ExportFunction("vm_get_inv")
    .ExportFunction("xor_buf")
    .ExportFunction("crc32")
    .ExportFunction("adler32")
    .ExportFunction("xor_checksum")
    .ExportFunction("read_u32be")
    .ExportFunction("write_u32be")
    .ExportFunction("read_u32le")
    .ExportFunction("write_u32le")
    .ExportFunction("rotl32")
    .ExportFunction("rotr32")
    .ExportFunction("swap32")
    .ExportFunction("vm_run")
    .ExportFunction("chacha_decrypt");

var (success, _, stdout, stderr) = CWasmInjector.CompileToWasm(injected, wasmPath, options);

if (success)
{
    Console.WriteLine($"Built {wasmPath}");
}
else
{
    Console.Error.WriteLine("WASM build failed (clang may not be on PATH):");
    if (!string.IsNullOrEmpty(stderr)) Console.Error.WriteLine(stderr);
    if (!string.IsNullOrEmpty(stdout)) Console.WriteLine(stdout);
    Console.WriteLine($"Injected C source saved to {cPath} – compile manually:");
    Console.WriteLine($"  clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--allow-undefined -Wl,--export-all -Os -o crypto_utils.wasm crypto_utils.c");
}
