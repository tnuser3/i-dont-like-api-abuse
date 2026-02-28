using System.Diagnostics;
using System.Text;

namespace Lib;

public static class CWasmInjector
{
    public static string Inject(string cSource, CWasmInjections injections)
    {
        var sb = new StringBuilder(cSource);

        foreach (var (key, value) in injections.Strings)
            ReplaceAll(sb, key, EscapeCString(value));

        foreach (var (key, value) in injections.Integers)
            ReplaceAll(sb, key, value.ToString());

        foreach (var (key, sbox) in injections.Sboxes)
            ReplaceAll(sb, key, SboxToCArray(sbox));

        foreach (var (key, call) in injections.Calls)
            ReplaceAll(sb, key, call);

        return sb.ToString();
    }

    private static void ReplaceAll(StringBuilder sb, string name, string replacement)
    {
        foreach (var p in new[] { $"{{{{{name}}}}}", $"{{{{STR:{name}}}}}", $"{{{{INT:{name}}}}}", $"{{{{SBOX:{name}}}}}", $"{{{{CALL:{name}}}}}" })
            sb.Replace(p, replacement);
    }

    private static string EscapeCString(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            _ = c switch
            {
                '"' => sb.Append("\\\""),
                '\\' => sb.Append("\\\\"),
                '\n' => sb.Append("\\n"),
                '\r' => sb.Append("\\r"),
                '\t' => sb.Append("\\t"),
                '\0' => sb.Append("\\0"),
                _ when c < 32 || c > 126 => sb.Append($"\\x{(int)c:x2}"),
                _ => sb.Append(c)
            };
        }
        return sb.Append('"').ToString();
    }

    private static string SboxToCArray(byte[] sbox)
    {
        var sb = new StringBuilder("{");
        for (int i = 0; i < sbox.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.AppendFormat("0x{0:x2}", sbox[i]);
        }
        return sb.Append('}').ToString();
    }

    public static (bool Success, string OutputPath, string StdOut, string StdErr) CompileToWasm(
        string cSourceOrPath,
        string outputPath,
        CWasmCompileOptions? options = null)
    {
        options ??= new CWasmCompileOptions();
        string cPath = cSourceOrPath;

        if (!cSourceOrPath.EndsWith(".c", StringComparison.OrdinalIgnoreCase))
        {
            cPath = Path.Combine(Path.GetTempPath(), $"wasm_src_{Guid.NewGuid():N}.c");
            File.WriteAllText(cPath, cSourceOrPath);
        }

        return options.Compiler == CWasmCompiler.Emcc
            ? CompileEmcc(cPath, outputPath, cSourceOrPath, options)
            : CompileClang(cPath, outputPath, cSourceOrPath, options);
    }

    private static (bool Success, string OutputPath, string StdOut, string StdErr) CompileClang(
        string cPath, string outputPath, string cSourceOrPath, CWasmCompileOptions options)
    {
        var args = new List<string> { "--target=wasm32", "-nostdlib", "-Wl,--no-entry", "-Wl,--allow-undefined", "-Os" };
        if (options.ExportedFunctions.Count > 0)
            foreach (var f in options.ExportedFunctions)
                args.Add($"-Wl,--export={f.TrimStart('_')}");
        else
            args.Add("-Wl,--export-all");
        args.AddRange(["-o", outputPath, cPath]);
        args.AddRange(options.ExtraArgs);

        return RunCompiler("clang", args, outputPath, cPath, cSourceOrPath, options,
            fallbackCmd: $"clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--allow-undefined -Wl,--export-all -Os -o crypto_utils.wasm {Path.GetFileName(cPath)}");
    }

    private static (bool Success, string OutputPath, string StdOut, string StdErr) CompileEmcc(
        string cPath, string outputPath, string cSourceOrPath, CWasmCompileOptions options)
    {
        var args = new List<string>
        {
            cPath, "-o", outputPath,
            "-s", "STANDALONE_WASM=1", "-s", "EXPORTED_FUNCTIONS=_malloc,_free",
            "-s", "EXPORTED_RUNTIME_METHODS=cwrap", "-Os"
        };
        if (options.ExportedFunctions.Count > 0)
        {
            var exports = string.Join(",", new[] { "_malloc", "_free" }
                .Concat(options.ExportedFunctions.Select(f => $"_{f.TrimStart('_')}"))
                .Distinct());
            args.AddRange(["-s", $"EXPORTED_FUNCTIONS=[{exports}]"]);
        }
        args.AddRange(options.ExtraArgs);

        return RunCompiler("emcc", args, outputPath, cPath, cSourceOrPath, options,
            fallbackCmd: $"emcc {Path.GetFileName(cPath)} -o crypto_utils.wasm -s STANDALONE_WASM=1 -Os");
    }

    private static (bool Success, string OutputPath, string StdOut, string StdErr) RunCompiler(
        string exe, List<string> args, string outputPath, string cPath, string cSourceOrPath,
        CWasmCompileOptions options, string fallbackCmd)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = string.Join(" ", args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a)),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        try
        {
            using var proc = Process.Start(startInfo);
            if (proc == null)
                return (false, outputPath, "", $"Failed to start {exe}. Is it on PATH?");
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(options.TimeoutMs);
            if (!cSourceOrPath.EndsWith(".c", StringComparison.OrdinalIgnoreCase))
                try { File.Delete(cPath); } catch { }
            return (proc.ExitCode == 0, outputPath, stdout, stderr);
        }
        catch (Exception ex)
        {
            return (false, outputPath, "", $"{exe} failed: {ex.Message}. Fallback: {fallbackCmd}");
        }
    }

    public static (bool Success, string OutputPath, string StdOut, string StdErr) InjectAndCompile(
        string cSource,
        CWasmInjections injections,
        string outputPath,
        CWasmCompileOptions? options = null)
    {
        string injected = Inject(cSource, injections);
        return CompileToWasm(injected, outputPath, options);
    }
}

public class CWasmInjections
{
    public Dictionary<string, string> Strings { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, long> Integers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, byte[]> Sboxes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Calls { get; } = new(StringComparer.OrdinalIgnoreCase);

    public CWasmInjections WithSbox(string placeholder, byte[] sbox)
    {
        Sboxes[placeholder] = sbox;
        return this;
    }

    public CWasmInjections WithString(string placeholder, string value)
    {
        Strings[placeholder] = value;
        return this;
    }

    public CWasmInjections WithInt(string placeholder, long value)
    {
        Integers[placeholder] = value;
        return this;
    }

    public CWasmInjections WithCall(string placeholder, string callCode)
    {
        Calls[placeholder] = callCode;
        return this;
    }
}

public enum CWasmCompiler { Emcc, Clang }

public class CWasmCompileOptions
{
    public CWasmCompiler Compiler { get; set; } = CWasmCompiler.Clang;
    public List<string> ExportedFunctions { get; } = new();
    public List<string> ExtraArgs { get; } = new();
    public int TimeoutMs { get; set; } = 60000;

    public CWasmCompileOptions ExportFunction(string name)
    {
        ExportedFunctions.Add(name.TrimStart('_'));
        return this;
    }
}
