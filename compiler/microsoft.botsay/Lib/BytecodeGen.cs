using System.Security.Cryptography;
using System.Text.Json;

namespace Lib;

public static class BytecodeGen
{
    public static readonly string[] Actions =
    {
        "vm_apply", "vm_apply_inv", "xor_buf", "xor_inplace", "crc32", "adler32", "xor_checksum",
        "to_hex", "from_hex", "read_u32be", "write_u32be", "read_u32le", "write_u32le",
        "rotl32", "rotr32", "swap32", "get_bit", "set_bit", "chacha_decrypt",
    };

    static void SecureShuffle(byte[] arr)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        for (int i = arr.Length - 1; i > 0; i--)
        {
            int j = SecureRandomIndex(rng, bytes, i + 1);
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
    }

    static int SecureRandomIndex(RandomNumberGenerator rng, byte[] bytes, int maxExclusive)
    {
        if (maxExclusive <= 1) return 0;
        uint max = (uint)maxExclusive;
        uint threshold = uint.MaxValue - uint.MaxValue % max;
        uint r;
        do
        {
            rng.GetBytes(bytes);
            r = BitConverter.ToUInt32(bytes);
        }
        while (r >= threshold);
        return (int)(r % max);
    }

    public static (byte[] OpcodeAction, byte[] Vm, byte[] VmInv, Dictionary<string, string> Mapping) Generate()
    {
        var all = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        SecureShuffle(all);
        var pool = all.Take(Actions.Length).ToArray();

        if (pool.Distinct().Count() != pool.Length)
            throw new InvalidOperationException("Opcode collision: each action must have a unique byte.");

        var mapping = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < Actions.Length; i++)
            mapping[$"0x{pool[i]:x2}"] = Actions[i];

        var opcodeAction = new byte[256];
        Array.Fill(opcodeAction, (byte)255);
        for (int i = 0; i < Actions.Length; i++)
            opcodeAction[pool[i]] = (byte)i;

        var vm = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
        SecureShuffle(vm);
        var vmInv = new byte[256];
        for (int i = 0; i < 256; i++)
            vmInv[vm[i]] = (byte)i;

        return (opcodeAction, vm, vmInv, mapping);
    }

    public static void WriteBytecodesJson(string buildDir, byte[] opcodeAction, byte[] vm, byte[] vmInv, Dictionary<string, string> mapping)
    {
        var jsonData = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
        {
            ["bytecodes"] = mapping,
            ["opcode_action"] = opcodeAction.Select(b => (int)b).ToArray(),
            ["vm"] = vm.Select(b => (int)b).ToArray(),
            ["vm_inv"] = vmInv.Select(b => (int)b).ToArray(),
        };
        var jsonPath = Path.Combine(buildDir, "bytecodes.json");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(jsonData, new JsonSerializerOptions { WriteIndented = true }) + "\n");
        Console.WriteLine($"Generated {jsonPath}");
    }
}
