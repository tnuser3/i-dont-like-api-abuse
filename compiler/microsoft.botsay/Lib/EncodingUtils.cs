using System.Text;

namespace Lib;

/// <summary>Byte and integer encoding utilities</summary>
public static class EncodingUtils
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string ToHex(byte[] bytes)
    {
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static byte[] FromHex(string hex)
    {
        hex = hex.Replace(" ", "");
        if (hex.Length % 2 != 0) throw new ArgumentException("Invalid hex: odd length");
        return Convert.FromHexString(hex);
    }

    public static string ToBase64(byte[] bytes) => Convert.ToBase64String(bytes);

    public static byte[] FromBase64(string b64) => Convert.FromBase64String(b64);

    public static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    public static byte[] FromBase64Url(string b64)
    {
        b64 = b64.Replace('-', '+').Replace('_', '/');
        switch (b64.Length % 4) { case 2: b64 += "=="; break; case 3: b64 += "="; break; }
        return Convert.FromBase64String(b64);
    }

    public static string ToBase32(byte[] bytes)
    {
        var sb = new StringBuilder();
        int bits = 0, value = 0;
        foreach (byte b in bytes)
        {
            value = (value << 8) | b;
            bits += 8;
            while (bits >= 5) { bits -= 5; sb.Append(Base32Alphabet[(value >> bits) & 31]); }
        }
        if (bits > 0) sb.Append(Base32Alphabet[(value << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] FromBase32(string b32)
    {
        b32 = b32.TrimEnd('=').ToUpperInvariant();
        var outList = new List<byte>();
        int bits = 0, value = 0;
        foreach (char c in b32)
        {
            int idx = Base32Alphabet.IndexOf(c);
            if (idx < 0) throw new ArgumentException($"Invalid base32: {c}");
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) { bits -= 8; outList.Add((byte)((value >> bits) & 0xff)); }
        }
        return outList.ToArray();
    }

    public static uint ReadU32BE(byte[] bytes, int offset) =>
        ((uint)bytes[offset] << 24) | ((uint)bytes[offset + 1] << 16) | ((uint)bytes[offset + 2] << 8) | bytes[offset + 3];

    public static void WriteU32BE(uint value, byte[] outBytes, int offset)
    {
        outBytes[offset] = (byte)(value >> 24);
        outBytes[offset + 1] = (byte)(value >> 16);
        outBytes[offset + 2] = (byte)(value >> 8);
        outBytes[offset + 3] = (byte)value;
    }

    public static uint ReadU32LE(byte[] bytes, int offset) =>
        bytes[offset] | ((uint)bytes[offset + 1] << 8) | ((uint)bytes[offset + 2] << 16) | ((uint)bytes[offset + 3] << 24);

    public static void WriteU32LE(uint value, byte[] outBytes, int offset)
    {
        outBytes[offset] = (byte)value;
        outBytes[offset + 1] = (byte)(value >> 8);
        outBytes[offset + 2] = (byte)(value >> 16);
        outBytes[offset + 3] = (byte)(value >> 24);
    }

    public static ulong ReadU64BE(byte[] bytes, int offset) =>
        ((ulong)ReadU32BE(bytes, offset) << 32) | ReadU32BE(bytes, offset + 4);

    public static void WriteU64BE(ulong value, byte[] outBytes, int offset)
    {
        WriteU32BE((uint)(value >> 32), outBytes, offset);
        WriteU32BE((uint)value, outBytes, offset + 4);
    }

    public static ulong ReadU64LE(byte[] bytes, int offset) =>
        ReadU32LE(bytes, offset) | ((ulong)ReadU32LE(bytes, offset + 4) << 32);

    public static void WriteU64LE(ulong value, byte[] outBytes, int offset)
    {
        WriteU32LE((uint)value, outBytes, offset);
        WriteU32LE((uint)(value >> 32), outBytes, offset + 4);
    }

    public static byte[] EncodeVarint(ulong value)
    {
        var outList = new List<byte>();
        do
        {
            byte b = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0) b |= 0x80;
            outList.Add(b);
        } while (value != 0);
        return outList.ToArray();
    }

    public static (ulong Value, int BytesRead) DecodeVarint(byte[] bytes, int offset = 0)
    {
        ulong value = 0; int shift = 0; int i = offset;
        while (i < bytes.Length)
        {
            byte b = bytes[i++];
            value |= ((ulong)(b & 0x7f)) << shift;
            if ((b & 0x80) == 0) return (value, i - offset);
            shift += 7;
            if (shift > 63) throw new OverflowException("Varint overflow");
        }
        throw new InvalidOperationException("Varint truncated");
    }
}
