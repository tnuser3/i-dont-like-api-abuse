namespace Lib;

/// <summary>Bitwise utilities</summary>
public static class BitwiseUtils
{
    public static void XorInPlace(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("XOR: buffers must be same length");
        for (int i = 0; i < a.Length; i++) a[i] ^= b[i];
    }

    public static byte[] Xor(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("XOR: buffers must be same length");
        var outArr = new byte[a.Length];
        for (int i = 0; i < a.Length; i++) outArr[i] = (byte)(a[i] ^ b[i]);
        return outArr;
    }

    public static uint Rotl32(uint value, int n)
    {
        n &= 31;
        return (value << n) | (value >> (32 - n));
    }

    public static uint Rotr32(uint value, int n)
    {
        n &= 31;
        return (value >> n) | (value << (32 - n));
    }

    public static ulong Rotl64(ulong value, int n)
    {
        n &= 63;
        return (value << n) | (value >> (64 - n));
    }

    public static ulong Rotr64(ulong value, int n)
    {
        n &= 63;
        return (value >> n) | (value << (64 - n));
    }

    public static uint Swap32(uint value) =>
        ((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value & 0xff0000) >> 8) | ((value & 0xff000000) >> 24);

    public static int GetBit(uint value, int bit) => (int)((value >> bit) & 1);

    public static uint SetBit(uint value, int bit, bool on) =>
        on ? value | (1u << bit) : value & ~(1u << bit);

    public static int Clz32(uint value)
    {
        if (value == 0) return 32;
        int n = 0;
        if ((value & 0xffff0000) == 0) { n += 16; value <<= 16; }
        if ((value & 0xff000000) == 0) { n += 8; value <<= 8; }
        if ((value & 0xf0000000) == 0) { n += 4; value <<= 4; }
        if ((value & 0xc0000000) == 0) { n += 2; value <<= 2; }
        if ((value & 0x80000000) == 0) n++;
        return n;
    }

    public static int Ctz32(uint value)
    {
        if (value == 0) return 32;
        int n = 0;
        if ((value & 0x0000ffff) == 0) { n += 16; value >>= 16; }
        if ((value & 0x000000ff) == 0) { n += 8; value >>= 8; }
        if ((value & 0x0000000f) == 0) { n += 4; value >>= 4; }
        if ((value & 0x00000003) == 0) { n += 2; value >>= 2; }
        if ((value & 0x00000001) == 0) n++;
        return n;
    }

    public static int Popcount32(uint value)
    {
        value -= (value >> 1) & 0x55555555;
        value = (value & 0x33333333) + ((value >> 2) & 0x33333333);
        value = (value + (value >> 4)) & 0x0f0f0f0f;
        return (int)((value * 0x01010101) >> 24);
    }
}
