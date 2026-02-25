namespace Lib;

/// <summary>S-box utilities. Regenerated at build time; falls back to GF(2^8) computation if generated file missing.</summary>
public static partial class SboxUtils
{
    public static byte[] AesSbox => GenerateAesSbox();
    public static byte[] AesInvSbox => InvertSbox(AesSbox);

    private static byte[]? _aesSbox;
    private static byte[]? _aesInvSbox;

    /// <summary>Generate AES S-box from GF(2^8) multiplicative inverse + affine transform (Rijndael definition)</summary>
    private static byte[] GenerateAesSbox()
    {
        var sbox = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            byte inv = Gf256Inv((byte)i);
            sbox[i] = Affine(inv);
        }
        return sbox;
    }

    /// <summary>Multiplicative inverse in GF(2^8) with irreducible poly 0x11b. inv(0)=0.</summary>
    private static byte Gf256Inv(byte x)
    {
        if (x == 0) return 0;
        byte r = x;
        for (int i = 0; i < 253; i++)
            r = Gf256Mul(r, x);
        return r;
    }

    private static byte Gf256Mul(byte a, byte b)
    {
        byte p = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0) p ^= a;
            bool hi = (a & 0x80) != 0;
            a = (byte)((a << 1) & 0xff);
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    /// <summary>Rijndael affine: y = x ^ rot(x,1) ^ rot(x,2) ^ rot(x,3) ^ rot(x,4) ^ 0x63</summary>
    private static byte Affine(byte x) =>
        (byte)(x ^ Rotl8(x, 1) ^ Rotl8(x, 2) ^ Rotl8(x, 3) ^ Rotl8(x, 4) ^ 0x63);

    private static byte Rotl8(byte x, int n) => (byte)((x << n) | (x >> (8 - n)));

    public static byte[] ApplySbox(byte[] bytes, byte[] sbox, bool inPlace = false)
    {
        var outArr = inPlace ? bytes : (byte[])bytes.Clone();
        for (int i = 0; i < outArr.Length; i++) outArr[i] = sbox[outArr[i]];
        return outArr;
    }

    public static byte[] SboxForward(byte[] bytes, bool inPlace = false) =>
        ApplySbox(bytes, AesSbox, inPlace);

    public static byte[] SboxInverse(byte[] bytes, bool inPlace = false) =>
        ApplySbox(bytes, AesInvSbox, inPlace);

    public static byte[] InvertSbox(byte[] sbox)
    {
        var inv = new byte[256];
        for (int i = 0; i < 256; i++) inv[sbox[i]] = (byte)i;
        return inv;
    }
}
