namespace Lib;

public static class ChecksumUtils
{
    private static readonly uint[]? Crc32Table;

    static ChecksumUtils()
    {
        var table = new uint[256];
        const uint poly = 0xedb88320;
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? (c >> 1) ^ poly : c >> 1;
            table[i] = c;
        }
        Crc32Table = table;
    }

    public static uint Crc32(byte[] bytes)
    {
        uint crc = 0xffffffff;
        foreach (byte b in bytes)
            crc = (crc >> 8) ^ Crc32Table![(crc ^ b) & 0xff];
        return crc ^ 0xffffffff;
    }

    public static uint Crc32WithInit(byte[] bytes, uint init)
    {
        uint crc = init ^ 0xffffffff;
        foreach (byte b in bytes)
            crc = (crc >> 8) ^ Crc32Table![(crc ^ b) & 0xff];
        return crc ^ 0xffffffff;
    }

    public static uint Adler32(byte[] bytes)
    {
        const uint mod = 65521;
        uint a = 1, b = 0;
        foreach (byte x in bytes)
        {
            a = (a + x) % mod;
            b = (b + a) % mod;
        }
        return (b << 16) | a;
    }

    public static ushort Fletcher16(byte[] bytes)
    {
        uint sum1 = 0, sum2 = 0;
        foreach (byte x in bytes)
        {
            sum1 = (sum1 + x) % 255;
            sum2 = (sum2 + sum1) % 255;
        }
        return (ushort)((sum2 << 8) | sum1);
    }

    public static uint Fletcher32(byte[] bytes)
    {
        const uint mod = 0xffff;
        uint sum1 = 0, sum2 = 0;
        for (int i = 0; i < bytes.Length; i += 2)
        {
            uint word = i + 1 < bytes.Length
                ? (uint)((bytes[i] << 8) | bytes[i + 1])
                : (uint)(bytes[i] << 8);
            sum1 = (sum1 + word) % mod;
            sum2 = (sum2 + sum1) % mod;
        }
        return (sum2 << 16) | sum1;
    }

    public static byte XorChecksum(byte[] bytes)
    {
        byte sum = 0;
        foreach (byte x in bytes) sum ^= x;
        return sum;
    }

    public static ushort Sum16(byte[] bytes)
    {
        uint sum = 0;
        for (int i = 0; i < bytes.Length; i += 2)
        {
            uint word = i + 1 < bytes.Length
                ? (uint)((bytes[i] << 8) | bytes[i + 1])
                : (uint)(bytes[i] << 8);
            sum += word;
        }
        return (ushort)(sum & 0xffff);
    }
}
