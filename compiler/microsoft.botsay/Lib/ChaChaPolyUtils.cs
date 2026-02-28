using System.Security.Cryptography;

namespace Lib;

public static class ChaChaPolyUtils
{
    public const int KeyLength = 32;
    public const int IvLength = 12;
    public const int AuthTagLength = 16;

    public static (byte[] Ciphertext, byte[] AuthTag, byte[] Iv) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[]? aad = null,
        byte[]? iv = null)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Key must be {KeyLength} bytes");
        iv ??= RandomNumberGenerator.GetBytes(IvLength);

        using var aead = new ChaCha20Poly1305(key);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AuthTagLength];

        aead.Encrypt(iv, plaintext, ciphertext, tag, aad);

        return (ciphertext, tag, iv);
    }

    public static byte[] Decrypt(
        byte[] key,
        byte[] ciphertext,
        byte[] authTag,
        byte[] iv,
        byte[]? aad = null)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Key must be {KeyLength} bytes");
        if (iv.Length != IvLength)
            throw new ArgumentException($"IV must be {IvLength} bytes");
        if (authTag.Length != AuthTagLength)
            throw new ArgumentException($"Auth tag must be {AuthTagLength} bytes");

        using var aead = new ChaCha20Poly1305(key);
        byte[] plaintext = new byte[ciphertext.Length];
        aead.Decrypt(iv, ciphertext, authTag, plaintext, aad);
        return plaintext;
    }

    public static byte[] PackResult(byte[] ciphertext, byte[] authTag, byte[] iv)
    {
        var outArr = new byte[iv.Length + ciphertext.Length + authTag.Length];
        Buffer.BlockCopy(iv, 0, outArr, 0, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, outArr, iv.Length, ciphertext.Length);
        Buffer.BlockCopy(authTag, 0, outArr, iv.Length + ciphertext.Length, authTag.Length);
        return outArr;
    }

    public static (byte[] Iv, byte[] Ciphertext, byte[] AuthTag) UnpackResult(byte[] packed)
    {
        if (packed.Length < IvLength + AuthTagLength)
            throw new ArgumentException("Packed buffer too short");
        var iv = new byte[IvLength];
        var authTag = new byte[AuthTagLength];
        var ciphertext = new byte[packed.Length - IvLength - AuthTagLength];
        Buffer.BlockCopy(packed, 0, iv, 0, IvLength);
        Buffer.BlockCopy(packed, IvLength, ciphertext, 0, ciphertext.Length);
        Buffer.BlockCopy(packed, packed.Length - AuthTagLength, authTag, 0, AuthTagLength);
        return (iv, ciphertext, authTag);
    }

    public static byte[] EncryptPacked(byte[] key, byte[] plaintext, byte[]? aad = null)
    {
        var (ciphertext, authTag, iv) = Encrypt(key, plaintext, aad);
        return PackResult(ciphertext, authTag, iv);
    }

    public static byte[] DecryptPacked(byte[] key, byte[] packed, byte[]? aad = null)
    {
        var (iv, ciphertext, authTag) = UnpackResult(packed);
        return Decrypt(key, ciphertext, authTag, iv, aad);
    }
}
