using System.Security.Cryptography;

namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// AES-256-GCM authenticated encryption with a random 96-bit nonce and 128-bit tag,
/// used as the data-encryption layer ("DEM") by every scheme in this library.
/// </summary>
/// <remarks>
/// <para>The produced body is laid out as <c>nonce(12) || tag(16) || ciphertext(n)</c>.</para>
/// <para>
/// A fresh random nonce is generated per call. With 96-bit random nonces the birthday
/// bound recommends re-keying well before 2^32 messages share a single key; rotate the
/// data-encryption key long before that. GCM authenticates both the ciphertext and the
/// supplied associated data (the envelope header), so any tampering with the scheme id,
/// key id, version, or ciphertext fails authentication.
/// </para>
/// </remarks>
internal static class AuthenticatedCipher
{
    internal const int NonceSizeInBytes = 12;
    internal const int TagSizeInBytes = 16;
    internal const int KeySizeInBytes = 32;
    internal const int OverheadInBytes = NonceSizeInBytes + TagSizeInBytes;

    /// <summary>Encrypts <paramref name="plaintext"/>, returning <c>nonce || tag || ciphertext</c>.</summary>
    internal static byte[] Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != KeySizeInBytes)
        {
            throw new PostQuantumCryptographicException("Data-encryption key must be 256 bits.");
        }

        var body = new byte[OverheadInBytes + plaintext.Length];
        Span<byte> nonce = body.AsSpan(0, NonceSizeInBytes);
        Span<byte> tag = body.AsSpan(NonceSizeInBytes, TagSizeInBytes);
        Span<byte> ciphertext = body.AsSpan(OverheadInBytes);

        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key, TagSizeInBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return body;
    }

    /// <summary>Authenticates and decrypts a <c>nonce || tag || ciphertext</c> body.</summary>
    /// <exception cref="PostQuantumCryptographicException">
    /// The body is malformed or authentication fails (tampering, corruption, or wrong key).
    /// </exception>
    internal static byte[] Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> body,
        ReadOnlySpan<byte> associatedData)
    {
        if (key.Length != KeySizeInBytes)
        {
            throw new PostQuantumCryptographicException("Data-encryption key must be 256 bits.");
        }

        if (body.Length < OverheadInBytes)
        {
            throw new PostQuantumCryptographicException("Encrypted body is too short to contain a nonce and tag.");
        }

        ReadOnlySpan<byte> nonce = body.Slice(0, NonceSizeInBytes);
        ReadOnlySpan<byte> tag = body.Slice(NonceSizeInBytes, TagSizeInBytes);
        ReadOnlySpan<byte> ciphertext = body[OverheadInBytes..];
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSizeInBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException ex)
        {
            // Do not leak which check failed; a generic failure avoids a padding/tag oracle.
            CryptographicOperations.ZeroMemory(plaintext);
            throw new PostQuantumCryptographicException(
                "Decryption failed: the data could not be authenticated. This indicates tampering, " +
                "corruption, or use of the wrong key.", ex);
        }
    }
}
