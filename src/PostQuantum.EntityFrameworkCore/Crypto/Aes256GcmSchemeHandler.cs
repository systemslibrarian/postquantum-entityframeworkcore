using PostQuantum.EntityFrameworkCore.Keys;

namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// Implements <see cref="EncryptionScheme.Aes256Gcm"/>: the data-encryption key is taken
/// directly from an <see cref="IDataProtectionKeyRing"/> and used with AES-256-GCM.
/// </summary>
internal sealed class Aes256GcmSchemeHandler : IEncryptionSchemeHandler
{
    private readonly IDataProtectionKeyRing _keyRing;

    internal Aes256GcmSchemeHandler(IDataProtectionKeyRing keyRing)
    {
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
    }

    public EncryptionScheme Scheme => EncryptionScheme.Aes256Gcm;

    public void ValidateReady()
    {
        // Resolving the active key proves the ring is wired up and has a usable DEK.
        DataEncryptionKey active = _keyRing.ActiveKey
            ?? throw new PostQuantumCryptographicException(
                "The data-protection key ring returned no active key for the AES-256-GCM scheme.");
        _ = active.KeyId;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        DataEncryptionKey key = _keyRing.ActiveKey;
        byte[] header = EncryptedEnvelope.WriteHeader(Scheme, key.KeyId);
        byte[] body = AuthenticatedCipher.Encrypt(key.Material, plaintext, header);
        return Concat(header, body);
    }

    public byte[] Decrypt(string keyId, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> body)
    {
        DataEncryptionKey key = _keyRing.Find(keyId)
            ?? throw new PostQuantumCryptographicException(
                $"No data-encryption key with id '{keyId}' is available to decrypt this value.");

        return AuthenticatedCipher.Decrypt(key.Material, body.Span, associatedData.Span);
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result.AsSpan());
        second.CopyTo(result.AsSpan(first.Length));
        return result;
    }
}
