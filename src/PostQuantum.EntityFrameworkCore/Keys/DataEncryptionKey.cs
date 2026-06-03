using System.Security.Cryptography;

namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// A symmetric data-encryption key (DEK) and its stable identifier.
/// </summary>
/// <remarks>
/// <para>
/// The 32-byte (256-bit) key material is copied on construction and zeroed on
/// <see cref="Dispose"/> via <see cref="CryptographicOperations.ZeroMemory"/>. Treat
/// instances as sensitive: do not log them, serialize them, or keep references longer
/// than necessary. The <see cref="KeyId"/> is non-secret and is stored in plaintext
/// inside every envelope so that the correct key can be selected for decryption,
/// including after rotation.
/// </para>
/// </remarks>
public sealed class DataEncryptionKey : IDisposable
{
    /// <summary>Required key length in bytes (256 bits) for AES-256-GCM.</summary>
    public const int KeySizeInBytes = 32;

    private readonly byte[] _material;
    private bool _disposed;

    /// <summary>
    /// Creates a key from existing 256-bit material. The bytes are copied; the caller
    /// retains ownership of the input array.
    /// </summary>
    /// <param name="keyId">Stable, non-secret identifier (e.g. "dek-2026-01").</param>
    /// <param name="material">Exactly 32 bytes of key material.</param>
    public DataEncryptionKey(string keyId, ReadOnlySpan<byte> material)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (material.Length != KeySizeInBytes)
        {
            throw new ArgumentException(
                $"A data-encryption key must be exactly {KeySizeInBytes} bytes ({KeySizeInBytes * 8} bits).",
                nameof(material));
        }

        KeyId = keyId;
        _material = material.ToArray();
    }

    /// <summary>The stable, non-secret key identifier persisted inside each envelope.</summary>
    public string KeyId { get; }

    /// <summary>
    /// Generates a new key with cryptographically secure random material.
    /// </summary>
    public static DataEncryptionKey Generate(string keyId)
    {
        Span<byte> material = stackalloc byte[KeySizeInBytes];
        RandomNumberGenerator.Fill(material);
        try
        {
            return new DataEncryptionKey(keyId, material);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }

    /// <summary>
    /// Exposes the raw key material for cryptographic use. Internal by design so that
    /// secret bytes are never part of the public API surface.
    /// </summary>
    internal ReadOnlySpan<byte> Material
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _material;
        }
    }

    /// <summary>Zeroes the key material.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_material);
        _disposed = true;
    }
}
