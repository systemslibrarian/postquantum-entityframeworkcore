using System.Security.Cryptography;

namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// A post-quantum key-encapsulation key pair (e.g. ML-KEM-768) used to wrap and unwrap
/// per-value data-encryption keys in the hybrid envelope scheme.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="EncapsulationKey"/> (public) is required to encrypt; the
/// <see cref="DecapsulationKey"/> (private) is required to decrypt and may be absent on
/// encrypt-only nodes that should never hold decryption capability. Private material is
/// copied on construction and zeroed on <see cref="Dispose"/>.
/// </para>
/// </remarks>
public sealed class KeyEncapsulationKeyPair : IDisposable
{
    private readonly byte[] _encapsulationKey;
    private readonly byte[]? _decapsulationKey;
    private bool _disposed;

    /// <summary>Creates a key pair from raw algorithm key bytes.</summary>
    /// <param name="keyId">Stable, non-secret identifier persisted inside each envelope.</param>
    /// <param name="algorithmName">Algorithm label, e.g. "ML-KEM-768".</param>
    /// <param name="encapsulationKey">Public encapsulation key bytes (required).</param>
    /// <param name="decapsulationKey">Private decapsulation key bytes (optional).</param>
    public KeyEncapsulationKeyPair(
        string keyId,
        string algorithmName,
        ReadOnlySpan<byte> encapsulationKey,
        ReadOnlySpan<byte> decapsulationKey = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithmName);
        if (encapsulationKey.IsEmpty)
        {
            throw new ArgumentException("An encapsulation (public) key is required.", nameof(encapsulationKey));
        }

        KeyId = keyId;
        AlgorithmName = algorithmName;
        _encapsulationKey = encapsulationKey.ToArray();
        _decapsulationKey = decapsulationKey.IsEmpty ? null : decapsulationKey.ToArray();
    }

    /// <summary>The stable, non-secret key identifier persisted inside each envelope.</summary>
    public string KeyId { get; }

    /// <summary>The algorithm label, e.g. "ML-KEM-768".</summary>
    public string AlgorithmName { get; }

    /// <summary><see langword="true"/> when this pair can decrypt (holds private material).</summary>
    public bool CanDecapsulate => _decapsulationKey is not null;

    /// <summary>The public encapsulation key bytes.</summary>
    internal ReadOnlySpan<byte> EncapsulationKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _encapsulationKey;
        }
    }

    /// <summary>The private decapsulation key bytes.</summary>
    /// <exception cref="InvalidOperationException">This pair holds no private material.</exception>
    internal ReadOnlySpan<byte> DecapsulationKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_decapsulationKey is null)
            {
                throw new InvalidOperationException(
                    $"Key pair '{KeyId}' has no decapsulation (private) key and cannot decrypt.");
            }

            return _decapsulationKey;
        }
    }

    /// <summary>Zeroes any private key material.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_decapsulationKey is not null)
        {
            CryptographicOperations.ZeroMemory(_decapsulationKey);
        }

        _disposed = true;
    }
}
