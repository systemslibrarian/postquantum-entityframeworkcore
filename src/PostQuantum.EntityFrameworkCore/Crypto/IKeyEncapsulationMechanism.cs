using PostQuantum.EntityFrameworkCore.Keys;

namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// Abstraction over a post-quantum key-encapsulation mechanism (KEM), such as
/// ML-KEM-768 (FIPS 203). Encapsulation produces a fresh shared secret and a ciphertext
/// that only the holder of the private key can turn back into that shared secret.
/// </summary>
/// <remarks>
/// This abstraction lets the hybrid envelope scheme be unit-tested deterministically and
/// lets advanced hosts substitute a different KEM (or a hardware-backed one) without
/// touching the envelope format.
/// </remarks>
public interface IKeyEncapsulationMechanism
{
    /// <summary>Algorithm label written into the envelope, e.g. "ML-KEM-768".</summary>
    string AlgorithmName { get; }

    /// <summary>
    /// <see langword="true"/> when this mechanism can run on the current platform.
    /// ML-KEM, for example, requires .NET 10+ with OpenSSL 3.5+ (Linux) or a recent
    /// Windows CNG. Always check before relying on the envelope scheme.
    /// </summary>
    bool IsSupported { get; }

    /// <summary>Generates a fresh key pair for this mechanism.</summary>
    /// <param name="keyId">The id to assign to the generated pair.</param>
    KeyEncapsulationKeyPair GenerateKeyPair(string keyId);

    /// <summary>
    /// Encapsulates to a public key, returning both the ciphertext to store and the
    /// shared secret from which a data-encryption key is derived.
    /// </summary>
    EncapsulationResult Encapsulate(KeyEncapsulationKeyPair publicKey);

    /// <summary>
    /// Recovers the shared secret from a ciphertext using the private key.
    /// </summary>
    byte[] Decapsulate(KeyEncapsulationKeyPair privateKey, ReadOnlySpan<byte> ciphertext);
}

/// <summary>The output of <see cref="IKeyEncapsulationMechanism.Encapsulate"/>.</summary>
public readonly struct EncapsulationResult
{
    /// <summary>Creates a result from a ciphertext and shared secret.</summary>
    public EncapsulationResult(byte[] ciphertext, byte[] sharedSecret)
    {
        Ciphertext = ciphertext ?? throw new ArgumentNullException(nameof(ciphertext));
        SharedSecret = sharedSecret ?? throw new ArgumentNullException(nameof(sharedSecret));
    }

    /// <summary>The KEM ciphertext to persist in the envelope.</summary>
    public byte[] Ciphertext { get; }

    /// <summary>The shared secret used to derive the data-encryption key. Sensitive.</summary>
    public byte[] SharedSecret { get; }
}
