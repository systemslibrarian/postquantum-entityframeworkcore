using System.Security.Cryptography;
using PostQuantum.EntityFrameworkCore.Keys;

namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// An <see cref="IKeyEncapsulationMechanism"/> backed by ML-KEM-768 (FIPS 203) from
/// <see cref="System.Security.Cryptography"/>.
/// </summary>
/// <remarks>
/// <para>
/// ML-KEM support is a <b>.NET 10+ runtime feature</b> that additionally requires an
/// underlying provider: OpenSSL 3.5+ on Linux/macOS, or a sufficiently recent Windows
/// CNG. On older target frameworks, or where the platform provider is unavailable,
/// <see cref="IsSupported"/> is <see langword="false"/> and every operation throws a
/// clear <see cref="PlatformNotSupportedException"/> rather than silently degrading.
/// </para>
/// <para>
/// Always gate use of the envelope scheme on <see cref="IsSupported"/>. The AES-256-GCM
/// scheme has no such requirement and works on every supported target framework.
/// </para>
/// </remarks>
public sealed class MLKemKeyEncapsulationMechanism : IKeyEncapsulationMechanism
{
    /// <summary>The canonical algorithm label written into envelopes.</summary>
    public const string Algorithm = "ML-KEM-768";

    /// <inheritdoc />
    public string AlgorithmName => Algorithm;

    /// <inheritdoc />
    public bool IsSupported =>
#if NET10_0_OR_GREATER
        MLKem.IsSupported;
#else
        false;
#endif

    /// <inheritdoc />
    public KeyEncapsulationKeyPair GenerateKeyPair(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
#if NET10_0_OR_GREATER
        EnsureSupported();
        using MLKem kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        byte[] encapsulationKey = kem.ExportEncapsulationKey();
        byte[] decapsulationKey = kem.ExportDecapsulationKey();
        try
        {
            return new KeyEncapsulationKeyPair(keyId, Algorithm, encapsulationKey, decapsulationKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decapsulationKey);
        }
#else
        throw Unsupported();
#endif
    }

    /// <inheritdoc />
    public EncapsulationResult Encapsulate(KeyEncapsulationKeyPair publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        RequireAlgorithm(publicKey);
#if NET10_0_OR_GREATER
        EnsureSupported();
        using MLKem kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, publicKey.EncapsulationKey);
        kem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
        return new EncapsulationResult(ciphertext, sharedSecret);
#else
        throw Unsupported();
#endif
    }

    /// <inheritdoc />
    public byte[] Decapsulate(KeyEncapsulationKeyPair privateKey, ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        RequireAlgorithm(privateKey);
#if NET10_0_OR_GREATER
        EnsureSupported();
        byte[] decapsulationKey = privateKey.DecapsulationKey.ToArray();
        try
        {
            using MLKem kem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, decapsulationKey);
            return kem.Decapsulate(ciphertext.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decapsulationKey);
        }
#else
        throw Unsupported();
#endif
    }

    private static void RequireAlgorithm(KeyEncapsulationKeyPair key)
    {
        if (!string.Equals(key.AlgorithmName, Algorithm, StringComparison.Ordinal))
        {
            throw new PostQuantumCryptographicException(
                $"Key '{key.KeyId}' is for algorithm '{key.AlgorithmName}', not '{Algorithm}'.");
        }
    }

#if NET10_0_OR_GREATER
    private void EnsureSupported()
    {
        if (!IsSupported)
        {
            throw Unsupported();
        }
    }
#endif

    private static PlatformNotSupportedException Unsupported() => new(
        "ML-KEM is unavailable on this platform. It requires .NET 10 or later with " +
        "OpenSSL 3.5+ (Linux/macOS) or a recent Windows CNG. Use the AES-256-GCM scheme, " +
        "or run on a platform with post-quantum support. See KNOWN-GAPS.md.");
}
