using System.Security.Cryptography;
using PostQuantum.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.Keys;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>Shared helpers for constructing protectors and key rings in tests.</summary>
internal static class TestKeys
{
    /// <summary>Builds an AES-256-GCM protector over an in-memory key ring with one random key.</summary>
    internal static IPostQuantumProtector AesProtector(out DataEncryptionKey key, string keyId = "dek-test-1")
    {
        key = DataEncryptionKey.Generate(keyId);
        var ring = new InMemoryDataProtectionKeyRing(key);
        return new PostQuantumProtector([new Aes256GcmSchemeHandler(ring)], EncryptionScheme.Aes256Gcm);
    }

    /// <summary>Builds an AES-256-GCM protector and discards the key handle.</summary>
    internal static IPostQuantumProtector AesProtector() => AesProtector(out _);

    /// <summary>Builds a hybrid-envelope protector over the supplied (typically fake) KEM.</summary>
    internal static IPostQuantumProtector EnvelopeProtector(
        IKeyEncapsulationMechanism kem,
        string keyId = "kek-test-1")
    {
        KeyEncapsulationKeyPair pair = kem.GenerateKeyPair(keyId);
        var ring = new InMemoryKeyEncapsulationKeyRing(pair);
        return new PostQuantumProtector(
            [new MLKemEnvelopeSchemeHandler(ring, kem)],
            EncryptionScheme.MLKem768Aes256Gcm);
    }
}

/// <summary>
/// A deterministic, INSECURE key-encapsulation mechanism used only to exercise the hybrid
/// envelope format on every platform, including those without real ML-KEM support.
/// </summary>
/// <remarks>
/// It models a KEM faithfully — fresh ciphertext per encapsulation, a shared secret only
/// recoverable with the private key — without providing any real security. Never use in
/// production.
/// </remarks>
internal sealed class FakeKeyEncapsulationMechanism : IKeyEncapsulationMechanism
{
    private const int SeedSize = 32;
    private const int CiphertextSize = 48;

    public string AlgorithmName => "FAKE-KEM-FOR-TESTS";

    public bool IsSupported => true;

    public KeyEncapsulationKeyPair GenerateKeyPair(string keyId)
    {
        // The "public" and "private" keys are the same secret seed; sufficient for a
        // deterministic test KEM where only the seed holder can derive the shared secret.
        Span<byte> seed = stackalloc byte[SeedSize];
        RandomNumberGenerator.Fill(seed);
        return new KeyEncapsulationKeyPair(keyId, AlgorithmName, seed, seed);
    }

    public EncapsulationResult Encapsulate(KeyEncapsulationKeyPair publicKey)
    {
        var ciphertext = new byte[CiphertextSize];
        RandomNumberGenerator.Fill(ciphertext);
        byte[] sharedSecret = DeriveSecret(publicKey.EncapsulationKey, ciphertext);
        return new EncapsulationResult(ciphertext, sharedSecret);
    }

    public byte[] Decapsulate(KeyEncapsulationKeyPair privateKey, ReadOnlySpan<byte> ciphertext)
        => DeriveSecret(privateKey.DecapsulationKey, ciphertext);

    private static byte[] DeriveSecret(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> ciphertext)
    {
        Span<byte> buffer = stackalloc byte[SeedSize + CiphertextSize];
        seed.CopyTo(buffer);
        ciphertext.CopyTo(buffer[SeedSize..]);
        return SHA256.HashData(buffer);
    }
}
