using Microsoft.Extensions.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Verifies that a protector whose default scheme cannot run on this platform fails at
/// construction (startup) rather than on the first encrypt.
/// </summary>
public class FailFastValidationTests
{
    [Fact]
    public void Constructing_with_an_unsupported_default_kem_throws_platform_not_supported()
    {
        var kem = new UnsupportedKeyEncapsulationMechanism();
        var pair = new KeyEncapsulationKeyPair("kek-1", kem.AlgorithmName, new byte[32]);
        var ring = new InMemoryKeyEncapsulationKeyRing(pair);

        PlatformNotSupportedException ex = Assert.Throws<PlatformNotSupportedException>(() =>
            new PostQuantumProtector(
                [new MLKemEnvelopeSchemeHandler(ring, kem)],
                EncryptionScheme.MLKem768Aes256Gcm));

        Assert.Contains("platform", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_supported_default_scheme_constructs_normally()
    {
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(new FakeKeyEncapsulationMechanism());
        Assert.Equal(EncryptionScheme.MLKem768Aes256Gcm, protector.DefaultScheme);
    }

    [Fact]
    public void Unsupported_kem_as_non_default_does_not_block_an_aes_default()
    {
        // ML-KEM registered only to read legacy values; AES is the default for new writes.
        // Validation only touches the default scheme, so an unsupported ML-KEM must not throw.
        using DataEncryptionKey dek = DataEncryptionKey.Generate("dek-1");
        var kem = new UnsupportedKeyEncapsulationMechanism();
        var pair = new KeyEncapsulationKeyPair("kek-1", kem.AlgorithmName, new byte[32]);

        var protector = new PostQuantumProtector(
            [
                new MLKemEnvelopeSchemeHandler(new InMemoryKeyEncapsulationKeyRing(pair), kem),
                new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(dek)),
            ],
            EncryptionScheme.Aes256Gcm);

        Assert.Equal("ok", protector.UnprotectText(protector.ProtectText("ok")));
    }

    [Fact]
    public void Resolving_from_di_with_unsupported_default_kem_throws_platform_not_supported()
    {
        var kem = new UnsupportedKeyEncapsulationMechanism();
        var pair = new KeyEncapsulationKeyPair("kek-1", kem.AlgorithmName, new byte[32]);

        var services = new ServiceCollection();
        services.AddPostQuantumEncryption(pq =>
        {
            pq.UseKeyEncapsulationMechanism(kem);
            pq.UseMLKem768Envelope(new InMemoryKeyEncapsulationKeyRing(pair));
        });

        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Throws<PlatformNotSupportedException>(
            () => provider.GetRequiredService<IPostQuantumProtector>());
    }
}

/// <summary>A KEM that reports itself unavailable, modelling a platform without ML-KEM.</summary>
internal sealed class UnsupportedKeyEncapsulationMechanism : IKeyEncapsulationMechanism
{
    public string AlgorithmName => "ML-KEM-768";

    public bool IsSupported => false;

    public KeyEncapsulationKeyPair GenerateKeyPair(string keyId) => throw new PlatformNotSupportedException();

    public EncapsulationResult Encapsulate(KeyEncapsulationKeyPair publicKey) => throw new PlatformNotSupportedException();

    public byte[] Decapsulate(KeyEncapsulationKeyPair privateKey, ReadOnlySpan<byte> ciphertext) =>
        throw new PlatformNotSupportedException();
}
