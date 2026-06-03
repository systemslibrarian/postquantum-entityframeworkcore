using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Exercises the hybrid KEM/DEM envelope format using a deterministic fake KEM so the
/// envelope logic is covered on every platform. Real ML-KEM is covered separately in
/// <see cref="RealMLKemTests"/> where the platform supports it.
/// </summary>
public class MLKemEnvelopeSchemeTests
{
    [Theory]
    [InlineData("medical-record-42")]
    [InlineData("")]
    [InlineData("multi-byte ✅ secret")]
    public void Envelope_protect_then_unprotect_returns_original(string plaintext)
    {
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(new FakeKeyEncapsulationMechanism());

        byte[] envelope = protector.ProtectText(plaintext);

        Assert.Equal(EncryptionScheme.MLKem768Aes256Gcm, EncryptedEnvelope.Parse(envelope).Scheme);
        Assert.Equal(plaintext, protector.UnprotectText(envelope));
    }

    [Fact]
    public void Envelope_uses_fresh_encapsulation_so_identical_plaintext_differs()
    {
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(new FakeKeyEncapsulationMechanism());

        byte[] first = protector.ProtectText("same");
        byte[] second = protector.ProtectText("same");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Envelope_unprotect_fails_when_ciphertext_is_tampered()
    {
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(new FakeKeyEncapsulationMechanism());
        byte[] envelope = protector.ProtectText("sensitive");

        envelope[^1] ^= 0xFF;

        Assert.Throws<PostQuantumCryptographicException>(() => protector.UnprotectText(envelope));
    }

    [Fact]
    public void Envelope_unprotect_fails_when_the_key_lacks_private_material()
    {
        var kem = new FakeKeyEncapsulationMechanism();
        KeyEncapsulationKeyPair fullPair = kem.GenerateKeyPair("kek-1");

        // A public-only pair: cannot decrypt.
        var publicOnly = new KeyEncapsulationKeyPair("kek-1", fullPair.AlgorithmName, fullPair.EncapsulationKey);

        var encryptProtector = new PostQuantumProtector(
            [new MLKemEnvelopeSchemeHandler(new InMemoryKeyEncapsulationKeyRing(fullPair), kem)],
            EncryptionScheme.MLKem768Aes256Gcm);
        byte[] envelope = encryptProtector.ProtectText("secret");

        var decryptProtector = new PostQuantumProtector(
            [new MLKemEnvelopeSchemeHandler(new InMemoryKeyEncapsulationKeyRing(publicOnly), kem)],
            EncryptionScheme.MLKem768Aes256Gcm);

        PostQuantumCryptographicException ex = Assert.Throws<PostQuantumCryptographicException>(
            () => decryptProtector.UnprotectText(envelope));
        Assert.Contains("private", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Protector_can_decrypt_both_schemes_during_a_migration()
    {
        using var dek = DataEncryptionKey.Generate("dek-legacy");
        var kem = new FakeKeyEncapsulationMechanism();
        KeyEncapsulationKeyPair kek = kem.GenerateKeyPair("kek-new");

        // Default to the post-quantum envelope, but keep the AES handler for legacy values.
        var protector = new PostQuantumProtector(
            [
                new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(dek)),
                new MLKemEnvelopeSchemeHandler(new InMemoryKeyEncapsulationKeyRing(kek), kem),
            ],
            EncryptionScheme.MLKem768Aes256Gcm);

        // A value written under the legacy AES scheme.
        var legacyOnly = new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(dek))],
            EncryptionScheme.Aes256Gcm);
        byte[] legacy = legacyOnly.ProtectText("old-value");

        byte[] modern = protector.ProtectText("new-value");

        Assert.Equal(EncryptionScheme.MLKem768Aes256Gcm, EncryptedEnvelope.Parse(modern).Scheme);
        Assert.Equal("old-value", protector.UnprotectText(legacy));
        Assert.Equal("new-value", protector.UnprotectText(modern));
    }
}
