using System.Security.Cryptography;
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
    public void Envelope_unprotect_wraps_kem_failure_when_ciphertext_length_is_tampered()
    {
        // A real KEM (ML-KEM) rejects a wrong-sized ciphertext with a raw ArgumentException.
        // The 2-byte length marker sits in the body, outside the AEAD associated data, so a
        // tamperer can resize the KEM ciphertext. The handler must fail closed with its own
        // exception rather than let the raw one escape and crash the query thread.
        var kem = new LengthStrictKeyEncapsulationMechanism();
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(kem);
        byte[] envelope = protector.ProtectText("sensitive");

        // The body begins right after the authenticated header; its first two bytes are the
        // big-endian KEM-ciphertext length. Shrink it by one so the KEM sees a short ciphertext.
        int lengthOffset = EncryptedEnvelope.Parse(envelope).AssociatedData.Length;
        int declared = (envelope[lengthOffset] << 8) | envelope[lengthOffset + 1];
        int tampered = declared - 1;
        envelope[lengthOffset] = (byte)(tampered >> 8);
        envelope[lengthOffset + 1] = (byte)tampered;

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

/// <summary>
/// A deterministic test KEM that, like real ML-KEM, rejects a wrong-sized ciphertext with a
/// raw <see cref="ArgumentException"/>. Used to prove the envelope handler converts that into
/// a <see cref="PostQuantumCryptographicException"/> instead of letting it escape.
/// </summary>
internal sealed class LengthStrictKeyEncapsulationMechanism : IKeyEncapsulationMechanism
{
    private const int SeedSize = 32;
    private const int CiphertextSize = 48;

    public string AlgorithmName => "FAKE-STRICT-KEM-FOR-TESTS";

    public bool IsSupported => true;

    public KeyEncapsulationKeyPair GenerateKeyPair(string keyId)
    {
        Span<byte> seed = stackalloc byte[SeedSize];
        RandomNumberGenerator.Fill(seed);
        return new KeyEncapsulationKeyPair(keyId, AlgorithmName, seed, seed);
    }

    public EncapsulationResult Encapsulate(KeyEncapsulationKeyPair publicKey)
    {
        var ciphertext = new byte[CiphertextSize];
        RandomNumberGenerator.Fill(ciphertext);
        return new EncapsulationResult(ciphertext, DeriveSecret(publicKey.EncapsulationKey, ciphertext));
    }

    public byte[] Decapsulate(KeyEncapsulationKeyPair privateKey, ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length != CiphertextSize)
        {
            throw new ArgumentException("Ciphertext is not the correct size.", nameof(ciphertext));
        }

        return DeriveSecret(privateKey.DecapsulationKey, ciphertext);
    }

    private static byte[] DeriveSecret(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> ciphertext)
    {
        Span<byte> buffer = stackalloc byte[SeedSize + CiphertextSize];
        seed.CopyTo(buffer);
        ciphertext.CopyTo(buffer[SeedSize..]);
        return SHA256.HashData(buffer);
    }
}
