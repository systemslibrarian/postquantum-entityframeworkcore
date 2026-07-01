using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Covers the version-2 hybrid envelope, which folds the KEM encapsulation block into the
/// AES-GCM associated data so the whole encapsulation is authenticated, while still reading
/// version-1 hybrid envelopes written by 0.1.0.
/// </summary>
public class EnvelopeHardeningTests
{
    private const string HybridHkdfInfo = "PQEF/ML-KEM-768+AES-256-GCM/v1";

    [Fact]
    public void Hybrid_envelope_is_written_as_format_version_2()
    {
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(new FakeKeyEncapsulationMechanism());

        byte[] envelope = protector.ProtectText("phi");

        Assert.Equal(EncryptedEnvelope.HybridFormatVersion, envelope[EncryptedEnvelope.VersionOffset]);
    }

    [Fact]
    public void Aes_envelope_remains_format_version_1()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();

        byte[] envelope = protector.ProtectText("pii");

        Assert.Equal(EncryptedEnvelope.FormatVersion, envelope[EncryptedEnvelope.VersionOffset]);
    }

    [Fact]
    public void Tampering_a_kem_ciphertext_byte_fails_authentication()
    {
        // In v2 the KEM ciphertext is part of the associated data, so flipping a byte inside
        // it must fail the AEAD tag (defence in depth beyond the derived-key mismatch).
        IPostQuantumProtector protector = TestKeys.EnvelopeProtector(new FakeKeyEncapsulationMechanism());
        byte[] envelope = protector.ProtectText("sensitive");

        // The KEM ciphertext begins two bytes into the body (after its big-endian length).
        int bodyOffset = EncryptedEnvelope.Parse(envelope).AssociatedData.Length;
        envelope[bodyOffset + 2] ^= 0xFF;

        Assert.Throws<PostQuantumCryptographicException>(() => protector.UnprotectText(envelope));
    }

    [Fact]
    public void Legacy_version_1_hybrid_envelope_still_decrypts()
    {
        // Reproduce exactly what 0.1.0 wrote: a version-1 header, the KEM block in the body,
        // and a DEM whose associated data is the header ONLY (no KEM block). The current
        // handler must still read it by rebuilding the version-1 associated data.
        const string plaintext = "written-by-0.1.0";
        const string keyId = "kek-legacy";
        var kem = new FakeKeyEncapsulationMechanism();
        KeyEncapsulationKeyPair pair = kem.GenerateKeyPair(keyId);
        EncapsulationResult encapsulation = kem.Encapsulate(pair);

        byte[] header = EncryptedEnvelope.WriteHeader(
            EncryptionScheme.MLKem768Aes256Gcm, keyId, EncryptedEnvelope.FormatVersion);

        Span<byte> dek = stackalloc byte[32];
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: encapsulation.SharedSecret,
            output: dek,
            salt: Encoding.UTF8.GetBytes(keyId),
            info: Encoding.ASCII.GetBytes(HybridHkdfInfo));

        // v1 associated data = header only.
        byte[] dem = AuthenticatedCipher.Encrypt(dek, Encoding.UTF8.GetBytes(plaintext), header);

        byte[] ciphertext = encapsulation.Ciphertext;
        var envelope = new byte[header.Length + 2 + ciphertext.Length + dem.Length];
        header.CopyTo(envelope.AsSpan());
        BinaryPrimitives.WriteUInt16BigEndian(envelope.AsSpan(header.Length, 2), (ushort)ciphertext.Length);
        ciphertext.CopyTo(envelope.AsSpan(header.Length + 2));
        dem.CopyTo(envelope.AsSpan(header.Length + 2 + ciphertext.Length));

        var protector = new PostQuantumProtector(
            [new MLKemEnvelopeSchemeHandler(new InMemoryKeyEncapsulationKeyRing(pair), kem)],
            EncryptionScheme.MLKem768Aes256Gcm);

        Assert.Equal(EncryptedEnvelope.FormatVersion, envelope[EncryptedEnvelope.VersionOffset]);
        Assert.Equal(plaintext, protector.UnprotectText(envelope));
    }
}
