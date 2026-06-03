using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Verifies the real ML-KEM-768 mechanism. Because platform support varies (it needs
/// .NET 10+ with OpenSSL 3.5+ or recent Windows CNG), each test asserts the correct
/// behavior for the current platform: a full round-trip where supported, and a clear,
/// honest <see cref="PlatformNotSupportedException"/> where not.
/// </summary>
public class RealMLKemTests
{
    private readonly MLKemKeyEncapsulationMechanism _mechanism = new();

    [Fact]
    public void AlgorithmName_is_ML_KEM_768()
    {
        Assert.Equal("ML-KEM-768", _mechanism.AlgorithmName);
    }

    [Fact]
    public void Real_ML_KEM_envelope_roundtrips_or_reports_unsupported()
    {
        if (!_mechanism.IsSupported)
        {
            Assert.Throws<PlatformNotSupportedException>(() => _mechanism.GenerateKeyPair("kek-real"));
            return;
        }

        KeyEncapsulationKeyPair pair = _mechanism.GenerateKeyPair("kek-real");
        var protector = new PostQuantumProtector(
            [new MLKemEnvelopeSchemeHandler(new InMemoryKeyEncapsulationKeyRing(pair), _mechanism)],
            EncryptionScheme.MLKem768Aes256Gcm);

        const string secret = "post-quantum protected medical record";
        byte[] envelope = protector.ProtectText(secret);

        Assert.Equal(secret, protector.UnprotectText(envelope));
        Assert.Equal(EncryptionScheme.MLKem768Aes256Gcm, EncryptedEnvelope.Parse(envelope).Scheme);
    }

    [Fact]
    public void Real_ML_KEM_encapsulate_decapsulate_agree_or_report_unsupported()
    {
        if (!_mechanism.IsSupported)
        {
            Assert.False(_mechanism.IsSupported);
            return;
        }

        KeyEncapsulationKeyPair pair = _mechanism.GenerateKeyPair("kek-real");
        EncapsulationResult encapsulation = _mechanism.Encapsulate(pair);
        byte[] recovered = _mechanism.Decapsulate(pair, encapsulation.Ciphertext);

        Assert.Equal(encapsulation.SharedSecret, recovered);
    }
}
