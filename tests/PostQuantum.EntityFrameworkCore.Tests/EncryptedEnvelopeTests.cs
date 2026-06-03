using PostQuantum.EntityFrameworkCore.Crypto;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

public class EncryptedEnvelopeTests
{
    [Fact]
    public void WriteHeader_then_Parse_roundtrips_scheme_and_keyId()
    {
        byte[] header = EncryptedEnvelope.WriteHeader(EncryptionScheme.Aes256Gcm, "dek-2026-01");
        byte[] payload = [.. header, 1, 2, 3, 4];

        ParsedEnvelope parsed = EncryptedEnvelope.Parse(payload);

        Assert.Equal(EncryptionScheme.Aes256Gcm, parsed.Scheme);
        Assert.Equal("dek-2026-01", parsed.KeyId);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, parsed.Body.ToArray());
        Assert.Equal(header, parsed.AssociatedData.ToArray());
    }

    [Fact]
    public void Parse_rejects_payload_with_wrong_magic()
    {
        var payload = new byte[16];
        PostQuantumCryptographicException ex =
            Assert.Throws<PostQuantumCryptographicException>(() => EncryptedEnvelope.Parse(payload));
        Assert.Contains("recognized", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_rejects_truncated_payload()
    {
        Assert.Throws<PostQuantumCryptographicException>(() => EncryptedEnvelope.Parse(new byte[3]));
    }

    [Fact]
    public void Parse_rejects_unknown_format_version()
    {
        byte[] header = EncryptedEnvelope.WriteHeader(EncryptionScheme.Aes256Gcm, "k");
        header[4] = 99; // corrupt the version byte
        PostQuantumCryptographicException ex =
            Assert.Throws<PostQuantumCryptographicException>(() => EncryptedEnvelope.Parse(header));
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WriteHeader_rejects_empty_keyId()
    {
        Assert.Throws<ArgumentException>(() => EncryptedEnvelope.WriteHeader(EncryptionScheme.Aes256Gcm, ""));
    }
}
