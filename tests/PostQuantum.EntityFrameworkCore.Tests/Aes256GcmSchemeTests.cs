using System.Text;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

public class Aes256GcmSchemeTests
{
    [Theory]
    [InlineData("alice@example.com")]
    [InlineData("")]
    [InlineData("Patient diagnosis: 🩺 sensitive — UTF-8 ✓")]
    public void ProtectText_then_UnprotectText_returns_original(string plaintext)
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();

        byte[] envelope = protector.ProtectText(plaintext);
        string roundTripped = protector.UnprotectText(envelope);

        Assert.Equal(plaintext, roundTripped);
    }

    [Fact]
    public void Protect_then_Unprotect_returns_original_bytes_for_large_payload()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        var data = new byte[200_000];
        new Random(12345).NextBytes(data);

        byte[] roundTripped = protector.Unprotect(protector.Protect(data));

        Assert.Equal(data, roundTripped);
    }

    [Fact]
    public void Protect_uses_a_fresh_nonce_so_identical_plaintext_yields_distinct_ciphertext()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();

        byte[] first = protector.ProtectText("same-secret");
        byte[] second = protector.ProtectText("same-secret");

        Assert.NotEqual(first, second);
        Assert.Equal("same-secret", protector.UnprotectText(first));
        Assert.Equal("same-secret", protector.UnprotectText(second));
    }

    [Fact]
    public void Ciphertext_does_not_contain_the_plaintext()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        const string secret = "SECRET-CARD-4111111111111111";

        byte[] envelope = protector.ProtectText(secret);

        Assert.False(
            ContainsSubsequence(envelope, Encoding.UTF8.GetBytes(secret)),
            "Ciphertext must not contain the plaintext.");
    }

    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || needle.Length > haystack.Length)
        {
            return false;
        }

        for (int i = 0; i + needle.Length <= haystack.Length; i++)
        {
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    [Fact]
    public void Unprotect_fails_when_the_ciphertext_is_tampered()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        byte[] envelope = protector.ProtectText("transfer $100");

        envelope[^1] ^= 0xFF; // flip a bit in the ciphertext

        Assert.Throws<PostQuantumCryptographicException>(() => protector.UnprotectText(envelope));
    }

    [Fact]
    public void Unprotect_fails_when_the_scheme_byte_is_downgraded()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        byte[] envelope = protector.ProtectText("data");

        // Byte 5 is the scheme id, which is bound into the AES-GCM associated data.
        envelope[5] = (byte)EncryptionScheme.MLKem768Aes256Gcm;

        // Now no AES handler matches the (forged) scheme, so dispatch fails.
        Assert.Throws<PostQuantumCryptographicException>(() => protector.UnprotectText(envelope));
    }

    [Fact]
    public void Unprotect_fails_when_the_keyId_in_the_header_is_tampered()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector(out _, "dek-test-1");
        byte[] envelope = protector.ProtectText("data");

        // The key id starts at offset 8; flipping it both breaks key lookup AND the AAD.
        envelope[8] ^= 0x01;

        Assert.Throws<PostQuantumCryptographicException>(() => protector.UnprotectText(envelope));
    }

    [Fact]
    public void Unprotect_fails_with_a_different_key_under_the_same_keyId()
    {
        const string keyId = "dek-shared-id";
        using var keyA = DataEncryptionKey.Generate(keyId);
        using var keyB = DataEncryptionKey.Generate(keyId);

        var protectorA = new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(keyA))],
            EncryptionScheme.Aes256Gcm);
        var protectorB = new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(keyB))],
            EncryptionScheme.Aes256Gcm);

        byte[] envelope = protectorA.ProtectText("top secret");

        // Same key id resolves, but the wrong key material fails authentication.
        Assert.Throws<PostQuantumCryptographicException>(() => protectorB.UnprotectText(envelope));
    }

    [Fact]
    public void Unprotect_fails_when_no_key_matches_the_header_keyId()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector(out _, "dek-test-1");
        byte[] envelope = protector.ProtectText("data");

        using var otherKey = DataEncryptionKey.Generate("a-totally-different-id");
        var otherProtector = new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(otherKey))],
            EncryptionScheme.Aes256Gcm);

        PostQuantumCryptographicException ex = Assert.Throws<PostQuantumCryptographicException>(
            () => otherProtector.UnprotectText(envelope));
        Assert.Contains("key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Values_remain_decryptable_after_key_rotation()
    {
        using var oldKey = DataEncryptionKey.Generate("dek-2025");
        using var newKey = DataEncryptionKey.Generate("dek-2026");

        // Encrypt while "dek-2025" is the only/active key.
        var legacyProtector = new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(oldKey))],
            EncryptionScheme.Aes256Gcm);
        byte[] legacyEnvelope = legacyProtector.ProtectText("written-in-2025");

        // Rotate: ring holds both keys, new key is active.
        var rotatedRing = new InMemoryDataProtectionKeyRing("dek-2026", [oldKey, newKey]);
        var rotatedProtector = new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(rotatedRing)],
            EncryptionScheme.Aes256Gcm);

        // Old value still decrypts; new writes use the new key.
        Assert.Equal("written-in-2025", rotatedProtector.UnprotectText(legacyEnvelope));
        byte[] freshEnvelope = rotatedProtector.ProtectText("written-in-2026");
        Assert.Equal("dek-2026", EncryptedEnvelope.Parse(freshEnvelope).KeyId);
        Assert.Equal("written-in-2026", rotatedProtector.UnprotectText(freshEnvelope));
    }
}
