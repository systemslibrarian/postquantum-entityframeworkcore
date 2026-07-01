using System.Collections.Concurrent;
using PostQuantum.EntityFrameworkCore.Crypto;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Locks in two documented behaviors of the protector: it is safe to share across threads
/// (it is registered as a singleton), and an intact envelope relocated to another location
/// that shares its key id still decrypts (a known, documented limitation).
/// </summary>
public class ProtectorBehaviorTests
{
    [Fact]
    public void Protector_is_safe_for_concurrent_use()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        var failures = new ConcurrentBag<string>();

        Parallel.For(0, 2000, i =>
        {
            string value = $"record-{i}";
            try
            {
                byte[] envelope = protector.ProtectText(value);
                if (protector.UnprotectText(envelope) != value)
                {
                    failures.Add(value);
                }
            }
            catch (Exception ex)
            {
                failures.Add($"{value}: {ex.GetType().Name}");
            }
        });

        Assert.Empty(failures);
    }

    [Fact]
    public void An_intact_envelope_relocated_under_the_same_key_still_decrypts()
    {
        // DOCUMENTED LIMITATION (see KNOWN-GAPS.md / threat model): the associated data binds
        // version, scheme, and key id — NOT the table, column, or row. So a whole valid
        // envelope copied elsewhere (same key id) still decrypts. This test makes that
        // behavior explicit so any future entity/property binding is a deliberate change.
        IPostQuantumProtector protector = TestKeys.AesProtector();

        byte[] ssn = protector.ProtectText("123-45-6789");

        // Simulate an attacker with write access copying the SSN envelope into the email column.
        byte[] relocated = (byte[])ssn.Clone();

        Assert.Equal("123-45-6789", protector.UnprotectText(relocated));
    }

    [Fact]
    public void Tampered_bytes_in_a_relocated_envelope_are_still_rejected()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        byte[] envelope = protector.ProtectText("123-45-6789");

        envelope[^1] ^= 0x01;

        Assert.Throws<PostQuantumCryptographicException>(() => protector.UnprotectText(envelope));
    }
}
