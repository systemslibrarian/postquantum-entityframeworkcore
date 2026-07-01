using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Covers in-place rotation of the in-memory key rings: adding a key, activating it, and
/// retiring an old one, with the guard that the active key cannot be removed.
/// </summary>
public class KeyRingRotationTests
{
    [Fact]
    public void AddKey_then_SetActiveKey_changes_the_active_key()
    {
        using var ring = new InMemoryDataProtectionKeyRing(DataEncryptionKey.Generate("dek-A"));
        Assert.Equal("dek-A", ring.ActiveKey.KeyId);

        ring.AddKey(DataEncryptionKey.Generate("dek-B"));
        Assert.Equal("dek-A", ring.ActiveKey.KeyId); // adding does not change active

        ring.SetActiveKey("dek-B");
        Assert.Equal("dek-B", ring.ActiveKey.KeyId);
        Assert.NotNull(ring.Find("dek-A")); // old key still resolvable
    }

    [Fact]
    public void SetActiveKey_for_an_unknown_id_throws()
    {
        using var ring = new InMemoryDataProtectionKeyRing(DataEncryptionKey.Generate("dek-A"));
        Assert.Throws<ArgumentException>(() => ring.SetActiveKey("dek-missing"));
    }

    [Fact]
    public void AddKey_rejects_a_duplicate_id()
    {
        using var ring = new InMemoryDataProtectionKeyRing(DataEncryptionKey.Generate("dek-A"));
        Assert.Throws<ArgumentException>(() => ring.AddKey(DataEncryptionKey.Generate("dek-A")));
    }

    [Fact]
    public void RemoveKey_retires_a_non_active_key_but_not_the_active_one()
    {
        using var ring = new InMemoryDataProtectionKeyRing(DataEncryptionKey.Generate("dek-A"));
        ring.AddKey(DataEncryptionKey.Generate("dek-B"));
        ring.SetActiveKey("dek-B");

        Assert.True(ring.RemoveKey("dek-A"));
        Assert.Null(ring.Find("dek-A"));
        Assert.False(ring.RemoveKey("dek-A")); // already gone
        Assert.Throws<ArgumentException>(() => ring.RemoveKey("dek-B")); // active key protected
    }

    [Fact]
    public void Kek_ring_supports_the_same_rotation_surface()
    {
        var kem = new FakeKeyEncapsulationMechanism();
        using var ring = new InMemoryKeyEncapsulationKeyRing(kem.GenerateKeyPair("kek-A"));

        ring.AddKey(kem.GenerateKeyPair("kek-B"));
        ring.SetActiveKey("kek-B");
        Assert.Equal("kek-B", ring.ActiveKey.KeyId);

        Assert.True(ring.RemoveKey("kek-A"));
        Assert.Throws<ArgumentException>(() => ring.RemoveKey("kek-B"));
    }
}
