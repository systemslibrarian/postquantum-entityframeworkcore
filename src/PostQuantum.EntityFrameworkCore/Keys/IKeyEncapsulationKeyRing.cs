namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// Supplies post-quantum key-encapsulation key pairs (the long-lived key-encryption keys,
/// or KEKs) for the hybrid envelope scheme and resolves historical pairs by id.
/// </summary>
/// <remarks>
/// This is the post-quantum counterpart to <see cref="IDataProtectionKeyRing"/> and the
/// natural integration point for <c>PostQuantum.KeyManagement</c>, which can custody the
/// private decapsulation keys in an HSM or KMS and expose only encapsulation keys to
/// encrypt-only nodes.
/// </remarks>
public interface IKeyEncapsulationKeyRing
{
    /// <summary>The key pair used to wrap data-encryption keys for new values.</summary>
    KeyEncapsulationKeyPair ActiveKey { get; }

    /// <summary>
    /// Resolves a key pair by the id stored in an envelope, or <see langword="null"/> if
    /// this ring does not hold it. The returned pair must hold private material to decrypt.
    /// </summary>
    KeyEncapsulationKeyPair? Find(string keyId);
}
