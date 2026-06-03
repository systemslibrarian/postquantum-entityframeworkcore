namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// Supplies symmetric data-encryption keys (DEKs) for the AES-256-GCM scheme and
/// resolves historical keys by id so that previously encrypted values remain readable
/// after rotation.
/// </summary>
/// <remarks>
/// <para>
/// This is the primary integration seam for <c>PostQuantum.KeyManagement</c>. The
/// in-memory implementation shipped here is intended for development, tests, and small
/// self-hosted deployments. In production, back this interface with a managed key store
/// (HSM, cloud KMS, or <c>PostQuantum.KeyManagement</c>) that performs custody, access
/// control, rotation, and auditing — none of which this library attempts to own.
/// </para>
/// </remarks>
public interface IDataProtectionKeyRing
{
    /// <summary>
    /// The key used to encrypt new values. Rotating this key changes which DEK new
    /// writes use while leaving historical envelopes decryptable via <see cref="Find"/>.
    /// </summary>
    DataEncryptionKey ActiveKey { get; }

    /// <summary>
    /// Resolves a key by the id stored in an envelope, or <see langword="null"/> if this
    /// ring does not hold a key with that id.
    /// </summary>
    DataEncryptionKey? Find(string keyId);
}
