namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// Encrypts and decrypts the scheme-specific portion of an envelope for one
/// <see cref="EncryptionScheme"/>. The protector owns scheme selection and dispatch;
/// each handler owns key resolution and the body format for its scheme.
/// </summary>
internal interface IEncryptionSchemeHandler
{
    /// <summary>The scheme this handler implements.</summary>
    EncryptionScheme Scheme { get; }

    /// <summary>
    /// Verifies that this handler can encrypt new values right now: its platform support is
    /// present and an active key is resolvable. Called for the default scheme when the
    /// protector is constructed so that misconfiguration fails fast at startup rather than on
    /// the first write.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">The scheme's platform support is absent.</exception>
    /// <exception cref="PostQuantumCryptographicException">No active key is available.</exception>
    void ValidateReady();

    /// <summary>
    /// Produces a complete envelope (header + body) for <paramref name="plaintext"/> using
    /// this scheme's active key.
    /// </summary>
    byte[] Encrypt(ReadOnlySpan<byte> plaintext);

    /// <summary>
    /// Decrypts a body previously produced by this scheme.
    /// </summary>
    /// <param name="keyId">The key id parsed from the envelope header.</param>
    /// <param name="associatedData">The header bytes, used as authenticated associated data.</param>
    /// <param name="body">The scheme-specific body following the header.</param>
    byte[] Decrypt(string keyId, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> body);
}
