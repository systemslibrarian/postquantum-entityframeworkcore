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
