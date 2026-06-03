namespace PostQuantum.EntityFrameworkCore;

/// <summary>
/// Thrown when a post-quantum protect/unprotect operation fails: a malformed or
/// truncated envelope, an unknown encryption scheme, a missing key, or a failed
/// authentication tag (which indicates tampering, corruption, or use of the wrong key).
/// </summary>
/// <remarks>
/// The message is intentionally generic and never includes plaintext, key material,
/// or the specific reason a tag failed, so that exception text cannot be used as a
/// decryption oracle. Inspect the inner exception for diagnostics in trusted contexts only.
/// </remarks>
public sealed class PostQuantumCryptographicException : Exception
{
    /// <summary>Creates a new <see cref="PostQuantumCryptographicException"/>.</summary>
    public PostQuantumCryptographicException(string message)
        : base(message)
    {
    }

    /// <summary>Creates a new <see cref="PostQuantumCryptographicException"/> with an inner cause.</summary>
    public PostQuantumCryptographicException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
