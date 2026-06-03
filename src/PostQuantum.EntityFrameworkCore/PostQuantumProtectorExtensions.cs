namespace PostQuantum.EntityFrameworkCore;

/// <summary>
/// Convenience extensions over <see cref="IPostQuantumProtector"/> that expose
/// <see cref="byte"/>-array signatures. These are usable from LINQ expression trees
/// (which cannot reference <c>Span</c> types) and so are what the value converters call.
/// </summary>
public static class PostQuantumProtectorExtensions
{
    /// <summary>Encrypts a byte array, returning a complete envelope.</summary>
    public static byte[] ProtectBytes(this IPostQuantumProtector protector, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(plaintext);
        return protector.Protect(plaintext);
    }

    /// <summary>Decrypts an envelope back into a byte array.</summary>
    public static byte[] UnprotectBytes(this IPostQuantumProtector protector, byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(protectedData);
        return protector.Unprotect(protectedData);
    }
}
