using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace PostQuantum.EntityFrameworkCore.EntityFrameworkCore;

/// <summary>
/// An EF Core <see cref="ValueConverter"/> that transparently encrypts a <c>byte[]</c>
/// property to an authenticated envelope (also <c>byte[]</c>) and decrypts on read.
/// Use for already-binary secrets such as document blobs, tokens, or key material.
/// </summary>
/// <remarks>
/// Because encryption is non-deterministic, a property using this converter cannot be
/// filtered, indexed, or joined on in the database. <see langword="null"/> values are
/// passed through by EF Core and are never encrypted.
/// </remarks>
public sealed class EncryptedBinaryConverter : ValueConverter<byte[], byte[]>
{
    /// <summary>Creates the converter over a configured protector.</summary>
    public EncryptedBinaryConverter(IPostQuantumProtector protector, ConverterMappingHints? mappingHints = null)
        : base(
            plaintext => protector.ProtectBytes(plaintext),
            ciphertext => protector.UnprotectBytes(ciphertext),
            mappingHints)
    {
        ArgumentNullException.ThrowIfNull(protector);
    }
}
