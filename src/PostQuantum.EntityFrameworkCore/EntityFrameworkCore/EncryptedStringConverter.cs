using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace PostQuantum.EntityFrameworkCore.EntityFrameworkCore;

/// <summary>
/// An EF Core <see cref="ValueConverter"/> that transparently encrypts a
/// <see cref="string"/> property to an authenticated envelope stored as <c>byte[]</c>
/// (map it to <c>varbinary</c>/<c>BLOB</c>), and decrypts on read.
/// </summary>
/// <remarks>
/// Because encryption is non-deterministic, a property using this converter cannot be
/// filtered, indexed, or joined on in the database. <see langword="null"/> values are
/// passed through by EF Core and are never encrypted.
/// </remarks>
public sealed class EncryptedStringConverter : ValueConverter<string, byte[]>
{
    /// <summary>Creates the converter over a configured protector.</summary>
    public EncryptedStringConverter(IPostQuantumProtector protector, ConverterMappingHints? mappingHints = null)
        : base(
            plaintext => protector.ProtectText(plaintext),
            ciphertext => protector.UnprotectText(ciphertext),
            mappingHints)
    {
        ArgumentNullException.ThrowIfNull(protector);
    }
}
