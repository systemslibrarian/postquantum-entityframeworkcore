using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace PostQuantum.EntityFrameworkCore.EntityFrameworkCore;

/// <summary>
/// Fluent helpers for marking EF Core properties as encrypted at rest.
/// </summary>
/// <example>
/// <code>
/// protected override void OnModelCreating(ModelBuilder modelBuilder)
/// {
///     modelBuilder.Entity&lt;Patient&gt;(b =&gt;
///     {
///         b.Property(p =&gt; p.Email).IsEncrypted(_protector);       // string (nullable or not)
///         b.Property(p =&gt; p.Diagnosis).IsEncrypted(_protector);   // string?
///         b.Property(p =&gt; p.ScannedDocument).IsEncrypted(_protector); // byte[]
///     });
/// }
/// </code>
/// </example>
public static class EncryptedPropertyBuilderExtensions
{
    /// <summary>
    /// Configures a string property (nullable or non-nullable) to be encrypted with the
    /// supplied protector. The column stores ciphertext as <c>byte[]</c>. <see langword="null"/>
    /// values are passed through by EF Core and are never encrypted.
    /// </summary>
    /// <remarks>
    /// This overload is intentionally non-generic so that both <c>string</c> and
    /// <c>string?</c> properties bind without nullable-annotation friction. For
    /// <c>byte[]</c> properties, the dedicated <see cref="IsEncrypted(PropertyBuilder{byte[]}, IPostQuantumProtector)"/>
    /// overload is selected automatically.
    /// </remarks>
    public static PropertyBuilder IsEncrypted(
        this PropertyBuilder propertyBuilder,
        IPostQuantumProtector protector)
    {
        ArgumentNullException.ThrowIfNull(propertyBuilder);
        ArgumentNullException.ThrowIfNull(protector);
        return propertyBuilder.HasConversion(new EncryptedStringConverter(protector));
    }

    /// <summary>
    /// Configures a <c>byte[]</c> property to be encrypted with the supplied protector.
    /// </summary>
    public static PropertyBuilder<byte[]> IsEncrypted(
        this PropertyBuilder<byte[]> propertyBuilder,
        IPostQuantumProtector protector)
    {
        ArgumentNullException.ThrowIfNull(propertyBuilder);
        ArgumentNullException.ThrowIfNull(protector);
        return propertyBuilder.HasConversion(new EncryptedBinaryConverter(protector));
    }
}
