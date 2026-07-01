using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace PostQuantum.EntityFrameworkCore.EntityFrameworkCore;

/// <summary>
/// Helpers for re-encrypting existing rows after a key or scheme rotation.
/// </summary>
/// <remarks>
/// <para>
/// Re-encryption is the operation that retires an old key or scheme: every value is read,
/// then written again so it is stored under the active key/scheme recorded in a fresh
/// envelope. Once every row is re-encrypted, the old key can be dropped from the ring.
/// </para>
/// <para>
/// <b>Why a helper is needed.</b> EF Core change tracking compares the property's model
/// (decrypted) value, which is unchanged by rotation, so a plain load-and-<c>SaveChanges</c>
/// generates no UPDATE and the ciphertext is never rewritten. These helpers explicitly mark
/// the encrypted properties as modified, forcing EF to round-trip them through the value
/// converter and re-emit the envelope under the active key/scheme.
/// </para>
/// </remarks>
public static class EncryptedDataMaintenance
{
    /// <summary>
    /// The member kinds EF Core needs preserved on an entity type for model and query use.
    /// Mirrors the annotation on <see cref="DbContext.Set{TEntity}()"/> so trimming/AOT is honored.
    /// </summary>
    private const DynamicallyAccessedMemberTypes EntityMembers =
        DynamicallyAccessedMemberTypes.PublicConstructors
        | DynamicallyAccessedMemberTypes.NonPublicConstructors
        | DynamicallyAccessedMemberTypes.PublicFields
        | DynamicallyAccessedMemberTypes.NonPublicFields
        | DynamicallyAccessedMemberTypes.PublicProperties
        | DynamicallyAccessedMemberTypes.NonPublicProperties
        | DynamicallyAccessedMemberTypes.Interfaces;

    /// <summary>
    /// Marks every encrypted property of a tracked entity as modified so the next
    /// <see cref="DbContext.SaveChanges()"/> re-encrypts it under the active key and scheme.
    /// Non-encrypted properties are untouched; <see langword="null"/> values stay null.
    /// </summary>
    /// <returns>The number of encrypted properties that were marked modified.</returns>
    public static int MarkEncryptedPropertiesModified<[DynamicallyAccessedMembers(EntityMembers)] TEntity>(
        this DbContext context, TEntity entity)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(entity);

        Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<TEntity> entry = context.Entry(entity);
        int count = 0;
        foreach (string name in GetEncryptedPropertyNames(context, typeof(TEntity)))
        {
            if (ForceReEncrypt(entry.Property(name)))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Forces a single property to be re-encrypted on the next save. Marks it modified and
    /// clears the tracked original value so that change detection — which compares the
    /// <i>decrypted</i> model values and would otherwise reset the flag because the plaintext
    /// is unchanged — keeps the property modified and re-runs the value converter. A property
    /// whose current value is <see langword="null"/> is left untouched (null stays null).
    /// </summary>
    /// <returns><see langword="true"/> if the property was marked for re-encryption.</returns>
    private static bool ForceReEncrypt(
        Microsoft.EntityFrameworkCore.ChangeTracking.PropertyEntry property)
    {
        if (property.CurrentValue is null)
        {
            return false;
        }

        property.OriginalValue = null;
        property.IsModified = true;
        return true;
    }

    /// <summary>
    /// Re-encrypts every row of <typeparamref name="TEntity"/> in batches, rewriting each
    /// encrypted column under the active key and scheme. Safe to run while the application is
    /// online; run it after rotating a key (and registering both old and new keys in the
    /// ring), then drop the old key once this completes.
    /// </summary>
    /// <param name="context">The context whose model declares the encrypted properties.</param>
    /// <param name="batchSize">Rows to load, re-encrypt, and save per batch.</param>
    /// <param name="cancellationToken">A token to cancel the sweep between batches.</param>
    /// <returns>The total number of rows re-encrypted.</returns>
    /// <remarks>
    /// Requires a single-column primary key for stable paging. For composite keys or custom
    /// paging, iterate your own query and call <see cref="MarkEncryptedPropertiesModified"/>
    /// on each entity instead.
    /// </remarks>
    public static async Task<int> ReEncryptAsync<[DynamicallyAccessedMembers(EntityMembers)] TEntity>(
        this DbContext context,
        int batchSize = 500,
        CancellationToken cancellationToken = default)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(batchSize);

        IEntityType entityType = context.Model.FindEntityType(typeof(TEntity))
            ?? throw new ArgumentException(
                $"'{typeof(TEntity)}' is not part of this context's model.", nameof(context));

        string[] encrypted = [.. GetEncryptedPropertyNames(context, typeof(TEntity))];
        if (encrypted.Length == 0)
        {
            return 0;
        }

        IKey primaryKey = entityType.FindPrimaryKey()
            ?? throw new InvalidOperationException(
                $"'{typeof(TEntity)}' has no primary key, which is required to page through rows. " +
                "Re-encrypt manually using MarkEncryptedPropertiesModified.");
        if (primaryKey.Properties.Count != 1)
        {
            throw new InvalidOperationException(
                $"'{typeof(TEntity)}' has a composite primary key, which automatic paging does not " +
                "support. Iterate your own ordered query and call MarkEncryptedPropertiesModified.");
        }

        string keyName = primaryKey.Properties[0].Name;
        int total = 0;
        for (int skip = 0; ; skip += batchSize)
        {
            List<TEntity> batch = await context.Set<TEntity>()
                .OrderBy(e => EF.Property<object>(e, keyName))
                .Skip(skip)
                .Take(batchSize)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);

            if (batch.Count == 0)
            {
                break;
            }

            foreach (TEntity entity in batch)
            {
                Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<TEntity> entry = context.Entry(entity);
                foreach (string name in encrypted)
                {
                    ForceReEncrypt(entry.Property(name));
                }
            }

            await context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            total += batch.Count;

            // Detach the batch so the change tracker does not grow across a large sweep.
            foreach (TEntity entity in batch)
            {
                context.Entry(entity).State = EntityState.Detached;
            }
        }

        return total;
    }

    private static IEnumerable<string> GetEncryptedPropertyNames(
        DbContext context,
        [DynamicallyAccessedMembers(EntityMembers)] Type clrType)
    {
        IEntityType entityType = context.Model.FindEntityType(clrType)
            ?? throw new ArgumentException(
                $"'{clrType}' is not part of this context's model.", nameof(clrType));

        foreach (IProperty property in entityType.GetProperties())
        {
            if (property.GetValueConverter() is EncryptedStringConverter or EncryptedBinaryConverter)
            {
                yield return property.Name;
            }
        }
    }
}
