using System.Collections.Concurrent;

namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// An in-memory <see cref="IDataProtectionKeyRing"/> suitable for development, tests,
/// and small self-hosted deployments where keys are provisioned at startup.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security note:</b> keys held here live in process memory for the lifetime of the
/// ring and are zeroed on <see cref="Dispose"/>. This type does not provide custody,
/// access control, rotation scheduling, or auditing. For production, implement
/// <see cref="IDataProtectionKeyRing"/> over a managed key store such as
/// <c>PostQuantum.KeyManagement</c>, an HSM, or a cloud KMS.
/// </para>
/// <para>
/// <b>Rotation.</b> Rotate <i>in place</i> with <see cref="AddKey"/> and
/// <see cref="SetActiveKey"/> on the ring instance the protector already holds — do not
/// build a new protector or ring to rotate. Entity Framework Core caches the model, and the
/// value converters in that cached model capture the protector instance; swapping the
/// protector has no effect until the model cache is invalidated. Mutating this ring is
/// thread-safe and is observed immediately by the singleton protector.
/// </para>
/// </remarks>
public sealed class InMemoryDataProtectionKeyRing : IDataProtectionKeyRing, IDisposable
{
    private readonly ConcurrentDictionary<string, DataEncryptionKey> _keys;
    private volatile string _activeKeyId;
    private bool _disposed;

    /// <summary>
    /// Creates a ring from a set of keys, designating one as active for new writes.
    /// </summary>
    /// <param name="activeKeyId">The id of the key used to encrypt new values.</param>
    /// <param name="keys">All keys the ring should hold, including historical keys.</param>
    public InMemoryDataProtectionKeyRing(string activeKeyId, IEnumerable<DataEncryptionKey> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(activeKeyId);
        ArgumentNullException.ThrowIfNull(keys);

        _keys = new ConcurrentDictionary<string, DataEncryptionKey>(StringComparer.Ordinal);
        foreach (DataEncryptionKey key in keys)
        {
            if (!_keys.TryAdd(key.KeyId, key))
            {
                throw new ArgumentException($"Duplicate key id '{key.KeyId}' in key ring.", nameof(keys));
            }
        }

        if (!_keys.ContainsKey(activeKeyId))
        {
            throw new ArgumentException(
                $"Active key id '{activeKeyId}' was not found among the supplied keys.", nameof(activeKeyId));
        }

        _activeKeyId = activeKeyId;
    }

    /// <summary>Creates a ring holding a single key, which is also the active key.</summary>
    public InMemoryDataProtectionKeyRing(DataEncryptionKey key)
        : this(GetKeyId(key), [key])
    {
    }

    /// <inheritdoc />
    public DataEncryptionKey ActiveKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _keys[_activeKeyId];
        }
    }

    /// <inheritdoc />
    public DataEncryptionKey? Find(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(keyId);
        return _keys.GetValueOrDefault(keyId);
    }

    /// <summary>
    /// Adds a key to the ring (for example a freshly generated key during rotation) without
    /// changing which key is active. Historical values keep decrypting; new writes are
    /// unaffected until <see cref="SetActiveKey"/> is called. Thread-safe.
    /// </summary>
    /// <exception cref="ArgumentException">A key with the same id is already present.</exception>
    public void AddKey(DataEncryptionKey key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(key);
        if (!_keys.TryAdd(key.KeyId, key))
        {
            throw new ArgumentException($"A key with id '{key.KeyId}' is already in the ring.", nameof(key));
        }
    }

    /// <summary>
    /// Makes an already-present key the active key for new writes. Combine with
    /// <see cref="AddKey"/> to rotate: add the new key, then activate it. Thread-safe; the
    /// change is observed immediately by the protector that holds this ring.
    /// </summary>
    /// <exception cref="ArgumentException">No key with this id is in the ring.</exception>
    public void SetActiveKey(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (!_keys.ContainsKey(keyId))
        {
            throw new ArgumentException($"No key with id '{keyId}' is in the ring; add it first.", nameof(keyId));
        }

        _activeKeyId = keyId;
    }

    /// <summary>
    /// Removes (retires) a non-active key once nothing is encrypted under it — typically after
    /// a re-encryption sweep. The active key cannot be removed. The removed key is disposed
    /// (its material zeroed). Thread-safe.
    /// </summary>
    /// <returns><see langword="true"/> if a key was removed.</returns>
    /// <exception cref="ArgumentException">An attempt was made to remove the active key.</exception>
    public bool RemoveKey(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (string.Equals(keyId, _activeKeyId, StringComparison.Ordinal))
        {
            throw new ArgumentException("Cannot remove the active key; activate another key first.", nameof(keyId));
        }

        if (_keys.TryRemove(keyId, out DataEncryptionKey? removed))
        {
            removed.Dispose();
            return true;
        }

        return false;
    }

    /// <summary>Zeroes and disposes every key held by the ring.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (DataEncryptionKey key in _keys.Values)
        {
            key.Dispose();
        }

        _disposed = true;
    }

    private static string GetKeyId(DataEncryptionKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.KeyId;
    }
}
