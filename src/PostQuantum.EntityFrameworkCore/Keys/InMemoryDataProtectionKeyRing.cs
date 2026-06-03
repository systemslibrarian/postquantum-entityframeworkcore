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
/// </remarks>
public sealed class InMemoryDataProtectionKeyRing : IDataProtectionKeyRing, IDisposable
{
    private readonly Dictionary<string, DataEncryptionKey> _keys;
    private readonly string _activeKeyId;
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

        _keys = new Dictionary<string, DataEncryptionKey>(StringComparer.Ordinal);
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
