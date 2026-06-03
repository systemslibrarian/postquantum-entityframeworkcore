namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// An in-memory <see cref="IKeyEncapsulationKeyRing"/> for development, tests, and small
/// self-hosted deployments.
/// </summary>
/// <remarks>
/// <b>Security note:</b> private decapsulation keys held here live in process memory and
/// are zeroed on <see cref="Dispose"/>. For production, custody private keys in
/// <c>PostQuantum.KeyManagement</c>, an HSM, or a cloud KMS and implement this interface
/// over that store.
/// </remarks>
public sealed class InMemoryKeyEncapsulationKeyRing : IKeyEncapsulationKeyRing, IDisposable
{
    private readonly Dictionary<string, KeyEncapsulationKeyPair> _keys;
    private readonly string _activeKeyId;
    private bool _disposed;

    /// <summary>Creates a ring from a set of key pairs, designating one as active.</summary>
    public InMemoryKeyEncapsulationKeyRing(string activeKeyId, IEnumerable<KeyEncapsulationKeyPair> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(activeKeyId);
        ArgumentNullException.ThrowIfNull(keys);

        _keys = new Dictionary<string, KeyEncapsulationKeyPair>(StringComparer.Ordinal);
        foreach (KeyEncapsulationKeyPair key in keys)
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

    /// <summary>Creates a ring holding a single key pair, which is also active.</summary>
    public InMemoryKeyEncapsulationKeyRing(KeyEncapsulationKeyPair key)
        : this(GetKeyId(key), [key])
    {
    }

    /// <inheritdoc />
    public KeyEncapsulationKeyPair ActiveKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _keys[_activeKeyId];
        }
    }

    /// <inheritdoc />
    public KeyEncapsulationKeyPair? Find(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(keyId);
        return _keys.GetValueOrDefault(keyId);
    }

    /// <summary>Zeroes and disposes every key pair held by the ring.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (KeyEncapsulationKeyPair key in _keys.Values)
        {
            key.Dispose();
        }

        _disposed = true;
    }

    private static string GetKeyId(KeyEncapsulationKeyPair key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return key.KeyId;
    }
}
