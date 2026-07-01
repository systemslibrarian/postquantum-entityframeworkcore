using System.Collections.Concurrent;

namespace PostQuantum.EntityFrameworkCore.Keys;

/// <summary>
/// An in-memory <see cref="IKeyEncapsulationKeyRing"/> for development, tests, and small
/// self-hosted deployments.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security note:</b> private decapsulation keys held here live in process memory and
/// are zeroed on <see cref="Dispose"/>. For production, custody private keys in
/// <c>PostQuantum.KeyManagement</c>, an HSM, or a cloud KMS and implement this interface
/// over that store.
/// </para>
/// <para>
/// <b>Rotation.</b> Rotate <i>in place</i> with <see cref="AddKey"/> and
/// <see cref="SetActiveKey"/> on the ring the protector already holds; see the note on
/// <see cref="InMemoryDataProtectionKeyRing"/> for why a new ring/protector would have no
/// effect with EF Core's model cache. Thread-safe.
/// </para>
/// </remarks>
public sealed class InMemoryKeyEncapsulationKeyRing : IKeyEncapsulationKeyRing, IDisposable
{
    private readonly ConcurrentDictionary<string, KeyEncapsulationKeyPair> _keys;
    private volatile string _activeKeyId;
    private bool _disposed;

    /// <summary>Creates a ring from a set of key pairs, designating one as active.</summary>
    public InMemoryKeyEncapsulationKeyRing(string activeKeyId, IEnumerable<KeyEncapsulationKeyPair> keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(activeKeyId);
        ArgumentNullException.ThrowIfNull(keys);

        _keys = new ConcurrentDictionary<string, KeyEncapsulationKeyPair>(StringComparer.Ordinal);
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

    /// <summary>Adds a key pair to the ring without changing the active key. Thread-safe.</summary>
    /// <exception cref="ArgumentException">A pair with the same id is already present.</exception>
    public void AddKey(KeyEncapsulationKeyPair key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(key);
        if (!_keys.TryAdd(key.KeyId, key))
        {
            throw new ArgumentException($"A key with id '{key.KeyId}' is already in the ring.", nameof(key));
        }
    }

    /// <summary>Makes an already-present pair the active key for new writes. Thread-safe.</summary>
    /// <exception cref="ArgumentException">No pair with this id is in the ring.</exception>
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
    /// Removes (retires) a non-active pair once nothing is encrypted under it. The active key
    /// cannot be removed. The removed pair is disposed (private material zeroed). Thread-safe.
    /// </summary>
    /// <returns><see langword="true"/> if a pair was removed.</returns>
    /// <exception cref="ArgumentException">An attempt was made to remove the active key.</exception>
    public bool RemoveKey(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        if (string.Equals(keyId, _activeKeyId, StringComparison.Ordinal))
        {
            throw new ArgumentException("Cannot remove the active key; activate another key first.", nameof(keyId));
        }

        if (_keys.TryRemove(keyId, out KeyEncapsulationKeyPair? removed))
        {
            removed.Dispose();
            return true;
        }

        return false;
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
