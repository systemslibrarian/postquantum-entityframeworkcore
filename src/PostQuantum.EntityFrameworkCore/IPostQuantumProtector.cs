using System.Text;
using PostQuantum.EntityFrameworkCore.Crypto;

namespace PostQuantum.EntityFrameworkCore;

/// <summary>
/// Encrypts and decrypts individual values into self-describing, authenticated envelopes.
/// This is the primary service applications resolve from dependency injection and the
/// engine behind the Entity Framework Core value converters.
/// </summary>
/// <remarks>
/// <para>
/// Encryption is non-deterministic by design: every call uses a fresh nonce (and, for the
/// hybrid scheme, a fresh encapsulation), so encrypting the same plaintext twice yields
/// different ciphertext. This defeats equality correlation but means encrypted columns
/// cannot be used in <c>WHERE</c> clauses, indexes, or joins. See the README threat model.
/// </para>
/// <para>Implementations are thread-safe and intended to be registered as singletons.</para>
/// </remarks>
public interface IPostQuantumProtector
{
    /// <summary>The scheme used to encrypt new values.</summary>
    EncryptionScheme DefaultScheme { get; }

    /// <summary>Encrypts raw bytes, returning a complete envelope.</summary>
    byte[] Protect(ReadOnlySpan<byte> plaintext);

    /// <summary>
    /// Decrypts an envelope produced by <see cref="Protect"/>, dispatching on the scheme
    /// recorded in the envelope so that values written under a previous scheme or key still
    /// decrypt.
    /// </summary>
    /// <exception cref="PostQuantumCryptographicException">
    /// The envelope is malformed, uses an unregistered scheme, references a missing key, or
    /// fails authentication.
    /// </exception>
    byte[] Unprotect(ReadOnlyMemory<byte> protectedData);

    /// <summary>Encrypts a UTF-8 string, returning a complete envelope.</summary>
    byte[] ProtectText(string plaintext);

    /// <summary>Decrypts an envelope back into a UTF-8 string.</summary>
    string UnprotectText(ReadOnlyMemory<byte> protectedData);
}

/// <summary>
/// Default <see cref="IPostQuantumProtector"/>: composes one or more
/// <see cref="IEncryptionSchemeHandler"/> instances, encrypts new values with the
/// configured default scheme, and decrypts by dispatching on each envelope's recorded scheme.
/// </summary>
public sealed class PostQuantumProtector : IPostQuantumProtector
{
    private readonly Dictionary<EncryptionScheme, IEncryptionSchemeHandler> _handlers;

    internal PostQuantumProtector(
        IEnumerable<IEncryptionSchemeHandler> handlers,
        EncryptionScheme defaultScheme)
    {
        ArgumentNullException.ThrowIfNull(handlers);
        _handlers = new Dictionary<EncryptionScheme, IEncryptionSchemeHandler>();
        foreach (IEncryptionSchemeHandler handler in handlers)
        {
            if (!_handlers.TryAdd(handler.Scheme, handler))
            {
                throw new ArgumentException(
                    $"Duplicate handler registered for scheme {handler.Scheme}.", nameof(handlers));
            }
        }

        if (!_handlers.ContainsKey(defaultScheme))
        {
            throw new ArgumentException(
                $"No handler is registered for the default scheme {defaultScheme}.", nameof(defaultScheme));
        }

        DefaultScheme = defaultScheme;
    }

    /// <inheritdoc />
    public EncryptionScheme DefaultScheme { get; }

    /// <inheritdoc />
    public byte[] Protect(ReadOnlySpan<byte> plaintext) => _handlers[DefaultScheme].Encrypt(plaintext);

    /// <inheritdoc />
    public byte[] Unprotect(ReadOnlyMemory<byte> protectedData)
    {
        ParsedEnvelope envelope = EncryptedEnvelope.Parse(protectedData);
        if (!_handlers.TryGetValue(envelope.Scheme, out IEncryptionSchemeHandler? handler))
        {
            throw new PostQuantumCryptographicException(
                $"This value was encrypted with scheme {envelope.Scheme}, which is not registered. " +
                "Register the corresponding handler to decrypt it.");
        }

        return handler.Decrypt(envelope.KeyId, envelope.AssociatedData, envelope.Body);
    }

    /// <inheritdoc />
    public byte[] ProtectText(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        int byteCount = Encoding.UTF8.GetByteCount(plaintext);
        byte[] rented = System.Buffers.ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            int written = Encoding.UTF8.GetBytes(plaintext, rented);
            return Protect(rented.AsSpan(0, written));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(rented.AsSpan(0, byteCount));
            System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <inheritdoc />
    public string UnprotectText(ReadOnlyMemory<byte> protectedData)
    {
        byte[] plaintext = Unprotect(protectedData);
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
