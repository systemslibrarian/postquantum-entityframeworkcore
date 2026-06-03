using System.Buffers.Binary;
using System.Text;

namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// Reads and writes the self-describing binary envelope that wraps every encrypted value.
/// </summary>
/// <remarks>
/// <para>The fixed header is identical for every scheme:</para>
/// <code>
/// Offset  Size  Field
/// 0       4     Magic ("PQE1")
/// 4       1     Format version (currently 1)
/// 5       1     Scheme id (see EncryptionScheme)
/// 6       2     Key id length, big-endian uint16
/// 8       L     Key id (UTF-8)
/// 8+L     ..    Scheme-specific body
/// </code>
/// <para>
/// The entire header (bytes <c>0 .. 8+L</c>) is used verbatim as the AES-GCM associated
/// data, which cryptographically binds the format version, scheme, and key id to the
/// ciphertext. An attacker cannot downgrade the scheme, swap the key id, or strip the
/// version without invalidating the authentication tag.
/// </para>
/// </remarks>
internal static class EncryptedEnvelope
{
    /// <summary>ASCII "PQE1" — magic bytes that prefix every envelope.</summary>
    internal static readonly byte[] Magic = "PQE1"u8.ToArray();

    /// <summary>Current envelope format version.</summary>
    internal const byte FormatVersion = 1;

    private const int MagicLength = 4;
    private const int MinHeaderLength = MagicLength + 1 + 1 + 2; // magic + version + scheme + keyIdLen

    /// <summary>Largest key id we will read or write, in UTF-8 bytes.</summary>
    internal const int MaxKeyIdLength = 512;

    /// <summary>
    /// Builds the envelope header for the given scheme and key id. The returned bytes are
    /// both the literal prefix of the envelope and the associated data for authenticated
    /// encryption.
    /// </summary>
    internal static byte[] WriteHeader(EncryptionScheme scheme, string keyId)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        int keyIdByteCount = Encoding.UTF8.GetByteCount(keyId);
        if (keyIdByteCount == 0)
        {
            throw new ArgumentException("Key id must not be empty.", nameof(keyId));
        }

        if (keyIdByteCount > MaxKeyIdLength)
        {
            throw new ArgumentException(
                $"Key id exceeds the maximum length of {MaxKeyIdLength} UTF-8 bytes.", nameof(keyId));
        }

        var header = new byte[MinHeaderLength + keyIdByteCount];
        Magic.CopyTo(header.AsSpan());
        header[4] = FormatVersion;
        header[5] = (byte)scheme;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6, 2), (ushort)keyIdByteCount);
        Encoding.UTF8.GetBytes(keyId, header.AsSpan(MinHeaderLength));
        return header;
    }

    /// <summary>
    /// Parses and validates the header of an encrypted payload.
    /// </summary>
    /// <exception cref="PostQuantumCryptographicException">
    /// The payload is too short, has an unrecognized magic value, or declares an
    /// unsupported format version.
    /// </exception>
    internal static ParsedEnvelope Parse(ReadOnlyMemory<byte> payload)
    {
        ReadOnlySpan<byte> span = payload.Span;
        if (span.Length < MinHeaderLength)
        {
            throw new PostQuantumCryptographicException("Encrypted payload is too short to contain a valid header.");
        }

        if (!span[..MagicLength].SequenceEqual(Magic))
        {
            throw new PostQuantumCryptographicException("Encrypted payload is not a recognized PostQuantum envelope.");
        }

        byte version = span[4];
        if (version != FormatVersion)
        {
            throw new PostQuantumCryptographicException(
                $"Unsupported envelope format version {version}. This build understands version {FormatVersion}.");
        }

        var scheme = (EncryptionScheme)span[5];
        int keyIdLength = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(6, 2));
        if (keyIdLength == 0 || keyIdLength > MaxKeyIdLength)
        {
            throw new PostQuantumCryptographicException("Encrypted payload declares an invalid key id length.");
        }

        int headerLength = MinHeaderLength + keyIdLength;
        if (span.Length < headerLength)
        {
            throw new PostQuantumCryptographicException("Encrypted payload is truncated within its header.");
        }

        string keyId = Encoding.UTF8.GetString(span.Slice(MinHeaderLength, keyIdLength));

        // The header bytes ARE the associated data used to authenticate the body.
        ReadOnlyMemory<byte> associatedData = payload[..headerLength];
        ReadOnlyMemory<byte> body = payload[headerLength..];
        return new ParsedEnvelope(scheme, keyId, associatedData, body);
    }
}

/// <summary>The decomposed result of <see cref="EncryptedEnvelope.Parse"/>.</summary>
internal readonly struct ParsedEnvelope
{
    internal ParsedEnvelope(
        EncryptionScheme scheme,
        string keyId,
        ReadOnlyMemory<byte> associatedData,
        ReadOnlyMemory<byte> body)
    {
        Scheme = scheme;
        KeyId = keyId;
        AssociatedData = associatedData;
        Body = body;
    }

    /// <summary>The scheme declared by the envelope header.</summary>
    internal EncryptionScheme Scheme { get; }

    /// <summary>The key id declared by the envelope header.</summary>
    internal string KeyId { get; }

    /// <summary>The full header bytes, used verbatim as authenticated associated data.</summary>
    internal ReadOnlyMemory<byte> AssociatedData { get; }

    /// <summary>The scheme-specific body following the header.</summary>
    internal ReadOnlyMemory<byte> Body { get; }
}
