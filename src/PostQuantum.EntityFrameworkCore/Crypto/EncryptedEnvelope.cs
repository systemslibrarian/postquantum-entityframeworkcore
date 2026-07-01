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
/// 0       4     Magic ("PQE1" — a fixed family marker, not the format version)
/// 4       1     Format version (see remarks)
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
/// <para>
/// <b>Format versions.</b> The 4-byte magic is a constant brand marker; the version
/// <i>byte</i> at offset 4 is authoritative. Version <c>1</c> is the original layout.
/// Version <c>2</c> is used only by the hybrid scheme and additionally folds the KEM
/// encapsulation block (its 2-byte length and ciphertext) into the AES-GCM associated
/// data, so the entire encapsulation is authenticated (an HPKE-style construction). The
/// AES-256-GCM scheme has no encapsulation block and continues to emit version <c>1</c>,
/// so existing AES envelopes are bit-for-bit unchanged. Readers accept versions 1 and 2.
/// </para>
/// </remarks>
internal static class EncryptedEnvelope
{
    /// <summary>ASCII "PQE1" — magic bytes that prefix every envelope.</summary>
    internal static readonly byte[] Magic = "PQE1"u8.ToArray();

    /// <summary>
    /// Original envelope format version. Emitted by schemes that have no key-encapsulation
    /// block (currently AES-256-GCM) and read for all schemes for backward compatibility.
    /// </summary>
    internal const byte FormatVersion = 1;

    /// <summary>
    /// Hybrid envelope format version: identical header layout to version 1, but the KEM
    /// encapsulation block is additionally included in the AEAD associated data. Emitted by
    /// the ML-KEM hybrid scheme; version-1 hybrid envelopes (written by 0.1.0) still decrypt.
    /// </summary>
    internal const byte HybridFormatVersion = 2;

    /// <summary>Byte offset of the format-version field within every envelope header.</summary>
    internal const int VersionOffset = 4;

    private const int MagicLength = 4;
    private const int MinHeaderLength = MagicLength + 1 + 1 + 2; // magic + version + scheme + keyIdLen

    /// <summary>Largest key id we will read or write, in UTF-8 bytes.</summary>
    internal const int MaxKeyIdLength = 512;

    /// <summary>
    /// Builds the envelope header for the given scheme and key id. The returned bytes are
    /// both the literal prefix of the envelope and the associated data for authenticated
    /// encryption.
    /// </summary>
    internal static byte[] WriteHeader(EncryptionScheme scheme, string keyId, byte version = FormatVersion)
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
        header[VersionOffset] = version;
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

        byte version = span[VersionOffset];
        if (version is not (FormatVersion or HybridFormatVersion))
        {
            throw new PostQuantumCryptographicException(
                $"Unsupported envelope format version {version}. This build understands versions " +
                $"{FormatVersion} and {HybridFormatVersion}.");
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
        return new ParsedEnvelope(version, scheme, keyId, associatedData, body);
    }
}

/// <summary>The decomposed result of <see cref="EncryptedEnvelope.Parse"/>.</summary>
internal readonly struct ParsedEnvelope
{
    internal ParsedEnvelope(
        byte version,
        EncryptionScheme scheme,
        string keyId,
        ReadOnlyMemory<byte> associatedData,
        ReadOnlyMemory<byte> body)
    {
        Version = version;
        Scheme = scheme;
        KeyId = keyId;
        AssociatedData = associatedData;
        Body = body;
    }

    /// <summary>The format version declared by the envelope header (1 or 2).</summary>
    internal byte Version { get; }

    /// <summary>The scheme declared by the envelope header.</summary>
    internal EncryptionScheme Scheme { get; }

    /// <summary>The key id declared by the envelope header.</summary>
    internal string KeyId { get; }

    /// <summary>The full header bytes, used verbatim as authenticated associated data.</summary>
    internal ReadOnlyMemory<byte> AssociatedData { get; }

    /// <summary>The scheme-specific body following the header.</summary>
    internal ReadOnlyMemory<byte> Body { get; }
}
