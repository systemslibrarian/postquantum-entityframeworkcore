using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.EntityFrameworkCore.Keys;

namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// Implements <see cref="EncryptionScheme.MLKem768Aes256Gcm"/>: a hybrid KEM/DEM envelope.
/// </summary>
/// <remarks>
/// <para>For each value:</para>
/// <list type="number">
/// <item>Encapsulate to the active ML-KEM public key, yielding a ciphertext and a shared secret.</item>
/// <item>Derive a fresh 256-bit data-encryption key from the shared secret with HKDF-SHA256.</item>
/// <item>Encrypt the value with AES-256-GCM under that key, authenticating the envelope header.</item>
/// </list>
/// <para>Body layout: <c>kemCtLen(2, big-endian) || kemCiphertext || nonce(12) || tag(16) || ciphertext</c>.</para>
/// <para>
/// HKDF binds the derivation to the key id (as salt) and a fixed context string (as info),
/// providing domain separation across schemes and keys.
/// </para>
/// <para>
/// <b>Format version 2 (current).</b> The AES-GCM associated data is the envelope header
/// <i>plus</i> the KEM block (<c>kemCtLen || kemCiphertext</c>), so the entire encapsulation
/// is authenticated — an HPKE-style construction with no unauthenticated bytes in the body.
/// Version-1 hybrid envelopes written by 0.1.0 (which authenticated only the header) are
/// still read: decryption rebuilds the version-1 associated data when it sees version 1.
/// </para>
/// </remarks>
internal sealed class MLKemEnvelopeSchemeHandler : IEncryptionSchemeHandler
{
    private static readonly byte[] HkdfInfo =
        Encoding.ASCII.GetBytes("PQEF/ML-KEM-768+AES-256-GCM/v1");

    private readonly IKeyEncapsulationKeyRing _keyRing;
    private readonly IKeyEncapsulationMechanism _kem;

    internal MLKemEnvelopeSchemeHandler(IKeyEncapsulationKeyRing keyRing, IKeyEncapsulationMechanism kem)
    {
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
        _kem = kem ?? throw new ArgumentNullException(nameof(kem));
    }

    public EncryptionScheme Scheme => EncryptionScheme.MLKem768Aes256Gcm;

    public void ValidateReady()
    {
        if (!_kem.IsSupported)
        {
            throw new PlatformNotSupportedException(
                $"The {Scheme} scheme is configured as the default for new writes, but the " +
                $"'{_kem.AlgorithmName}' mechanism is unavailable on this platform. ML-KEM requires " +
                ".NET 10+ with OpenSSL 3.5+ (Linux/macOS) or a recent Windows CNG. Probe " +
                "MLKemKeyEncapsulationMechanism.IsSupported at startup and fall back to UseAes256Gcm " +
                "where it is false. See KNOWN-GAPS.md.");
        }

        KeyEncapsulationKeyPair active = _keyRing.ActiveKey
            ?? throw new PostQuantumCryptographicException(
                "The key-encapsulation key ring returned no active key for the ML-KEM hybrid scheme.");
        _ = active.KeyId;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        KeyEncapsulationKeyPair publicKey = _keyRing.ActiveKey;
        byte[] header = EncryptedEnvelope.WriteHeader(Scheme, publicKey.KeyId, EncryptedEnvelope.HybridFormatVersion);

        EncapsulationResult encapsulation = _kem.Encapsulate(publicKey);
        byte[] sharedSecret = encapsulation.SharedSecret;
        byte[] kemCiphertext = encapsulation.Ciphertext;

        if (kemCiphertext.Length > ushort.MaxValue)
        {
            throw new PostQuantumCryptographicException("KEM ciphertext is unexpectedly large.");
        }

        // The KEM block (length + ciphertext) sits at the front of the body and is also
        // folded into the AEAD associated data (format version 2), so the full encapsulation
        // is authenticated alongside the header.
        var kemBlock = new byte[2 + kemCiphertext.Length];
        BinaryPrimitives.WriteUInt16BigEndian(kemBlock.AsSpan(0, 2), (ushort)kemCiphertext.Length);
        kemCiphertext.CopyTo(kemBlock.AsSpan(2));

        byte[] associatedData = BuildAssociatedData(header, kemBlock);

        Span<byte> dek = stackalloc byte[AuthenticatedCipher.KeySizeInBytes];
        try
        {
            DeriveKey(sharedSecret, publicKey.KeyId, dek);
            byte[] dem = AuthenticatedCipher.Encrypt(dek, plaintext, associatedData);

            var envelope = new byte[header.Length + kemBlock.Length + dem.Length];
            header.CopyTo(envelope.AsSpan());
            kemBlock.CopyTo(envelope.AsSpan(header.Length));
            dem.CopyTo(envelope.AsSpan(header.Length + kemBlock.Length));
            return envelope;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    public byte[] Decrypt(string keyId, ReadOnlyMemory<byte> associatedData, ReadOnlyMemory<byte> body)
    {
        ReadOnlySpan<byte> span = body.Span;
        if (span.Length < 2)
        {
            throw new PostQuantumCryptographicException("Envelope body is too short to contain a KEM ciphertext length.");
        }

        int kemCtLength = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(0, 2));
        if (span.Length < 2 + kemCtLength)
        {
            throw new PostQuantumCryptographicException("Envelope body is truncated within the KEM ciphertext.");
        }

        ReadOnlyMemory<byte> kemBlock = body.Slice(0, 2 + kemCtLength);
        ReadOnlyMemory<byte> kemCiphertext = body.Slice(2, kemCtLength);
        ReadOnlyMemory<byte> dem = body.Slice(2 + kemCtLength);

        KeyEncapsulationKeyPair pair = _keyRing.Find(keyId)
            ?? throw new PostQuantumCryptographicException(
                $"No key-encapsulation key with id '{keyId}' is available to decrypt this value.");

        if (!pair.CanDecapsulate)
        {
            throw new PostQuantumCryptographicException(
                $"Key-encapsulation key '{keyId}' has no private material and cannot decrypt.");
        }

        byte[] sharedSecret;
        try
        {
            sharedSecret = _kem.Decapsulate(pair, kemCiphertext.Span);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            // The KEM-ciphertext length marker lives in the body, outside the AEAD associated
            // data, so a tamperer can present the KEM with a wrong-sized ciphertext. Real
            // ML-KEM rejects that with a raw ArgumentException/CryptographicException; convert
            // it to the library's single generic failure so the envelope fails closed instead
            // of crashing the caller (the documented "quiet errors" contract).
            throw new PostQuantumCryptographicException(
                "Decryption failed: the envelope could not be authenticated. This indicates " +
                "tampering, corruption, or use of the wrong key.", ex);
        }

        // Format version 2 folds the KEM block into the associated data; version 1 (written
        // by 0.1.0) authenticated only the header. Rebuild the matching AAD for the version.
        byte version = associatedData.Span[EncryptedEnvelope.VersionOffset];
        byte[]? aadBuffer = version >= EncryptedEnvelope.HybridFormatVersion
            ? BuildAssociatedData(associatedData.Span, kemBlock.Span)
            : null;
        ReadOnlySpan<byte> aad = aadBuffer ?? associatedData.Span;

        Span<byte> dek = stackalloc byte[AuthenticatedCipher.KeySizeInBytes];
        try
        {
            DeriveKey(sharedSecret, keyId, dek);
            return AuthenticatedCipher.Decrypt(dek, dem.Span, aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>
    /// Concatenates the envelope header and the KEM block into the associated data used by
    /// the version-2 hybrid construction, so the entire encapsulation is authenticated.
    /// </summary>
    private static byte[] BuildAssociatedData(ReadOnlySpan<byte> header, ReadOnlySpan<byte> kemBlock)
    {
        var associatedData = new byte[header.Length + kemBlock.Length];
        header.CopyTo(associatedData);
        kemBlock.CopyTo(associatedData.AsSpan(header.Length));
        return associatedData;
    }

    private static void DeriveKey(ReadOnlySpan<byte> sharedSecret, string keyId, Span<byte> destination)
    {
        Span<byte> salt = stackalloc byte[EncryptedEnvelope.MaxKeyIdLength];
        int saltLength = Encoding.UTF8.GetBytes(keyId, salt);
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: sharedSecret,
            output: destination,
            salt: salt[..saltLength],
            info: HkdfInfo);
    }
}
