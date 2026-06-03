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

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        KeyEncapsulationKeyPair publicKey = _keyRing.ActiveKey;
        byte[] header = EncryptedEnvelope.WriteHeader(Scheme, publicKey.KeyId);

        EncapsulationResult encapsulation = _kem.Encapsulate(publicKey);
        byte[] sharedSecret = encapsulation.SharedSecret;
        byte[] kemCiphertext = encapsulation.Ciphertext;

        if (kemCiphertext.Length > ushort.MaxValue)
        {
            throw new PostQuantumCryptographicException("KEM ciphertext is unexpectedly large.");
        }

        Span<byte> dek = stackalloc byte[AuthenticatedCipher.KeySizeInBytes];
        try
        {
            DeriveKey(sharedSecret, publicKey.KeyId, dek);
            byte[] dem = AuthenticatedCipher.Encrypt(dek, plaintext, header);

            var body = new byte[2 + kemCiphertext.Length + dem.Length];
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(0, 2), (ushort)kemCiphertext.Length);
            kemCiphertext.CopyTo(body.AsSpan(2));
            dem.CopyTo(body.AsSpan(2 + kemCiphertext.Length));

            var envelope = new byte[header.Length + body.Length];
            header.CopyTo(envelope.AsSpan());
            body.CopyTo(envelope.AsSpan(header.Length));
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

        byte[] sharedSecret = _kem.Decapsulate(pair, kemCiphertext.Span);
        Span<byte> dek = stackalloc byte[AuthenticatedCipher.KeySizeInBytes];
        try
        {
            DeriveKey(sharedSecret, keyId, dek);
            return AuthenticatedCipher.Decrypt(dek, dem.Span, associatedData.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
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
