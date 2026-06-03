namespace PostQuantum.EntityFrameworkCore.Crypto;

/// <summary>
/// Identifies the cryptographic scheme used to produce an encrypted envelope.
/// The numeric value is stored as a single byte in every envelope so that ciphertext
/// remains self-describing and decryptable after the active scheme changes.
/// </summary>
/// <remarks>
/// Values are part of the on-disk format contract and MUST never be reused or
/// renumbered once shipped.
/// </remarks>
public enum EncryptionScheme : byte
{
    /// <summary>
    /// AES-256-GCM with a 96-bit random nonce and a 128-bit authentication tag.
    /// The 256-bit data-encryption key is supplied directly by an
    /// <see cref="Keys.IDataProtectionKeyRing"/>. Symmetric AES-256 retains roughly
    /// 128 bits of security against Grover's algorithm and is the recommended
    /// quantum-resistant data cipher.
    /// </summary>
    Aes256Gcm = 1,

    /// <summary>
    /// Hybrid post-quantum envelope: a fresh random data-encryption key protects the
    /// payload with AES-256-GCM, and that key is wrapped to an ML-KEM-768 (FIPS 203)
    /// public key. Decryption requires ML-KEM decapsulation with the private key.
    /// This is the genuinely post-quantum scheme: the long-lived key-encryption key
    /// is protected by a NIST-standardized lattice KEM.
    /// </summary>
    MLKem768Aes256Gcm = 2,
}
