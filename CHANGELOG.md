# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Hybrid envelope: fail closed on a tampered KEM-ciphertext length.** The 2-byte KEM
  ciphertext length lives in the envelope body, outside the AEAD associated data. A corrupted
  length marker could hand real ML-KEM a wrong-sized ciphertext, which threw a raw
  `ArgumentException`/`CryptographicException` out of `Decapsulate` instead of the library's
  `PostQuantumCryptographicException` — an unhandled exception on the query path. The hybrid
  handler now wraps that into `PostQuantumCryptographicException`, upholding the documented
  "single generic exception" contract.

### Documentation

- Documented that the associated data binds version/scheme/key id but **not** the table,
  column, or row, so an attacker with database write access can relocate a whole valid
  envelope to another location sharing the same key id and it will decrypt. Recorded the
  entity/property-binding and KEM-block-binding hardenings (gated on a format-version bump) in
  the threat model and KNOWN-GAPS.

## [0.1.0] — 2026-06-03

Initial release. Production-usable for encrypting sensitive EF Core columns at rest.

### Added

- **Authenticated envelope format `PQE1`** — self-describing, versioned, and dispatch-on-read.
  The header (magic, version, scheme id, key id) is bound into the AES-GCM associated data,
  preventing scheme downgrade and key-id confusion.
- **AES-256-GCM scheme** (`Aes256Gcm`) — fresh 96-bit nonce and 128-bit tag per value; data
  key supplied by a key ring. Works on .NET 8, 9, and 10.
- **ML-KEM-768 hybrid envelope scheme** (`MLKem768Aes256Gcm`) — per-value data key wrapped to
  an ML-KEM-768 (FIPS 203) public key, with HKDF-SHA256 key derivation; data encrypted with
  AES-256-GCM. Feature-detected at compile time (.NET 10+) and run time (`IsSupported`).
- **`IPostQuantumProtector`** with `Protect`/`Unprotect` and UTF-8 text helpers; thread-safe,
  singleton-friendly.
- **Key-ring abstractions** — `IDataProtectionKeyRing` and `IKeyEncapsulationKeyRing` — the
  integration seam for PostQuantum.KeyManagement, with in-memory implementations for
  development and tests. Key material is zeroized on dispose.
- **EF Core integration** — `EncryptedStringConverter`, `EncryptedBinaryConverter`, and
  `IsEncrypted(protector)` property-builder extensions for `string`, `string?`, and `byte[]`.
- **Dependency-injection** — `AddPostQuantumEncryption(builder => …)` with `UseAes256Gcm`,
  `UseMLKem768Envelope`, and a custom-KEM hook; supports running multiple schemes for
  migration.
- **Key rotation & scheme migration** — old values remain decryptable by their recorded key
  id and scheme while new writes use the active key/scheme.
- **Tests** — round-trips, tamper/forgery detection, scheme-downgrade rejection, wrong-key and
  missing-key handling, key rotation, hybrid-envelope coverage (deterministic + real ML-KEM),
  DI wiring, and full EF Core + SQLite integration across net8.0/net9.0/net10.0.
- **Runnable sample** — `samples/ClinicRecords` demonstrates encrypted patient PII/PHI and
  prints raw on-disk ciphertext to prove encryption at rest.
- **Supply chain** — Central Package Management, deterministic builds, SourceLink, symbol
  packages, CycloneDX SBOM generation, and CI across all target frameworks.

### Security

- Fail-closed decryption with generic error messages (no padding/tag oracle).
- No unauthenticated encryption mode; no third-party cryptographic implementations.

## What would come next

Kept intentionally short and honest — these strengthen the library but are not required for
the v0.1 scenarios:

- Optional `[Encrypted]` attribute / convention to complement the fluent API.
- A nonce-budget guard that warns before a data key approaches its safe message limit.
- Additional KEM parameter sets (ML-KEM-512/1024) behind the existing mechanism seam.
- A first-class PostQuantum.KeyManagement adapter package and a re-encryption sweep helper.

[Unreleased]: https://github.com/systemslibrarian/postquantum-entityframeworkcore/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/systemslibrarian/postquantum-entityframeworkcore/releases/tag/v0.1.0
