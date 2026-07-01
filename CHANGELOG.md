# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-06-30

First stable release. Commits to Semantic Versioning for the 1.x line: the public API and the
envelope format (PQE1, scheme ids, format versions 1–2) are stable. Data written by 1.x stays
readable across 1.x.

### Added

- **In-place key rotation on the in-memory rings.** `InMemoryDataProtectionKeyRing` and
  `InMemoryKeyEncapsulationKeyRing` now expose thread-safe `AddKey`, `SetActiveKey`, and
  `RemoveKey`, so rotation works on the ring the protector already holds. (Rebuilding a fresh
  protector to rotate does not work — EF Core caches the model, including the captured
  protector — so this is the supported path; a KMS-backed ring reflects its active key
  dynamically.)
- **Re-encryption helpers** (`EncryptedDataMaintenance`): `DbContext.ReEncryptAsync<T>()`
  sweeps an entity's rows in batches and rewrites each encrypted column under the active
  key/scheme; `DbContext.MarkEncryptedPropertiesModified(entity)` does the same for a custom
  query. These force EF Core to re-run the value converter — a plain load-and-`SaveChanges`
  does not, because change tracking compares the unchanged decrypted value.
- **Fail-fast startup validation.** Constructing the protector now verifies that the default
  scheme is usable on this platform and has an active key, so a misconfiguration (for example
  ML-KEM as the default on a host without it) throws at construction/startup rather than on the
  first write.
- **Tracked public API surface.** A `PublicAPI.txt` baseline enforced by
  `Microsoft.CodeAnalysis.PublicApiAnalyzers` makes any change to the public surface a
  deliberate, reviewed edit.

### Changed

- **Hybrid envelope now authenticates the full encapsulation (format version 2).** The ML-KEM
  scheme folds the KEM block (length + ciphertext) into the AES-GCM associated data — an
  HPKE-style construction with no unauthenticated bytes in the body. Version-1 hybrid envelopes
  written by 0.1.0 are still read. The AES-256-GCM scheme is unchanged and continues to emit
  version-1 envelopes. **Compatibility:** 0.1.0 cannot read format-v2 hybrid envelopes, so
  upgrade all nodes before writing post-quantum values.
- **`IsEncrypted` rejects unsupported property types** with a clear, property-named error
  instead of an opaque EF Core model-build failure (use `string` or `byte[]`).

### Fixed

- **Hybrid envelope: fail closed on a tampered KEM-ciphertext length.** A corrupted length
  marker could hand real ML-KEM a wrong-sized ciphertext, throwing a raw
  `ArgumentException`/`CryptographicException` out of `Decapsulate` instead of the library's
  `PostQuantumCryptographicException`. The hybrid handler now wraps that, upholding the
  "single generic exception" contract. (In format v2 the length is also authenticated.)

### Security

- **Supply chain:** pinned the SQLite native bundle used by tests and the sample to a patched
  release (SQLitePCLRaw 3.x), clearing advisory GHSA-2m69-gcr7-jv3q. These are test/sample-only
  dependencies and are not part of the shipped library package.

### Documentation

- Added a "this library vs. Always Encrypted / TDE" comparison table and an explicit note that
  the library is **not** ASP.NET Core Data Protection.
- Expanded the key-rotation / re-encryption guide and documented the EF model-cache rotation
  gotcha. Recorded that location binding (entity/property/row) remains out of scope and cannot
  be complete at the value-converter layer.

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
the 1.0 scenarios:

- Optional `[Encrypted]` attribute / convention to complement the fluent API.
- A nonce-budget guard that warns before a data key approaches its safe message limit.
- Additional KEM parameter sets (ML-KEM-512/1024) behind the existing mechanism seam.
- A first-class PostQuantum.KeyManagement adapter package.

[Unreleased]: https://github.com/systemslibrarian/postquantum-entityframeworkcore/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/systemslibrarian/postquantum-entityframeworkcore/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/systemslibrarian/postquantum-entityframeworkcore/releases/tag/v0.1.0
