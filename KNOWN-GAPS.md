# Known gaps & limitations

This document is deliberately frank. It lists what PostQuantum.EntityFrameworkCore **does
not** do today, so you can make an informed decision rather than discover a gap in
production. None of these are secret; several are intentional design choices.

## Cryptography & format

- **Non-deterministic encryption → no searchable columns.** Every value uses a fresh nonce
  (and, in the hybrid scheme, a fresh encapsulation). Encrypting the same plaintext twice
  yields different ciphertext. This is a security feature, but it means you **cannot** filter,
  index, sort, or join on an encrypted column in the database. If you need equality lookup on
  a protected value, you need deterministic or searchable encryption — not provided here.
- **Length is not hidden.** Ciphertext length is `plaintext length + fixed overhead` (header
  + nonce + tag, plus the KEM ciphertext for the hybrid scheme). If the *length* of a value
  is sensitive, pad it before encrypting.
- **No format-preserving encryption.** A 16-digit card number does not stay a 16-digit
  number; it becomes a binary envelope.
- **Single AEAD (AES-256-GCM).** ChaCha20-Poly1305 and AES-GCM-SIV are not offered. The
  96-bit random-nonce design means you should rotate a data-encryption key well before it
  encrypts anything close to 2³² values (birthday bound). The library does not currently
  enforce or count toward this limit for you.
- **One KEM (ML-KEM-768).** ML-KEM-512/1024 and other KEMs are not wired up. The
  `IKeyEncapsulationMechanism` seam exists so they *can* be added without a format change.

## Platform support

- **ML-KEM is .NET 10+ only**, and additionally requires OpenSSL 3.5+ (Linux/macOS) or recent
  Windows CNG at runtime. On .NET 8/9, or where the provider is missing, the hybrid scheme is
  unavailable and throws `PlatformNotSupportedException`. **AES-256-GCM works everywhere** on
  net8/9/10. There is no silent downgrade — you must choose the AES scheme explicitly when
  ML-KEM is absent.
- **CI/headless runners** frequently lack OpenSSL 3.5, so the real ML-KEM tests assert the
  "unsupported" path there. The envelope format itself is fully exercised on every platform
  via a deterministic test KEM.

## Key management

- **No key custody.** This library does not store, generate-at-rest, or guard keys beyond the
  lifetime of an in-memory ring. Production key custody is the responsibility of your
  key-management layer (PostQuantum.KeyManagement / HSM / KMS) implementing the ring
  interfaces.
- **No automatic rotation or re-encryption job.** Rotation is *safe* (old values stay
  readable by key id), but the library does not *schedule* rotation or sweep old rows. You
  drive that from your application or key-management layer.
- **In-memory keys are process-lifetime.** `InMemoryDataProtectionKeyRing` and
  `InMemoryKeyEncapsulationKeyRing` hold material in managed memory (zeroed on dispose). They
  are for development, tests, and small self-hosted use — not a substitute for an HSM.

## EF Core integration

- **Configured per `DbContext` via the fluent API.** There is no `[Encrypted]` attribute or
  global convention scan; you call `IsEncrypted(protector)` per property. This keeps the key
  dependency explicit and testable, at the cost of a little verbosity.
- **Null values are not encrypted.** EF Core does not pass `null` through value converters, so
  a `null` column stays `null`. The *absence* of a value is therefore visible.
- **No automatic migration of existing plaintext.** Turning on encryption for a column that
  already holds plaintext does not retroactively encrypt those rows; see
  [docs/migration.md](docs/migration.md) for the load-and-resave pattern.
- **Provider value-comparers.** Encrypted `byte[]` columns use EF's default byte-array
  handling; if you rely on change tracking of large binary blobs, benchmark for your workload.

## Operational

- **No built-in audit log** of encrypt/decrypt operations.
- **No telemetry/metrics** emitted by the library.
- **Branding/icon** is not yet shipped in the NuGet package (functional metadata is complete).

If one of these gaps is blocking you, please open an issue describing your scenario — it
helps prioritize. Security-sensitive gaps should follow [SECURITY.md](SECURITY.md).

> To God be the glory — 1 Corinthians 10:31
