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
- **Associated data does not bind a value to its database location.** The AES-GCM associated
  data is the envelope header (version/scheme/key id) — plus, in the hybrid scheme, the KEM
  encapsulation block. It does **not** include the table, column, or primary key, so an
  attacker with database *write* access can copy a whole valid envelope from one row/column
  into another that shares the same key id and it will decrypt (see the threat model's
  *Ciphertext relocation/replay* row). Binding the entity/property into the associated data is
  a candidate enhancement gated on a future format-version bump — but note it cannot be
  complete at the EF value-converter layer, which never sees a row's primary key, so
  same-column row-to-row relocation would remain undefended even then.
- **The hybrid envelope now authenticates the full encapsulation (format v2).** As of 1.0 the
  KEM-ciphertext length and ciphertext are folded into the AES-GCM associated data, so the
  whole encapsulation is authenticated (an HPKE-style construction). Version-1 hybrid envelopes
  written by 0.1.0 — which authenticated only the header, and already failed closed on a
  tampered encapsulation because it produced a wrong derived key — are still read. The
  AES-256-GCM scheme is unchanged and continues to emit version-1 envelopes.

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
  readable by key id) and *supported* — rotate the active key in place with the ring's
  `AddKey`/`SetActiveKey`, and re-encrypt existing rows with `DbContext.ReEncryptAsync<T>()`
  (or `MarkEncryptedPropertiesModified` for custom sweeps) — but the library does not
  *schedule* rotation. You decide when to rotate and when to run the sweep. Note that rebuilding
  a fresh protector/ring to rotate does **not** work: EF Core caches the model (and the
  captured protector) per context type, so you must mutate the ring the protector already holds.
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
