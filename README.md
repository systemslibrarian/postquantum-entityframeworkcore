# PostQuantum.EntityFrameworkCore

**Secure-by-default, post-quantum encryption for sensitive data at rest in Entity Framework Core.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Target Frameworks](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4.svg)](#requirements)
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20%2B%20ML--KEM--768-0a7.svg)](#how-it-works)

Encrypt individual EF Core properties — emails, national IDs, medical notes, financial
details — with authenticated **AES-256-GCM**, optionally wrapped in an **ML-KEM-768
(FIPS 203)** hybrid envelope so the key that protects your data is itself protected by a
NIST-standardized post-quantum algorithm. One line per column:

```csharp
b.Property(p => p.Email).IsEncrypted(protector);
```

> To God be the glory — 1 Corinthians 10:31

---

## Table of contents

- [Why this library exists](#why-this-library-exists)
- [When to use this — and when not to](#when-to-use-this--and-when-not-to)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Integrating with PostQuantum.KeyManagement](#integrating-with-postquantumkeymanagement)
- [Key rotation](#key-rotation)
- [Threat model](#threat-model)
- [Honest limitations](#honest-limitations)
- [Requirements](#requirements)
- [Supply chain & verification](#supply-chain--verification)
- [Project layout](#project-layout)
- [Building & testing](#building--testing)
- [Versioning & roadmap](#versioning--roadmap)
- [License](#license)

---

## Why this library exists

Most "encrypt a column" solutions share two problems:

1. **They are not authenticated.** Plain AES-CBC or a naive XOR leaves ciphertext that an
   attacker can silently flip. This library uses AES-256-**GCM** and binds the envelope
   header (version, scheme, key id) into the authentication tag, so any tampering — including
   a *downgrade* of the scheme byte or a swap of the key id — is detected on decrypt.
2. **They ignore the quantum horizon.** "Harvest now, decrypt later" is a real strategy:
   an adversary captures encrypted data today and decrypts it once a cryptographically
   relevant quantum computer exists. Symmetric AES-256 is already a strong post-quantum
   choice (Grover's algorithm only halves its effective strength, leaving ~128 bits). The
   weak link is usually the *asymmetric* key wrapping — which is exactly what this library
   replaces with **ML-KEM-768**, the lattice KEM standardized by NIST in FIPS 203.

The result is a small, auditable library that makes the *right* thing the *easy* thing: a
single `.IsEncrypted(protector)` call, strong defaults you don't have to think about, and a
clean seam for real key management.

## When to use this — and when not to

**Good fit**

- You have a handful of genuinely sensitive **columns** (PII, PHI, financial data, secrets,
  tokens) you want encrypted at rest, independently of disk/database transparent encryption.
- You want **defense in depth**: even an attacker with a database dump, a stolen backup, or
  read access to storage sees only authenticated ciphertext.
- You want a **post-quantum migration path** for the key-wrapping layer without rewriting
  your data layer.
- You can tolerate that encrypted columns are **not searchable** in the database.

**Poor fit (use something else)**

- You need to **query, sort, index, or join** on the protected value in the database. This
  library uses non-deterministic encryption on purpose; equality search would require
  deterministic or searchable encryption, which has its own trade-offs and is out of scope.
- You want to encrypt the **entire database** transparently — use TDE / filesystem
  encryption (and consider using this *on top* for the few crown-jewel columns).
- You need **format-preserving** encryption (e.g. keep a 16-digit number 16 digits).

### This library vs. full-database solutions

| | **This library** (field encryption) | **Always Encrypted** (SQL Server) | **TDE** / filesystem encryption |
| --- | --- | --- | --- |
| **Granularity** | Per chosen column | Per chosen column | Whole database / disk |
| **Threat covered** | DB dump, backup, storage read access | DB admin + storage; keys stay client-side | DB files / disk at rest |
| **Protects against a live, compromised DB connection** | Yes (server only ever sees ciphertext) | Yes | **No** (data is decrypted for any valid connection) |
| **Queryable encrypted columns** | No (non-deterministic) | Limited (deterministic columns only) | Yes (transparent) |
| **Post-quantum key wrapping** | **Yes** (ML-KEM-768 option) | No | No |
| **Database engine support** | Any EF Core provider | SQL Server / Azure SQL | Engine-specific |
| **Key custody** | Your KMS/HSM via key rings | Windows cert store / Azure Key Vault | Engine / OS |

**Rule of thumb:** use **TDE/filesystem encryption** for blanket at-rest protection of the
whole database, and add **this library on top** for the few crown-jewel columns you want
protected even from someone who can read the live database — with a post-quantum migration
path for the key-wrapping layer. Reach for **Always Encrypted** instead if you are all-in on
SQL Server and need limited equality queries on protected columns.

> **Not** ASP.NET Core Data Protection. Despite the familiar `Protect`/`Unprotect` shape and
> the `IDataProtectionKeyRing` name, this library does not use or extend
> `Microsoft.AspNetCore.DataProtection`. That stack is not post-quantum and has a different
> key-lifetime and rotation model; this library is a separate, purpose-built at-rest cipher.

## Quick start

Install (from this repository or, once published, from NuGet):

```bash
dotnet add package PostQuantum.EntityFrameworkCore
```

Configure a protector and mark your sensitive properties:

```csharp
using PostQuantum.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.DependencyInjection;
using PostQuantum.EntityFrameworkCore.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Keys;

// 1. Provision a data-encryption key. In production this comes from a managed key store
//    (see "Integrating with PostQuantum.KeyManagement"); here we load 32 bytes you control.
var dek = new DataEncryptionKey("dek-2026-01", keyMaterial /* 32 bytes */);

// 2. Register the protector.
services.AddPostQuantumEncryption(pq =>
{
    pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek));
});

// 3. Mark properties as encrypted in your DbContext.
public sealed class ClinicContext(DbContextOptions<ClinicContext> options, IPostQuantumProtector protector)
    : DbContext(options)
{
    public DbSet<Patient> Patients => Set<Patient>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Patient>(b =>
        {
            b.Property(p => p.Email).IsEncrypted(protector);       // string
            b.Property(p => p.Diagnosis).IsEncrypted(protector);   // string?
            b.Property(p => p.ScannedForm).IsEncrypted(protector); // byte[]
        });
    }
}
```

That's it. Reads and writes are transparent; the database stores authenticated ciphertext.

**Turn on the post-quantum envelope** (on a platform with ML-KEM support — see
[Requirements](#requirements)):

```csharp
services.AddPostQuantumEncryption(pq =>
{
    pq.UseAes256Gcm(dekRing, asDefault: false);   // keep AES available to read legacy rows
    pq.UseMLKem768Envelope(kekRing);              // new writes use ML-KEM-768 + AES-256-GCM
});
```

A complete, runnable example lives in [`samples/ClinicRecords`](samples/ClinicRecords) —
it inserts patient records, reads them back decrypted, and dumps the raw on-disk bytes to
prove they are ciphertext.

## How it works

Every encrypted value is a single, self-describing **envelope** (`byte[]`, store it as
`varbinary`/`BLOB`):

```
PQE1 | ver | scheme | keyIdLen | keyId | scheme-specific body
└──────────── authenticated as associated data ────────────┘
```

Because the whole header is fed to AES-GCM as associated data, the format version, the
scheme, and the key id are all cryptographically bound to the ciphertext. There is **no
silent downgrade** and **no key-id confusion**. The hybrid scheme additionally folds its KEM
encapsulation block into the associated data (envelope format version 2), so the entire
encapsulation is authenticated — an HPKE-style construction. The `PQE1` magic is a fixed
family marker; the version *byte* governs the layout, and readers accept versions 1 and 2.

| Scheme | Id | What it does | Post-quantum? |
| --- | --- | --- | --- |
| `Aes256Gcm` | 1 | AES-256-GCM with a fresh 96-bit nonce and 128-bit tag; key supplied directly. | Symmetric layer only (AES-256 ≈ 128-bit vs. Grover). |
| `MLKem768Aes256Gcm` | 2 | Per-value random data key encrypts the data (AES-256-GCM); that data key is wrapped to an **ML-KEM-768** public key. HKDF-SHA256 derives the data key from the KEM shared secret. | **Yes** — the long-lived key-encryption key is a NIST FIPS 203 lattice KEM. |

The envelope is **versioned and dispatch-on-read**: a protector decrypts each value using
the scheme and key id recorded *in that value*, so you can change the default scheme or
rotate keys and still read everything written before.

## Integrating with PostQuantum.KeyManagement

This library deliberately does **not** own key custody, rotation scheduling, or auditing.
Instead it defines two small seams:

- `IDataProtectionKeyRing` — supplies symmetric data-encryption keys (DEKs) by id.
- `IKeyEncapsulationKeyRing` — supplies ML-KEM key pairs (KEKs) by id, optionally
  private-key-less on encrypt-only nodes.

The shipped `InMemory…` implementations are perfect for development, tests, and small
self-hosted deployments. For production, implement these interfaces over
**PostQuantum.KeyManagement**, an HSM, or a cloud KMS:

```csharp
public sealed class KeyManagementDekRing(IKeyVault vault) : IDataProtectionKeyRing
{
    public DataEncryptionKey ActiveKey => vault.GetActiveDataKey();
    public DataEncryptionKey? Find(string keyId) => vault.TryGetDataKey(keyId);
}

services.AddPostQuantumEncryption(pq =>
    pq.UseAes256Gcm(sp => sp.GetRequiredService<KeyManagementDekRing>()));
```

The factory overloads (`Use…(sp => …)`) resolve the ring from DI so your key store can have
its own dependencies, lifetime, and disposal.

## Key rotation

Rotation is first-class because the key id travels inside every envelope. Rotate **in place**
on the ring the protector already holds:

```csharp
dekRing.AddKey(DataEncryptionKey.Generate("dek-2026-07")); // add the new key
dekRing.SetActiveKey("dek-2026-07");                        // new writes use it; old rows still decrypt
int rewritten = await db.ReEncryptAsync<Customer>();       // re-encrypt existing rows under the new key
dekRing.RemoveKey("dek-2026-01");                          // retire the old key once the sweep is done
```

1. Add a new key and activate it. New writes use it automatically; existing rows still decrypt
   by their recorded key id.
2. Re-encrypt old rows with `ReEncryptAsync<T>()` (or `MarkEncryptedPropertiesModified` for a
   custom query) to retire a key. A plain load-and-`SaveChanges` will **not** rewrite an
   unchanged value — change tracking compares the decrypted value — so the helper marks the
   columns for you.
3. Remove the old key from the ring.

> **Rotate in place, not by swapping the protector.** EF Core caches the model, and the value
> converters in that cached model capture the protector instance. Build a *new* protector/ring
> and nothing changes until the cache is invalidated — so mutate the ring the protector holds
> (the in-memory rings are thread-safe; a KMS-backed ring reflects its active key dynamically).

The same applies to schemes: register both the AES and ML-KEM handlers during a migration
and old AES rows keep decrypting while new rows use the post-quantum envelope. See
[docs/migration.md](docs/migration.md) for the full rotation and backfill guide.

## Threat model

**What this protects against**

- **Database-at-rest compromise** — stolen DB files, leaked backups, snapshot exfiltration,
  storage-layer read access: the attacker sees only authenticated ciphertext.
- **Tampering / forgery** — any bit flip in ciphertext, nonce, tag, scheme byte, or key id
  fails authentication and raises `PostQuantumCryptographicException`. No tampered value is
  ever returned as plaintext.
- **Scheme downgrade** — the scheme id is authenticated, so an attacker cannot coerce a
  value to be read under a weaker scheme.
- **"Harvest now, decrypt later"** — with the ML-KEM-768 envelope, captured ciphertext is
  not unlocked by a future quantum computer attacking the key-wrapping layer.

**What it explicitly does NOT protect against**

- **A compromised application process or key store.** If the attacker can read the live
  DEK/KEK (process memory, the key vault), they can decrypt. Key custody is the job of your
  key-management layer, not this library.
- **Plaintext elsewhere.** Logs, caches, search indexes, debuggers, and crash dumps may hold
  decrypted values. Encryption-at-rest does not encrypt your application's memory.
- **Traffic analysis / size leakage.** Ciphertext length is a known function of plaintext
  length (plus a fixed overhead). Pad upstream if length is sensitive.
- **Correlation by other columns.** You can still link rows via unencrypted columns.
- **Ciphertext relocation by an attacker with write access.** The associated data binds the
  version, scheme, and key id — not the table, column, or row — so a whole valid envelope
  copied into another location that shares the same key id still decrypts. Tampered *bytes*
  are always rejected; *relocated* intact envelopes are not. See the
  [threat model](docs/threat-model.md) and [KNOWN-GAPS.md](KNOWN-GAPS.md).

See [SECURITY.md](SECURITY.md) for reporting and [KNOWN-GAPS.md](KNOWN-GAPS.md) for a frank,
itemized list of current limitations.

## Honest limitations

- **Encrypted columns are not queryable** in the database (no `WHERE`, index, sort, or join
  on the protected value). This is intentional — encryption is non-deterministic.
- **No automatic key rotation/scheduling.** The library makes rotation *safe* and provides
  helpers to perform it (`AddKey`/`SetActiveKey`/`RemoveKey` on the ring and
  `ReEncryptAsync<T>()`), but it does not *schedule* it — you decide when. Scheduling belongs
  in PostQuantum.KeyManagement.
- **ML-KEM availability is platform-dependent** (see below). Where unavailable, you get a
  clear `PlatformNotSupportedException` rather than a silent downgrade. AES-256-GCM always
  works.
- **No `[Encrypted]` data-annotation attribute** — configuration is via the explicit fluent
  `IsEncrypted(protector)` API, which keeps key wiring visible and testable.

## Requirements

- **.NET 8, 9, or 10.** The AES-256-GCM scheme works on all three.
- **ML-KEM-768 requires .NET 10+** *and* a platform crypto provider:
  - Linux/macOS: **OpenSSL 3.5 or newer**.
  - Windows: a recent **CNG** with ML-KEM support.
  - Detect at runtime with `new MLKemKeyEncapsulationMechanism().IsSupported`. When `false`,
    every ML-KEM operation throws `PlatformNotSupportedException` — it never degrades silently.

## Supply chain & verification

We treat the supply chain as part of the security boundary:

- **MIT-licensed, source-available**, with a small dependency surface (EF Core and the
  Microsoft.Extensions abstractions). Crypto comes from the **.NET base class library**
  (`AesGcm`, `HKDF`, `MLKem`) — no third-party crypto implementations.
- **Central Package Management** (`Directory.Packages.props`) pins every version so builds
  are auditable and reproducible.
- **Deterministic builds** with **SourceLink** and embedded untracked sources, plus a
  **symbol package** (`.snupkg`), so you can debug into the exact published source.
- **SBOM** (CycloneDX) is generated in CI and on demand via
  [`scripts/generate-sbom.sh`](scripts/generate-sbom.sh).
- **CI** builds and tests on every target framework (`.github/workflows/ci.yml`).

To verify a build yourself:

```bash
git clone https://github.com/systemslibrarian/postquantum-entityframeworkcore
cd postquantum-entityframeworkcore
dotnet test -c Release                 # builds + runs the full test suite on net8/9/10
./scripts/generate-sbom.sh             # produces sbom/*.cdx.json (requires network once)
dotnet pack -c Release                 # produces the .nupkg + .snupkg under artifacts/
```

The `PQE1` envelope format and the schemes above are fully specified in this README and the
source — there is no hidden format. Anyone can independently parse, audit, or re-implement
an envelope.

## Project layout

```
src/PostQuantum.EntityFrameworkCore/   The library
  Crypto/        Envelope format, schemes, AES-GCM, ML-KEM mechanism
  Keys/          DEK/KEK types, key-ring abstractions + in-memory implementations
  EntityFrameworkCore/  Value converters + IsEncrypted() property extensions
  DependencyInjection/  AddPostQuantumEncryption + builder
tests/           xUnit suite (round-trips, tamper, rotation, EF integration, ML-KEM)
samples/ClinicRecords/   Runnable end-to-end demo with SQLite
docs/            Getting started, threat model, migration notes
scripts/         SBOM generation
```

## Building & testing

```bash
dotnet build -c Release        # all target frameworks
dotnet test  -c Release        # full suite
dotnet format --verify-no-changes
dotnet run --project samples/ClinicRecords
```

## Versioning & roadmap

This is **v1.0.0**. It follows [Semantic Versioning](https://semver.org); for the 1.x line:

- **API stability.** The public surface is tracked (a `PublicAPI.txt` baseline enforced by an
  analyzer). No breaking changes to public types within 1.x.
- **Format stability.** The `PQE1` envelope, the scheme ids (`Aes256Gcm = 1`,
  `MLKem768Aes256Gcm = 2`), and envelope format versions 1 and 2 are frozen for 1.x. Any new
  format is introduced under a new version byte that 1.x can still read; data written by 1.x
  stays readable across 1.x. (Note: 0.1.0 cannot read the hybrid format-v2 envelopes 1.0
  writes — upgrade all nodes before writing post-quantum values.)

See [CHANGELOG.md](CHANGELOG.md) for the precise contents of this release.

## License

MIT — see [LICENSE](LICENSE).

> To God be the glory — 1 Corinthians 10:31
