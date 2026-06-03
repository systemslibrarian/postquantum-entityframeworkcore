# Getting started

This walks through adding post-quantum column encryption to an existing EF Core model in
about five minutes. For the conceptual background, read the
[README](../README.md); for the runnable version, see
[`samples/ClinicRecords`](../samples/ClinicRecords).

## 1. Add the package

```bash
dotnet add package PostQuantum.EntityFrameworkCore
```

## 2. Get a 32-byte data-encryption key

In production, fetch this from your key store. For a quick start you can generate one and
store it securely (environment variable, secret manager — **not** source control):

```csharp
using PostQuantum.EntityFrameworkCore.Keys;

// Generate once, persist the 32 bytes securely, and load them on startup.
using var generated = DataEncryptionKey.Generate("dek-2026-01");
// ... export generated to your secret store ...

// On startup:
var dek = new DataEncryptionKey("dek-2026-01", keyBytesFromYourSecretStore);
```

## 3. Register the protector

```csharp
using PostQuantum.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Keys;

builder.Services.AddPostQuantumEncryption(pq =>
{
    pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek));
});
```

To use the post-quantum hybrid envelope where the platform supports it:

```csharp
var mlkem = new MLKemKeyEncapsulationMechanism();
builder.Services.AddPostQuantumEncryption(pq =>
{
    if (mlkem.IsSupported)
    {
        using var kek = mlkem.GenerateKeyPair("kek-2026-01"); // or load from your key store
        pq.UseKeyEncapsulationMechanism(mlkem);
        pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek), asDefault: false);
        pq.UseMLKem768Envelope(new InMemoryKeyEncapsulationKeyRing(kek));
    }
    else
    {
        pq.UseAes256Gcm(new InMemoryDataProtectionKeyRing(dek));
    }
});
```

## 4. Mark properties as encrypted

Inject the protector into your `DbContext` and configure properties in `OnModelCreating`:

```csharp
using PostQuantum.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.EntityFrameworkCore;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options, IPostQuantumProtector protector)
    : DbContext(options)
{
    private readonly IPostQuantumProtector _protector = protector;

    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Customer>(b =>
        {
            b.Property(c => c.Email).IsEncrypted(_protector);
            b.Property(c => c.TaxId).IsEncrypted(_protector);
            b.Property(c => c.Notes).IsEncrypted(_protector);   // string?
        });
    }
}
```

Register the context so DI supplies the protector:

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(connectionString));
```

## 5. Use it normally

```csharp
db.Customers.Add(new Customer { Email = "a@b.com", TaxId = "12-3456789" });
await db.SaveChangesAsync();             // stored as ciphertext

var c = await db.Customers.FirstAsync(); // transparently decrypted
Console.WriteLine(c.Email);              // a@b.com
```

Remember: you **cannot** write `Where(c => c.Email == "a@b.com")` against an encrypted
column. Look rows up by an unencrypted key, or keep a separate blind index if you need
equality search (out of scope for this library).

## Column types

Encrypted values are stored as `byte[]`. Most providers map this to `varbinary`/`BLOB`
automatically. If you want an explicit type, chain `HasColumnType`:

```csharp
b.Property(c => c.Email).IsEncrypted(_protector);
b.Property(c => c.Email).HasColumnType("bytea"); // PostgreSQL example
```

## Next steps

- [Threat model](threat-model.md) — what this does and does not defend against.
- [Migration](migration.md) — encrypting a column that already holds plaintext.
- [KNOWN-GAPS.md](../KNOWN-GAPS.md) — the honest limitations list.

> To God be the glory — 1 Corinthians 10:31
