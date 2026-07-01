# Migration notes

## Encrypting a column that already holds plaintext

Turning on `IsEncrypted(...)` for a column does **not** retroactively encrypt existing rows —
EF Core only runs the converter when it reads or writes through the model. Plan a one-time
backfill.

Recommended approach: **add a new encrypted column, copy, then swap.**

1. Add a new property/column (e.g. `EmailEncrypted`) and mark it `IsEncrypted(protector)`.
2. Backfill in batches, reading the old plaintext column and writing the new one:

   ```csharp
   const int batchSize = 500;
   while (true)
   {
       var batch = await db.Customers
           .Where(c => c.EmailEncrypted == null && c.Email != null)
           .OrderBy(c => c.Id)
           .Take(batchSize)
           .ToListAsync();

       if (batch.Count == 0) break;

       foreach (var c in batch)
           c.EmailEncrypted = c.Email;   // converter encrypts on save

       await db.SaveChangesAsync();
   }
   ```

3. Verify counts, then drop the old plaintext column in a later migration and rename.

Doing it as add-copy-swap (rather than encrypting in place) keeps the operation reversible
until you are confident, and avoids a window where the same column is half plaintext and
half ciphertext.

## Migrating from AES-only to the ML-KEM hybrid envelope

Because the scheme id travels in every envelope, you can switch the default scheme without a
data migration:

```csharp
services.AddPostQuantumEncryption(pq =>
{
    pq.UseKeyEncapsulationMechanism(mlkem);
    pq.UseAes256Gcm(dekRing, asDefault: false);   // still registered → old rows decrypt
    pq.UseMLKem768Envelope(kekRing);              // becomes the default for new writes
});
```

- Existing AES-256-GCM rows keep decrypting via the still-registered AES handler.
- New writes use the post-quantum envelope.
- To fully retire AES, re-encrypt rows in the background (load each entity and call
  `SaveChanges`, which rewrites the column under the active scheme), then remove the AES
  handler.

## Rotating a data-encryption key

Rotate **in place** on the ring your protector already holds. Do *not* build a new protector
or ring to rotate: EF Core caches the model, and the value converters in that cached model
capture the protector instance, so a swapped protector has no effect until the model cache is
invalidated. The in-memory rings expose thread-safe rotation for exactly this reason (a
production KMS-backed ring instead reflects the active key dynamically).

```csharp
// dekRing is the same IDataProtectionKeyRing instance the protector was built with.
dekRing.AddKey(DataEncryptionKey.Generate("dek-2026-07")); // new writes still use the old key…
dekRing.SetActiveKey("dek-2026-07");                        // …until you activate the new one
```

New writes now use `dek-2026-07`; rows written under `dek-2026-01` still decrypt because the
old key remains in the ring.

### Re-encrypting existing rows to retire the old key

A plain load-and-`SaveChanges` does **not** rewrite an unchanged value: EF Core change
tracking compares the *decrypted* model value, which is unchanged by rotation, so no UPDATE is
generated. Use the helpers, which mark the encrypted columns so EF re-runs the converter:

```csharp
// Sweep every row of an entity in batches, rewriting each encrypted column under the
// now-active key. Safe to run online.
int rewritten = await db.ReEncryptAsync<Customer>(batchSize: 500);

// …or, for a custom query / composite keys, force re-encryption per entity:
foreach (var c in db.Customers.Where(/* your filter */))
    db.MarkEncryptedPropertiesModified(c);
await db.SaveChangesAsync();
```

Once every row is re-encrypted, retire the old key:

```csharp
dekRing.RemoveKey("dek-2026-01"); // throws if it is still the active key
```

The same `AddKey`/`SetActiveKey`/`RemoveKey` surface exists on
`InMemoryKeyEncapsulationKeyRing` for rotating ML-KEM key-encapsulation keys.

## Choosing a column type

Encrypted values are `byte[]`. Map to your provider's binary type explicitly if you don't
want the default:

| Provider | Suggested type |
| --- | --- |
| SQL Server | `varbinary(max)` |
| PostgreSQL | `bytea` |
| SQLite | `BLOB` (default) |
| MySQL | `LONGBLOB` |

Account for the envelope overhead when sizing fixed-width columns: header (~10–20 bytes) +
nonce (12) + tag (16), plus the ML-KEM ciphertext (~1088 bytes) for the hybrid scheme.

> To God be the glory — 1 Corinthians 10:31
