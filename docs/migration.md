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

```csharp
var ring = new InMemoryDataProtectionKeyRing(
    activeKeyId: "dek-2026-07",
    keys: [oldKey /* dek-2026-01 */, newKey /* dek-2026-07 */]);
```

New writes use `dek-2026-07`; rows written under `dek-2026-01` still decrypt. Re-encrypt in
the background to retire the old key, then drop it from the ring.

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
