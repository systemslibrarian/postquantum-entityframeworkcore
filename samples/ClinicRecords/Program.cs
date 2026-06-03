using ClinicRecords;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.DependencyInjection;
using PostQuantum.EntityFrameworkCore.Keys;

Console.WriteLine("PostQuantum.EntityFrameworkCore — ClinicRecords sample");
Console.WriteLine("======================================================\n");

// ---------------------------------------------------------------------------
// 1. Provision keys.
//
//    In production these come from PostQuantum.KeyManagement, an HSM, or a cloud
//    KMS — NEVER generated ad hoc at startup. We generate ephemeral keys here only
//    so the sample is self-contained and runnable. Data written in one run will not
//    be readable in the next, by design.
// ---------------------------------------------------------------------------
using var dataKey = DataEncryptionKey.Generate("dek-sample-2026-01");
var dekRing = new InMemoryDataProtectionKeyRing(dataKey);

var mlkem = new MLKemKeyEncapsulationMechanism();
bool postQuantum = mlkem.IsSupported;

// ---------------------------------------------------------------------------
// 2. Configure encryption. Prefer the post-quantum hybrid envelope when the
//    platform supports ML-KEM; always keep AES-256-GCM available.
// ---------------------------------------------------------------------------
var services = new ServiceCollection();
services.AddPostQuantumEncryption(pq =>
{
    if (postQuantum)
    {
        using var kek = mlkem.GenerateKeyPair("kek-sample-2026-01");
        var kekRing = new InMemoryKeyEncapsulationKeyRing(kek);
        pq.UseKeyEncapsulationMechanism(mlkem);
        pq.UseAes256Gcm(dekRing, asDefault: false);          // kept for legacy/interop
        pq.UseMLKem768Envelope(kekRing);                      // default for new writes
    }
    else
    {
        pq.UseAes256Gcm(dekRing);                             // default
    }
});

await using ServiceProvider provider = services.BuildServiceProvider();
var protector = provider.GetRequiredService<IPostQuantumProtector>();

Console.WriteLine($"Default scheme: {protector.DefaultScheme}");
Console.WriteLine(postQuantum
    ? "ML-KEM-768 is supported on this platform — new values use the post-quantum envelope.\n"
    : "ML-KEM-768 is unavailable here — falling back to AES-256-GCM (still quantum-resistant\n" +
      "for the symmetric layer). See KNOWN-GAPS.md for platform requirements.\n");

// ---------------------------------------------------------------------------
// 3. Create a fresh on-disk database.
// ---------------------------------------------------------------------------
string dbPath = Path.Combine(Path.GetTempPath(), $"clinic-{Guid.NewGuid():N}.db");
var connectionString = new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString();
DbContextOptions<ClinicContext> options = new DbContextOptionsBuilder<ClinicContext>()
    .UseSqlite(connectionString)
    .Options;

try
{
    using (var ctx = new ClinicContext(options, protector))
    {
        ctx.Database.EnsureCreated();
        ctx.Patients.AddRange(
            new Patient
            {
                FullName = "Jane Roe",
                Clinic = "Cardiology",
                Email = "jane.roe@example.com",
                NationalId = "078-05-1120",
                Diagnosis = "Hypertension, stage 2",
                CardLast4 = "4242",
            },
            new Patient
            {
                FullName = "John Public",
                Clinic = "Oncology",
                Email = "john.public@example.com",
                NationalId = "219-09-9999",
                Diagnosis = "Routine screening — no findings",
                CardLast4 = null,
            });
        ctx.SaveChanges();
    }

    // -----------------------------------------------------------------------
    // 4. Read back through EF Core: values are transparently decrypted.
    // -----------------------------------------------------------------------
    Console.WriteLine("Decrypted via EF Core:");
    Console.WriteLine("----------------------");
    using (var ctx = new ClinicContext(options, protector))
    {
        foreach (Patient p in ctx.Patients.OrderBy(p => p.Id))
        {
            Console.WriteLine($"  #{p.Id} {p.FullName} ({p.Clinic})");
            Console.WriteLine($"      email      : {p.Email}");
            Console.WriteLine($"      national id: {p.NationalId}");
            Console.WriteLine($"      diagnosis  : {p.Diagnosis ?? "(none)"}");
            Console.WriteLine($"      card last4 : {p.CardLast4 ?? "(none)"}");
        }
    }

    // -----------------------------------------------------------------------
    // 5. Read the raw bytes straight from SQLite to prove the data is at-rest
    //    ciphertext, not plaintext.
    // -----------------------------------------------------------------------
    Console.WriteLine("\nRaw bytes on disk (what an attacker with the database file sees):");
    Console.WriteLine("----------------------------------------------------------------");
    using (var raw = new SqliteConnection(connectionString))
    {
        raw.Open();
        using var cmd = raw.CreateCommand();
        cmd.CommandText = "SELECT FullName, Email, NationalId FROM Patients ORDER BY Id LIMIT 1";
        using SqliteDataReader reader = cmd.ExecuteReader();
        reader.Read();

        string fullName = reader.GetString(0);
        var emailCipher = (byte[])reader["Email"];
        var nationalIdCipher = (byte[])reader["NationalId"];

        Console.WriteLine($"  FullName (cleartext)   : {fullName}");
        Console.WriteLine($"  Email (ciphertext)     : {Describe(emailCipher)}");
        Console.WriteLine($"  NationalId (ciphertext): {Describe(nationalIdCipher)}");
    }

    // -----------------------------------------------------------------------
    // 6. Direct use of the protector (outside EF Core).
    // -----------------------------------------------------------------------
    Console.WriteLine("\nDirect protector use:");
    Console.WriteLine("---------------------");
    byte[] envelope = protector.ProtectText("API token: sk-live-EXAMPLE");
    Console.WriteLine($"  envelope length: {envelope.Length} bytes, scheme byte: {envelope[5]}");
    Console.WriteLine($"  decrypted back : {protector.UnprotectText(envelope)}");

    Console.WriteLine("\nDone. To God be the glory — 1 Corinthians 10:31");
}
finally
{
    SqliteConnection.ClearAllPools();
    if (File.Exists(dbPath))
    {
        File.Delete(dbPath);
    }
}

static string Describe(byte[] cipher)
{
    string magic = System.Text.Encoding.ASCII.GetString(cipher, 0, 4);
    string head = Convert.ToHexString(cipher.AsSpan(0, Math.Min(16, cipher.Length)));
    return $"[{cipher.Length} bytes] magic='{magic}' {head}…";
}
