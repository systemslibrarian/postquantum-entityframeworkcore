using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Exercises the re-encryption helpers used to retire an old key after rotation, including
/// the subtlety that a plain load-and-save does not rewrite an unchanged encrypted value.
/// </summary>
/// <remarks>
/// Each test uses a distinct context type because EF Core caches the model — and the
/// protector captured by its value converters — globally per context CLR type. Rotation is
/// performed in place on the single ring the protector holds (the only path that works with
/// that cache), mirroring production use.
/// </remarks>
public class ReEncryptionTests
{
    private sealed class Record
    {
        public int Id { get; set; }
        public string Email { get; set; } = "";   // encrypted string
        public byte[] Scan { get; set; } = [];      // encrypted byte[]
    }

    private abstract class RecordContextBase(DbContextOptions options, IPostQuantumProtector protector)
        : DbContext(options)
    {
        private readonly IPostQuantumProtector _protector = protector;

        public DbSet<Record> Records => Set<Record>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Record>(b =>
            {
                b.HasKey(r => r.Id);
                b.Property(r => r.Email).IsEncrypted(_protector);
                b.Property(r => r.Scan).IsEncrypted(_protector);
            });
        }
    }

    private sealed class SweepContext(DbContextOptions<SweepContext> options, IPostQuantumProtector protector)
        : RecordContextBase(options, protector);

    private sealed class MarkContext(DbContextOptions<MarkContext> options, IPostQuantumProtector protector)
        : RecordContextBase(options, protector);

    private static (IPostQuantumProtector Protector, InMemoryDataProtectionKeyRing Ring) NewAes(string activeKeyId)
    {
        DataEncryptionKey key = DataEncryptionKey.Generate(activeKeyId);
        var ring = new InMemoryDataProtectionKeyRing(key);
        var protector = new PostQuantumProtector([new Aes256GcmSchemeHandler(ring)], EncryptionScheme.Aes256Gcm);
        return (protector, ring);
    }

    private static string EmailKeyId(SqliteConnection connection, int id)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT Email FROM Records WHERE Id = $id";
        command.Parameters.AddWithValue("$id", id);
        var bytes = (byte[])command.ExecuteScalar()!;
        return EncryptedEnvelope.Parse(bytes).KeyId;
    }

    [Fact]
    public async Task ReEncryptAsync_rewrites_every_row_under_the_new_key()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        (IPostQuantumProtector protector, InMemoryDataProtectionKeyRing ring) = NewAes("dek-A");
        DbContextOptions<SweepContext> options = new DbContextOptionsBuilder<SweepContext>()
            .UseSqlite(connection)
            .Options;

        using (var ctx = new SweepContext(options, protector))
        {
            ctx.Database.EnsureCreated();
            for (int i = 0; i < 25; i++)
            {
                ctx.Records.Add(new Record { Email = $"user{i}@example.com", Scan = [(byte)i, 1, 2, 3] });
            }

            await ctx.SaveChangesAsync();
        }

        Assert.Equal("dek-A", EmailKeyId(connection, 1));

        // Rotate in place: add the new key and activate it, then re-encrypt every row.
        ring.AddKey(DataEncryptionKey.Generate("dek-B"));
        ring.SetActiveKey("dek-B");

        int count;
        using (var ctx = new SweepContext(options, protector))
        {
            count = await ctx.ReEncryptAsync<Record>(batchSize: 10);
        }

        Assert.Equal(25, count);
        Assert.Equal("dek-B", EmailKeyId(connection, 1));
        Assert.Equal("dek-B", EmailKeyId(connection, 25));

        // Key A is no longer referenced by any row: retiring it must not break reads.
        Assert.True(ring.RemoveKey("dek-A"));
        using (var ctx = new SweepContext(options, protector))
        {
            List<Record> all = await ctx.Records.OrderBy(r => r.Id).ToListAsync();
            Assert.Equal(25, all.Count);
            Assert.Equal("user0@example.com", all[0].Email);
            Assert.Equal(new byte[] { 0, 1, 2, 3 }, all[0].Scan);
        }
    }

    [Fact]
    public async Task A_plain_save_does_not_re_encrypt_but_MarkModified_does()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        (IPostQuantumProtector protector, InMemoryDataProtectionKeyRing ring) = NewAes("dek-A");
        DbContextOptions<MarkContext> options = new DbContextOptionsBuilder<MarkContext>()
            .UseSqlite(connection)
            .Options;

        using (var ctx = new MarkContext(options, protector))
        {
            ctx.Database.EnsureCreated();
            ctx.Records.Add(new Record { Email = "user@example.com", Scan = [9, 9, 9] });
            await ctx.SaveChangesAsync();
        }

        ring.AddKey(DataEncryptionKey.Generate("dek-B"));
        ring.SetActiveKey("dek-B");

        // Load and SaveChanges without marking: the decrypted value is unchanged, so EF
        // generates no UPDATE and the row stays under key A.
        using (var ctx = new MarkContext(options, protector))
        {
            Record record = await ctx.Records.SingleAsync();
            _ = record.Email;
            await ctx.SaveChangesAsync();
        }

        Assert.Equal("dek-A", EmailKeyId(connection, 1));

        // Now force re-encryption explicitly.
        using (var ctx = new MarkContext(options, protector))
        {
            Record record = await ctx.Records.SingleAsync();
            int marked = ctx.MarkEncryptedPropertiesModified(record);
            Assert.Equal(2, marked); // Email + Scan
            await ctx.SaveChangesAsync();
        }

        Assert.Equal("dek-B", EmailKeyId(connection, 1));
    }

    [Fact]
    public async Task ReEncryptAsync_returns_zero_when_no_properties_are_encrypted()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        DbContextOptions<PlainContext> options = new DbContextOptionsBuilder<PlainContext>()
            .UseSqlite(connection)
            .Options;

        using var ctx = new PlainContext(options);
        ctx.Database.EnsureCreated();
        ctx.Plain.Add(new Plain { Name = "x" });
        await ctx.SaveChangesAsync();

        Assert.Equal(0, await ctx.ReEncryptAsync<Plain>());
    }

    private sealed class Plain
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
    }

    private sealed class PlainContext(DbContextOptions<PlainContext> options) : DbContext(options)
    {
        public DbSet<Plain> Plain => Set<Plain>();
    }
}
