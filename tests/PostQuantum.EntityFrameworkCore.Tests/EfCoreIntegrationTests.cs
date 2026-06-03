using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

public class EfCoreIntegrationTests
{
    private sealed class Patient
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";       // not encrypted
        public string Email { get; set; } = "";       // encrypted, required
        public string? Diagnosis { get; set; }         // encrypted, optional
    }

    private sealed class ClinicContext(DbContextOptions<ClinicContext> options, IPostQuantumProtector protector)
        : DbContext(options)
    {
        private readonly IPostQuantumProtector _protector = protector;

        public DbSet<Patient> Patients => Set<Patient>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Patient>(b =>
            {
                b.HasKey(p => p.Id);
                b.Property(p => p.Name).IsRequired();
                b.Property(p => p.Email).IsEncrypted(_protector).IsRequired();
                b.Property(p => p.Diagnosis).IsEncrypted(_protector).IsRequired(false);
            });
        }
    }

    private static IPostQuantumProtector NewProtector()
    {
        DataEncryptionKey dek = DataEncryptionKey.Generate("dek-clinic");
        return new PostQuantumProtector(
            [new Aes256GcmSchemeHandler(new InMemoryDataProtectionKeyRing(dek))],
            EncryptionScheme.Aes256Gcm);
    }

    [Fact]
    public void Encrypted_properties_roundtrip_through_the_database()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        IPostQuantumProtector protector = NewProtector();
        DbContextOptions<ClinicContext> options = new DbContextOptionsBuilder<ClinicContext>()
            .UseSqlite(connection)
            .Options;

        using (var ctx = new ClinicContext(options, protector))
        {
            ctx.Database.EnsureCreated();
            ctx.Patients.Add(new Patient
            {
                Name = "Jane Roe",
                Email = "jane.roe@example.com",
                Diagnosis = "Hypertension, stage 2",
            });
            ctx.SaveChanges();
        }

        using (var ctx = new ClinicContext(options, protector))
        {
            Patient loaded = ctx.Patients.Single();
            Assert.Equal("Jane Roe", loaded.Name);
            Assert.Equal("jane.roe@example.com", loaded.Email);
            Assert.Equal("Hypertension, stage 2", loaded.Diagnosis);
        }
    }

    [Fact]
    public void Encrypted_columns_are_stored_as_authenticated_envelopes_not_plaintext()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        IPostQuantumProtector protector = NewProtector();
        DbContextOptions<ClinicContext> options = new DbContextOptionsBuilder<ClinicContext>()
            .UseSqlite(connection)
            .Options;

        using (var ctx = new ClinicContext(options, protector))
        {
            ctx.Database.EnsureCreated();
            ctx.Patients.Add(new Patient { Name = "John Doe", Email = "john.doe@example.com", Diagnosis = "n/a" });
            ctx.SaveChanges();
        }

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Name, Email FROM Patients";
        using SqliteDataReader reader = command.ExecuteReader();
        Assert.True(reader.Read());

        // Name is not encrypted: stored as text.
        Assert.Equal("John Doe", reader.GetString(0));

        // Email is encrypted: stored as a BLOB beginning with the "PQE1" envelope magic,
        // and it must not contain the plaintext.
        var emailBytes = (byte[])reader["Email"];
        Assert.Equal("PQE1"u8.ToArray(), emailBytes.AsSpan(0, 4).ToArray());
        Assert.DoesNotContain("john.doe", System.Text.Encoding.UTF8.GetString(emailBytes));
    }

    [Fact]
    public void Null_encrypted_values_are_preserved_as_null()
    {
        using var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        IPostQuantumProtector protector = NewProtector();
        DbContextOptions<ClinicContext> options = new DbContextOptionsBuilder<ClinicContext>()
            .UseSqlite(connection)
            .Options;

        using (var ctx = new ClinicContext(options, protector))
        {
            ctx.Database.EnsureCreated();
            ctx.Patients.Add(new Patient { Name = "No Email", Email = "x@y.z", Diagnosis = null! });
            ctx.SaveChanges();
        }

        using (var ctx = new ClinicContext(options, protector))
        {
            Patient loaded = ctx.Patients.Single();
            Assert.Null(loaded.Diagnosis);
        }
    }
}
