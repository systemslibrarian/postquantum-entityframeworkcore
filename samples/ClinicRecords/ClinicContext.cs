using Microsoft.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.EntityFrameworkCore;

namespace ClinicRecords;

/// <summary>
/// An EF Core context that transparently encrypts the sensitive columns of
/// <see cref="Patient"/> using a configured <see cref="IPostQuantumProtector"/>.
/// </summary>
public sealed class ClinicContext : DbContext
{
    private readonly IPostQuantumProtector _protector;

    public ClinicContext(DbContextOptions<ClinicContext> options, IPostQuantumProtector protector)
        : base(options)
    {
        _protector = protector;
    }

    public DbSet<Patient> Patients => Set<Patient>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Patient>(b =>
        {
            b.HasKey(p => p.Id);
            b.Property(p => p.FullName).IsRequired();
            b.Property(p => p.Clinic).IsRequired();

            // Sensitive columns: encrypted at rest. Each becomes an authenticated envelope
            // stored as BLOB. Note these columns can no longer be filtered or indexed on.
            b.Property(p => p.Email).IsEncrypted(_protector).IsRequired();
            b.Property(p => p.NationalId).IsEncrypted(_protector).IsRequired();
            b.Property(p => p.Diagnosis).IsEncrypted(_protector);
            b.Property(p => p.CardLast4).IsEncrypted(_protector);
        });
    }
}
