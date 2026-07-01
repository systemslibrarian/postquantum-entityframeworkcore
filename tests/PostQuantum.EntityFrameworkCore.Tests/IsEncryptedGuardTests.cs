using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Crypto;
using PostQuantum.EntityFrameworkCore.EntityFrameworkCore;
using PostQuantum.EntityFrameworkCore.Keys;
using Xunit;

namespace PostQuantum.EntityFrameworkCore.Tests;

/// <summary>
/// Verifies that <c>IsEncrypted</c> rejects unsupported property types with a clear,
/// property-named error instead of an opaque EF Core model-build failure.
/// </summary>
public class IsEncryptedGuardTests
{
    private sealed class Widget
    {
        public int Id { get; set; }
        public int Quantity { get; set; } // not a string or byte[]
    }

    private sealed class BadContext(DbContextOptions<BadContext> options, IPostQuantumProtector protector)
        : DbContext(options)
    {
        private readonly IPostQuantumProtector _protector = protector;

        public DbSet<Widget> Widgets => Set<Widget>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Encrypting an int property is a mistake; the guard must catch it.
            modelBuilder.Entity<Widget>().Property(w => w.Quantity).IsEncrypted(_protector);
        }
    }

    [Fact]
    public void IsEncrypted_on_a_non_string_non_binary_property_throws_a_clear_error()
    {
        IPostQuantumProtector protector = TestKeys.AesProtector();
        DbContextOptions<BadContext> options = new DbContextOptionsBuilder<BadContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        using var ctx = new BadContext(options, protector);

        ArgumentException ex = Assert.Throws<ArgumentException>(() => _ = ctx.Model);
        Assert.Contains("Quantity", ex.Message, StringComparison.Ordinal);
        Assert.Contains("byte[]", ex.Message, StringComparison.Ordinal);
    }
}
