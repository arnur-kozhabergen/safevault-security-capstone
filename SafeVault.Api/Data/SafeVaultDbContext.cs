using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Models;

namespace SafeVault.Api.Data;

public sealed class SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
    : IdentityDbContext<SafeVaultUser, IdentityRole, string>(options)
{
    public DbSet<VaultRecord> Records => Set<VaultRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<VaultRecord>(entity =>
        {
            entity.HasKey(record => record.Id);
            entity.Property(record => record.OwnerId).HasMaxLength(450).IsRequired();
            entity.Property(record => record.Title).HasMaxLength(100).IsRequired();
            entity.Property(record => record.Body).HasMaxLength(4000).IsRequired();
            // SQLite cannot order DateTimeOffset directly; persist UTC ticks for server-side ordering.
            entity.Property(record => record.CreatedUtc).HasConversion(
                value => value.UtcTicks,
                value => new DateTimeOffset(value, TimeSpan.Zero));
            entity.HasIndex(record => new { record.OwnerId, record.Title });
            entity.HasOne<SafeVaultUser>()
                .WithMany()
                .HasForeignKey(record => record.OwnerId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
