using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Persistence;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<ProxyServer> Servers => Set<ProxyServer>();
    public DbSet<ProxyRule> Rules => Set<ProxyRule>();
    public DbSet<Certificate> Certificates => Set<Certificate>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<ConfigSnapshot> ConfigSnapshots => Set<ConfigSnapshot>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
            e.Property(u => u.Name).HasMaxLength(200).IsRequired();
            e.Property(u => u.Email).HasMaxLength(320).IsRequired();
        });

        b.Entity<ApiKey>(e =>
        {
            e.HasIndex(k => k.Prefix).IsUnique();
            e.Property(k => k.Prefix).HasMaxLength(32).IsRequired();
            e.Property(k => k.Name).HasMaxLength(200).IsRequired();
            e.HasOne(k => k.User).WithMany(u => u.ApiKeys)
                .HasForeignKey(k => k.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<ProxyServer>(e =>
        {
            e.Property(s => s.Name).HasMaxLength(200).IsRequired();
            e.Property(s => s.Host).HasMaxLength(253).IsRequired();
            e.HasMany(s => s.Rules).WithOne(r => r.Server)
                .HasForeignKey(r => r.ServerId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<ProxyRule>(e =>
        {
            e.Property(r => r.Domain).HasMaxLength(253).IsRequired();
            e.Property(r => r.UpstreamUrl).HasMaxLength(2048).IsRequired();
            e.Property(r => r.AllowedCidrs).HasMaxLength(2048);
            e.Property(r => r.DeniedCidrs).HasMaxLength(2048);
            e.Property(r => r.BasicAuthUsername).HasMaxLength(200);
            e.Property(r => r.BasicAuthPasswordHash).HasMaxLength(200);
            e.Property(r => r.AdditionalUpstreams).HasMaxLength(4096);
            e.Property(r => r.LoadBalancePolicy).HasMaxLength(50);
            e.Property(r => r.FrameOptions).HasMaxLength(20);
            e.Property(r => r.HealthCheckPath).HasMaxLength(2048);
            e.Property(r => r.UpstreamTlsServerName).HasMaxLength(253);
            e.Property(r => r.UpstreamTlsTrustedCaFile).HasMaxLength(4096);
            // EF puts the ORIGINAL value in the UPDATE's WHERE clause, so a row
            // someone else has written since we loaded it matches nothing and
            // SaveChanges raises DbUpdateConcurrencyException instead of
            // overwriting. SQLite has no native rowversion, hence a plain int
            // the endpoints increment.
            e.Property(r => r.Version).IsConcurrencyToken();
            e.HasIndex(r => r.Domain);
        });

        b.Entity<ConfigSnapshot>(e =>
        {
            e.HasKey(s => s.Id);
            e.Property(s => s.Actor).HasMaxLength(200);
            e.Property(s => s.Note).HasMaxLength(500);
            e.HasIndex(s => s.CreatedAt);
        });

        b.Entity<Certificate>(e =>
        {
            e.Property(c => c.Domain).HasMaxLength(253).IsRequired();
            e.HasIndex(c => c.Domain);
        });

        b.Entity<AuditEntry>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.Action).HasMaxLength(100).IsRequired();
            e.Property(a => a.TargetType).HasMaxLength(100);
            e.Property(a => a.TargetName).HasMaxLength(300);
            e.HasIndex(a => a.Timestamp);
        });
    }
}
