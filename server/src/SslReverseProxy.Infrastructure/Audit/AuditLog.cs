using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Infrastructure.Audit;

/// <summary>Append-only audit sink backed by EF Core. Only ever inserts.</summary>
public sealed class AuditLog : IAuditLog
{
    private readonly AppDbContext _db;
    public AuditLog(AppDbContext db) => _db = db;

    public async Task WriteAsync(AuditEntry entry, CancellationToken ct = default)
    {
        _db.AuditEntries.Add(entry);
        await _db.SaveChangesAsync(ct);
    }
}
