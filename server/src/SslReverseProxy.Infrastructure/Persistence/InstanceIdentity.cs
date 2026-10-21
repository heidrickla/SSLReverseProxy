using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Persistence;

/// <summary>The installation's stable id, created once. Clients such as the Home Assistant integration key on it.</summary>
public static class InstanceIdentity
{
    public static async Task<InstanceInfo> GetAsync(AppDbContext db, TimeProvider clock, CancellationToken ct)
    {
        if (await db.Instance.AsNoTracking().SingleOrDefaultAsync(i => i.Id == 1, ct) is { } existing)
            return existing;
        var created = new InstanceInfo { InstanceId = Guid.NewGuid(), CreatedAt = clock.GetUtcNow() };
        db.Instance.Add(created);
        try
        {
            await db.SaveChangesAsync(ct);
            return created;
        }
        catch (DbUpdateException)
        {
            // Another request created it first; that one stands.
            db.Entry(created).State = EntityState.Detached;
            return await db.Instance.AsNoTracking().SingleAsync(i => i.Id == 1, ct);
        }
    }
}
