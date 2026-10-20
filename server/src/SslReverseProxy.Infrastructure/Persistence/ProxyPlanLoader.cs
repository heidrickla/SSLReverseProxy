using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Persistence;

public static class ProxyPlanLoader
{
    /// <summary>The rules and certificate rows every generated config is built from.</summary>
    public static async Task<ProxyPlan> LoadProxyPlanAsync(this AppDbContext db, CancellationToken ct = default)
    {
        var rules = await db.Rules.AsNoTracking().ToListAsync(ct);
        var certificates = await db.Certificates.AsNoTracking().ToListAsync(ct);
        return new ProxyPlan(rules, certificates.Select(CertificatePlan.From).ToList());
    }
}
