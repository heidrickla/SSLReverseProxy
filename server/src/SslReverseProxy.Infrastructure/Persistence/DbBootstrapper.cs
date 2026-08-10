using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Infrastructure.Persistence;

/// <summary>
/// Ensures the database exists and seeds a single bootstrap admin + API key on
/// first run. The plaintext token is written to the log exactly once so the
/// operator can capture it; it is never stored or recoverable afterward.
/// </summary>
public static class DbBootstrapper
{
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken ct = default)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("DbBootstrapper");

        await db.Database.MigrateAsync(ct);

        if (await db.Users.AnyAsync(ct))
            return;

        var admin = new User
        {
            Name = "Bootstrap Admin",
            Email = "admin@localhost",
            Role = Role.Admin,
            IsActive = true,
        };
        db.Users.Add(admin);
        await db.SaveChangesAsync(ct);

        var apiKeys = scope.ServiceProvider.GetRequiredService<IApiKeyService>();
        var issued = await apiKeys.CreateAsync(admin.Id, "bootstrap", lifetime: null, ct);

        // Offered in memory so a local dev UI can claim it via /api/bootstrap-key.
        scope.ServiceProvider.GetRequiredService<BootstrapKeyBroker>().Offer(issued.PlaintextToken);

        logger.LogWarning(
            "Seeded bootstrap admin. One-time API key (store it now, it will not be shown again): {Token}",
            issued.PlaintextToken);
    }
}
