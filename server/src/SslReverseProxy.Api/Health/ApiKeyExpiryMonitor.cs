using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Health;

/// <summary>Raises <see cref="AlertTypes.ApiKeyExpiring"/> for keys near expiry, checking every hour.</summary>
public sealed class ApiKeyExpiryMonitor(
    IServiceScopeFactory scopes, IAlertSink alerts, TimeProvider clock, ILogger<ApiKeyExpiryMonitor> logger)
    : BackgroundService
{
    internal static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "API key expiry check failed.");
            }

            try
            {
                await Task.Delay(Interval, clock, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>One check. The warning sent is stored on the key before the alert is raised.</summary>
    internal async Task CheckAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = clock.GetUtcNow();
        // SQLite cannot compare DateTimeOffset columns, so the expiry filter runs in memory.
        var keys = await db.ApiKeys.Include(k => k.User)
            .Where(k => k.RevokedAt == null && k.ExpiresAt != null).ToListAsync(ct);
        var raised = new List<Alert>();
        foreach (var key in keys)
            if (ApiKeyAlerts.Evaluate(key, key.User?.Name ?? "", now) is { } alert)
                raised.Add(alert);
        if (raised.Count == 0) return;
        await db.SaveChangesAsync(ct);
        foreach (var alert in raised) alerts.Raise(alert);
    }
}
