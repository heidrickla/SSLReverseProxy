using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;

namespace SslReverseProxy.Api.Health;

/// <summary>
/// Stores the proxy's traffic once per <c>Proxy:TrafficSampleSeconds</c>, so the
/// dashboard reads the database and never waits on Caddy. No row is written
/// while the proxy is stopped.
/// </summary>
public sealed class TrafficSampler : BackgroundService
{
    // An hour beyond the dashboard's day keeps its oldest hour whole.
    private static readonly TimeSpan Retention = TrafficSummary.Window + TimeSpan.FromHours(1);

    private readonly IServiceScopeFactory _scopes;
    private readonly IProxyController _proxy;
    private readonly TrafficRecorder _traffic;
    private readonly TimeProvider _clock;
    private readonly ILogger<TrafficSampler> _logger;
    private readonly TimeSpan _interval;

    public TrafficSampler(
        IServiceScopeFactory scopes, IProxyController proxy, TrafficRecorder traffic,
        TimeProvider clock, IOptions<ProxyOptions> options, ILogger<TrafficSampler> logger)
    {
        _scopes = scopes;
        _proxy = proxy;
        _traffic = traffic;
        _clock = clock;
        _logger = logger;
        _interval = TimeSpan.FromSeconds(Math.Max(0, options.Value.TrafficSampleSeconds));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_interval == TimeSpan.Zero)
        {
            _logger.LogInformation("Traffic sampling is off (Proxy:TrafficSampleSeconds is 0).");
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, _clock, stoppingToken);
                await SampleAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Traffic sample failed.");
            }
        }
    }

    private async Task SampleAsync(CancellationToken ct)
    {
        await _proxy.CaptureTrafficAsync(ct);
        var traffic = _traffic.TakePending();

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = _clock.GetUtcNow();
        if (traffic is not null)
        {
            db.TrafficSamples.Add(traffic.ToSample(now));
            await db.SaveChangesAsync(ct);
        }

        var cutoff = (now - Retention).ToUnixTimeSeconds();
        await db.TrafficSamples.Where(s => s.At < cutoff).ExecuteDeleteAsync(ct);
    }
}
