using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Alerts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Alerts;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;

namespace SslReverseProxy.Api.Health;

/// <summary>
/// Probes every enabled rule's upstreams in the background and keeps each
/// server's status in memory, so listing servers never waits on a probe.
/// Probes go through <see cref="IUpstreamHealthChecker"/>, which applies the SSRF policy.
/// </summary>
public sealed class ServerHealthMonitor : BackgroundService, IServerHealthStore
{
    private const int MaxConcurrentProbes = 8;

    private readonly IServiceScopeFactory _scopes;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IEventStream _events;
    private readonly IAlertSink _alerts;
    private readonly ServerAlertTracker _tracker;
    private readonly TimeProvider _clock;
    private readonly ILogger<ServerHealthMonitor> _logger;
    private readonly TimeSpan _interval;
    private readonly ConcurrentDictionary<Guid, ServerHealth> _health = new();
    private readonly Channel<bool> _wake =
        Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    public ServerHealthMonitor(
        IServiceScopeFactory scopes, IHostApplicationLifetime lifetime, IEventStream events, IAlertSink alerts,
        TimeProvider clock, IOptions<ProxyOptions> options, IOptions<AlertOptions> alertOptions,
        ILogger<ServerHealthMonitor> logger)
    {
        _scopes = scopes;
        _lifetime = lifetime;
        _events = events;
        _alerts = alerts;
        _tracker = new ServerAlertTracker(alertOptions.Value.ServerDownChecks);
        _clock = clock;
        _logger = logger;
        _interval = TimeSpan.FromSeconds(Math.Max(0, options.Value.ServerHealthIntervalSeconds));
    }

    public ServerHealth Get(Guid serverId) =>
        _health.TryGetValue(serverId, out var health) ? health : ServerHealth.Unknown;

    public void RequestCheck() => _wake.Writer.TryWrite(true);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_interval == TimeSpan.Zero)
        {
            _logger.LogInformation("Server health monitor is off (Proxy:ServerHealthIntervalSeconds is 0).");
            return;
        }

        // An upstream on this host would read as down if probed before Kestrel listens.
        await WaitForStartAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAllAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Server health check failed.");
            }

            using var timer = new CancellationTokenSource(_interval, _clock);
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, timer.Token);
            try
            {
                await _wake.Reader.ReadAsync(wait.Token);
            }
            catch (OperationCanceledException)
            {
                // Interval elapsed, or the host is stopping; the loop condition decides.
            }
        }
    }

    private async Task WaitForStartAsync(CancellationToken ct)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var onStart = _lifetime.ApplicationStarted.Register(() => started.TrySetResult());
        using var onStop = ct.Register(() => started.TrySetCanceled(ct));
        await started.Task;
    }

    private async Task CheckAllAsync(CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var checker = scope.ServiceProvider.GetRequiredService<IUpstreamHealthChecker>();

        var servers = await db.Servers.AsNoTracking().Include(s => s.Rules).ToListAsync(ct);
        using var throttle = new SemaphoreSlim(MaxConcurrentProbes);
        await Task.WhenAll(servers.Select(s => CheckServerAsync(s, checker, throttle, ct)));

        var current = servers.Select(s => s.Id).ToHashSet();
        foreach (var gone in _health.Keys.Where(id => !current.Contains(id)))
        {
            _health.TryRemove(gone, out _);
            _tracker.Forget(gone);
        }
    }

    private async Task CheckServerAsync(
        ProxyServer server, IUpstreamHealthChecker checker, SemaphoreSlim throttle, CancellationToken ct)
    {
        var upstreams = server.Rules.Where(r => r.Enabled)
            .SelectMany(r => r.AllUpstreams())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var answered = await Task.WhenAll(upstreams.Select(async url =>
        {
            await throttle.WaitAsync(ct);
            try { return (await checker.CheckAsync(url, ct)).Reachable; }
            finally { throttle.Release(); }
        }));

        var up = answered.Count(a => a);
        var now = _clock.GetUtcNow();
        var health = new ServerHealth(ServerHealth.Classify(up, upstreams.Count), up, upstreams.Count, now);
        var previous = Get(server.Id);
        _health[server.Id] = health;

        if (previous.Status != health.Status)
            _events.Publish(new ProxyEvent(
                "server.health", $"{server.Name} is {health.Status.ToString().ToLowerInvariant()}", now, null));
        if (_tracker.Observe(server.Id, server.Name, health, now) is { } alert)
            _alerts.Raise(alert);
    }
}
