using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;

namespace SslReverseProxy.Api.Health;

/// <summary>
/// Keeps the certificate rows in step with what Caddy serves. Each cycle adds a row for every enabled
/// TLS rule's host and drops rule rows whose host no rule names, reads the certificate served for each
/// name over SNI, and takes errors from Caddy's log. It also ends forced renewals: once a new serial is
/// served, or after <see cref="ProxyOptions.RenewTimeoutMinutes"/>, the forcing policy is removed by
/// applying the config again.
/// </summary>
public sealed class CertificateMonitor : BackgroundService, ICertificateChecks
{
    private const int MaxConcurrentProbes = 8;
    private static readonly TimeSpan PendingInterval = TimeSpan.FromSeconds(5);

    private readonly IServiceScopeFactory _scopes;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly IProxyController _proxy;
    private readonly ICertificateProbe _probe;
    private readonly CaddyCertificateLog _log;
    private readonly IEventStream _events;
    private readonly TimeProvider _clock;
    private readonly ProxyOptions _options;
    private readonly ILogger<CertificateMonitor> _logger;
    private readonly TimeSpan _interval;
    private readonly Channel<bool> _wake =
        Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    public CertificateMonitor(
        IServiceScopeFactory scopes, IHostApplicationLifetime lifetime, IProxyController proxy,
        ICertificateProbe probe, CaddyCertificateLog log, IEventStream events, TimeProvider clock,
        IOptions<ProxyOptions> options, ILogger<CertificateMonitor> logger)
    {
        _scopes = scopes;
        _lifetime = lifetime;
        _proxy = proxy;
        _probe = probe;
        _log = log;
        _events = events;
        _clock = clock;
        _options = options.Value;
        _logger = logger;
        _interval = TimeSpan.FromSeconds(Math.Max(0, _options.CertificateCheckSeconds));
    }

    public bool Enabled => _interval > TimeSpan.Zero;

    public void RequestCheck() => _wake.Writer.TryWrite(true);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!Enabled)
        {
            _logger.LogInformation("Certificate monitor is off (Proxy:CertificateCheckSeconds is 0).");
            return;
        }

        await WaitForStartAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            var pending = false;
            try
            {
                pending = await CheckAllAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Certificate check failed.");
            }

            using var timer = new CancellationTokenSource(pending ? PendingInterval : _interval, _clock);
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

    /// <summary>One cycle. Returns whether a forced renewal is still waiting, which shortens the next wait.</summary>
    internal async Task<bool> CheckAllAsync(CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var running = (await _proxy.GetStatusAsync(ct)).State == ProxyState.Running;

        var configured = await SyncRuleRowsAsync(db, ct);
        var certs = await db.Certificates.ToListAsync(ct);

        var probed = new Dictionary<Guid, ServedCertificate?>();
        if (running)
        {
            using var throttle = new SemaphoreSlim(MaxConcurrentProbes);
            var reads = await Task.WhenAll(certs.Where(c => configured.Contains(c.Domain)).Select(async c =>
            {
                await throttle.WaitAsync(ct);
                try { return (c.Id, Reading: await _probe.ReadAsync(c.Domain, ct)); }
                finally { throttle.Release(); }
            }));
            foreach (var (id, reading) in reads) probed[id] = reading;
        }

        var now = _clock.GetUtcNow();
        var reapply = false;
        var events = new List<ProxyEvent>();
        foreach (var cert in certs)
        {
            var before = cert.Status;
            var checkedNow = probed.TryGetValue(cert.Id, out var reading);
            reapply |= Update(cert, checkedNow, reading, now, events);
            if (cert.Status != before)
                events.Add(new ProxyEvent("certificate.status",
                    $"{cert.Domain} is {cert.Status.ToString().ToLowerInvariant()}", now, null));
        }

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // A row was deleted while it was being checked; the next cycle reads the table again.
            _logger.LogDebug(ex, "A certificate row changed during the check.");
            return true;
        }

        foreach (var e in events) _events.Publish(e);

        if (reapply && running)
        {
            var status = await _proxy.ApplyConfigurationAsync(await db.LoadProxyPlanAsync(ct), ct);
            if (status.State != ProxyState.Running)
                _logger.LogWarning("Could not apply the config after a forced renewal ended: {Message}", status.Message);
        }

        return certs.Any(c => c.RenewFromSerial is not null);
    }

    /// <summary>
    /// Adds a row for each enabled TLS rule's host that has none and removes rule rows whose host no
    /// TLS rule names. Returns the names Caddy is configured to serve: manual rows and enabled rule hosts.
    /// </summary>
    private async Task<HashSet<string>> SyncRuleRowsAsync(AppDbContext db, CancellationToken ct)
    {
        var tlsRules = await db.Rules.AsNoTracking().Where(r => r.EnableTls)
            .Select(r => new { r.Domain, r.Enabled }).ToListAsync(ct);
        var enabledHosts = tlsRules.Where(r => r.Enabled).Select(r => CertificateNames.Normalize(r.Domain))
            .Where(h => CertificateNames.Problem(h) is null).ToHashSet(StringComparer.Ordinal);
        var anyHosts = tlsRules.Select(r => CertificateNames.Normalize(r.Domain)).ToHashSet(StringComparer.Ordinal);

        var rows = await db.Certificates.ToListAsync(ct);
        var known = rows.Select(c => c.Domain).ToHashSet(StringComparer.Ordinal);
        foreach (var host in enabledHosts.Where(h => !known.Contains(h)).Order(StringComparer.Ordinal))
            db.Certificates.Add(new Certificate
            {
                Domain = host,
                Source = CertificateSource.Rule,
                Status = CertificateStatus.Issuing,
                Issuer = string.Empty,
            });
        // A host whose rules are all disabled keeps its row, and with it the chosen challenge.
        foreach (var row in rows.Where(c => c.Source == CertificateSource.Rule && !anyHosts.Contains(c.Domain)))
            db.Certificates.Remove(row);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex)
        {
            // Another writer added the same name or removed the row first; the next cycle catches up.
            _logger.LogDebug(ex, "Certificate rows changed while syncing them with the rules.");
            db.ChangeTracker.Clear();
        }

        var configured = rows.Where(c => c.Source == CertificateSource.Manual).Select(c => c.Domain)
            .ToHashSet(StringComparer.Ordinal);
        configured.UnionWith(enabledHosts);
        return configured;
    }

    /// <summary>Applies one check to a row. Returns whether the config has to be applied again.</summary>
    private bool Update(Certificate cert, bool checkedNow, ServedCertificate? served, DateTimeOffset now, List<ProxyEvent> events)
    {
        var reapply = false;
        var match = served is { MatchesName: true } ? served : null;

        if (cert.RenewFromSerial is not null && cert.RenewRequestedAt is { } requested)
        {
            if (match is not null && !string.Equals(match.Serial, cert.RenewFromSerial, StringComparison.OrdinalIgnoreCase))
            {
                cert.RenewFromSerial = null;
                reapply = true;
                events.Add(new ProxyEvent("certificate.renewed", $"{cert.Domain} was renewed", now, null));
            }
            else if (now - requested >= TimeSpan.FromMinutes(Math.Max(1, _options.RenewTimeoutMinutes)))
            {
                cert.RenewFromSerial = null;
                reapply = true;
                if (_log.Latest(cert.Domain) is not { Error: not null } failed || failed.At < requested)
                    _log.RecordFailure(cert.Domain,
                        $"No new certificate was served within {Math.Max(1, _options.RenewTimeoutMinutes)} minutes of the renewal request.");
                events.Add(new ProxyEvent("certificate.renew_failed", $"{cert.Domain} was not renewed", now, null));
            }
        }

        var notReady = CaddyConfigBuilder.ChallengeReady(CertificatePlan.From(cert), _options)
            ? null
            : ChallengeProblem(cert);
        if (!checkedNow)
        {
            // The proxy is stopped or the name is not configured; the last reading stands.
            if (notReady is not null) cert.LastError = notReady;
            return reapply;
        }

        cert.CheckedAt = now;
        cert.LastError = notReady ?? _log.Latest(cert.Domain)?.Error;
        if (match is not null)
        {
            cert.IssuedAt = match.NotBefore;
            cert.ExpiresAt = match.NotAfter;
            cert.SerialNumber = match.Serial;
            cert.Issuer = match.Issuer;
            cert.Algorithm = match.Algorithm;
            cert.Status = CertificateStatusEvaluator.FromDates(match.NotBefore, match.NotAfter, now).Status;
        }
        else
        {
            cert.Status = cert.LastError is null ? CertificateStatus.Issuing : CertificateStatus.Failed;
        }
        return reapply;
    }

    private string ChallengeProblem(Certificate cert) =>
        cert.Challenge == CertificateChallenge.DnsCloudflare
            ? CloudflareToken.Problem(_options) ?? "The DNS challenge cannot be used."
            : "A wildcard certificate needs the DNS challenge.";
}
