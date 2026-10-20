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
/// applying the config again. Readings are taken outside <see cref="ProxyChanges"/>; the rows they are
/// applied to are read again inside it.
/// </summary>
public sealed class CertificateMonitor : BackgroundService, ICertificateChecks
{
    private const int MaxConcurrentProbes = 8;
    private static readonly TimeSpan PendingInterval = TimeSpan.FromSeconds(5);

    private readonly IServiceScopeFactory _scopes;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ProxyChanges _changes;
    private readonly ICertificateProbe _probe;
    private readonly CaddyCertificateLog _log;
    private readonly IEventStream _events;
    private readonly IAlertSink _alerts;
    private readonly TimeProvider _clock;
    private readonly ProxyOptions _options;
    private readonly ILogger<CertificateMonitor> _logger;
    private readonly TimeSpan _interval;
    private readonly Channel<bool> _wake =
        Channel.CreateBounded<bool>(new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    public CertificateMonitor(
        IServiceScopeFactory scopes, IHostApplicationLifetime lifetime, ProxyChanges changes,
        ICertificateProbe probe, CaddyCertificateLog log, IEventStream events, IAlertSink alerts, TimeProvider clock,
        IOptions<ProxyOptions> options, ILogger<CertificateMonitor> logger)
    {
        _scopes = scopes;
        _lifetime = lifetime;
        _changes = changes;
        _probe = probe;
        _log = log;
        _events = events;
        _alerts = alerts;
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

    /// <summary>One cycle. Returns whether a forced renewal or a cleanup is still waiting, which shortens the next wait.</summary>
    internal async Task<bool> CheckAllAsync(CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        bool running;
        HashSet<string> configured;
        using (var sync = await _changes.EnterAsync(ct))
        {
            running = (await sync.StatusAsync(ct)).State == ProxyState.Running;
            configured = await SyncRuleRowsAsync(db, ct);
        }
        db.ChangeTracker.Clear();
        var names = await db.Certificates.AsNoTracking().Select(c => new { c.Id, c.Domain }).ToListAsync(ct);

        // Each probe can take seconds, so readings are taken outside the scope. A renewal requested after
        // readAt is judged by a later cycle's readings, never by these.
        var readAt = _clock.GetUtcNow();
        var probed = new Dictionary<Guid, ServedCertificate?>();
        if (running)
        {
            using var throttle = new SemaphoreSlim(MaxConcurrentProbes);
            var reads = await Task.WhenAll(names.Where(c => configured.Contains(c.Domain)).Select(async c =>
            {
                await throttle.WaitAsync(ct);
                try { return (c.Id, Reading: await _probe.ReadAsync(c.Domain, ct)); }
                finally { throttle.Release(); }
            }));
            foreach (var (id, reading) in reads) probed[id] = reading;
        }

        using var change = await _changes.EnterAsync(ct);
        var certs = await db.Certificates.ToListAsync(ct);
        var now = _clock.GetUtcNow();
        var renewalEnded = false;
        var events = new List<ProxyEvent>();
        var alerts = new List<Alert>();
        foreach (var cert in certs)
        {
            var before = cert.Status;
            var checkedNow = probed.TryGetValue(cert.Id, out var reading);
            renewalEnded |= Update(cert, checkedNow, reading, readAt, now, events);
            // Only a fresh reading alerts; a stored status can be days old.
            if (checkedNow && CertificateAlerts.Evaluate(cert, now) is { } alert)
                alerts.Add(alert);
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
        foreach (var a in alerts) _alerts.Raise(a);

        // A stopped proxy holds no policy, and its next start builds the config from the rows.
        if ((renewalEnded || change.PolicyStale) && (await change.StatusAsync(ct)).State == ProxyState.Running)
        {
            var status = await change.ApplyAsync(await db.LoadProxyPlanAsync(ct), ct);
            if (status.State != ProxyState.Running)
            {
                change.PolicyLeftBehind();
                _logger.LogWarning("Could not apply the config after a forced renewal ended; retrying: {Message}", status.Message);
            }
        }

        return change.PolicyStale || certs.Any(c => c.RenewFromSerial is not null);
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

    /// <summary>
    /// Applies one reading, taken from <paramref name="readAt"/>, to a row. Returns whether a forced
    /// renewal ended, so the config has to be applied again.
    /// </summary>
    private bool Update(Certificate cert, bool checkedNow, ServedCertificate? served, DateTimeOffset readAt, DateTimeOffset now,
        List<ProxyEvent> events)
    {
        var reapply = false;
        var match = served is { MatchesName: true } ? served : null;

        if (cert.RenewFromSerial is not null && cert.RenewRequestedAt is { } requested)
        {
            if (match is not null && readAt >= requested
                && !string.Equals(match.Serial, cert.RenewFromSerial, StringComparison.OrdinalIgnoreCase))
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
