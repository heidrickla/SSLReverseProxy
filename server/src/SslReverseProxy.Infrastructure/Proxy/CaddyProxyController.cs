using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Manages the lifecycle and configuration of an external Caddy reverse proxy.
/// Registered as a singleton; guards its own process state with a lock. Talks to
/// Caddy only over the loopback admin API.
/// </summary>
public sealed class CaddyProxyController : IProxyController, IDisposable
{
    private static readonly TimeSpan AdminStartTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan ScrapeTimeout = TimeSpan.FromSeconds(5);
    /// <summary>Bounds every admin call, so a stalled Caddy holds a <see cref="ProxyChanges"/> scope at most this long.</summary>
    public static readonly TimeSpan AdminRequestTimeout = TimeSpan.FromSeconds(30);

    private readonly ProxyOptions _options;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<CaddyProxyController> _logger;
    private readonly TimeProvider _clock;
    private readonly TrafficRecorder _traffic;
    private readonly SecretRedactor _redactor;
    private readonly CaddyCertificateLog _certificates;
    private readonly RecentRequests _recent;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private DateTimeOffset? _startedAt;
    private int _activeRuleCount;

    public CaddyProxyController(
        IOptions<ProxyOptions> options,
        IHttpClientFactory httpFactory,
        ILogger<CaddyProxyController> logger,
        TimeProvider clock,
        TrafficRecorder traffic,
        SecretRedactor redactor,
        CaddyCertificateLog certificates,
        RecentRequests recent)
    {
        _options = options.Value;
        _httpFactory = httpFactory;
        _logger = logger;
        _clock = clock;
        _traffic = traffic;
        _redactor = redactor;
        _certificates = certificates;
        _recent = recent;
    }

    public async Task<ProxyStatus> GetStatusAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try { return Snapshot(); }
        finally { _gate.Release(); }
    }

    public async Task<ProxyStatus> StartAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_process is { HasExited: false })
                return Snapshot();

            if (!BinaryAvailable())
                return Unavailable("Caddy executable was not found. Set Proxy:CaddyPath.");

            Directory.CreateDirectory(_options.ConfigDirectory);
            var configPath = Path.Combine(_options.ConfigDirectory, "caddy.json");
            // Start from an empty valid config; rules are applied via ApplyConfiguration.
            await File.WriteAllTextAsync(configPath,
                CaddyConfigBuilder.Build(Array.Empty<ProxyRule>(), _options).ToJsonString(), ct);

            var psi = CaddyEnvironment.StartInfo(_options, "run", "--config", configPath);

            var proc = Process.Start(psi);
            if (proc is null)
                return Faulted("Failed to start the Caddy process.");

            // Redirected output has to be read: once the pipe fills, Caddy blocks
            // on its next log line and the admin API stops answering.
            proc.OutputDataReceived += ForwardCaddyOutput;
            proc.ErrorDataReceived += ForwardCaddyOutput;
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

            // A config pushed before the admin API listens is refused.
            if (await WaitForAdminAsync(proc, ct) is { } startError)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                proc.Dispose();
                return Faulted(startError);
            }

            _process = proc;
            _startedAt = _clock.GetUtcNow();
            _activeRuleCount = 0;
            _traffic.ProcessStopped();
            _logger.LogInformation("Started Caddy (pid {Pid}).", proc.Id);
            return Snapshot();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting proxy.");
            return Faulted(ex.Message);
        }
        finally { _gate.Release(); }
    }

    public async Task<ProxyStatus> StopAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_process is null || _process.HasExited)
            {
                Reset();
                return Snapshot();
            }

            await CaptureTrafficCoreAsync(ct);
            try
            {
                _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error stopping proxy process; resetting state.");
            }

            Reset();
            _traffic.ProcessStopped();
            _logger.LogInformation("Stopped Caddy.");
            return Snapshot();
        }
        finally { _gate.Release(); }
    }

    public async Task<ProxyStatus> ApplyConfigurationAsync(ProxyPlan plan, CancellationToken ct = default)
    {
        var rules = plan.Rules;
        await _gate.WaitAsync(ct);
        try
        {
            // Refused whatever the process state, so a stopped proxy reports why its rules cannot load.
            if (RoutePath.Conflicts(rules).Concat(PlaceholderIssues(rules)).FirstOrDefault() is { } refused)
                return Faulted(refused);

            if (_process is null || _process.HasExited)
                return _process is null && !BinaryAvailable()
                    ? Unavailable("Caddy is not installed.")
                    : Stopped("Proxy is stopped; start it before applying configuration.");
            var config = CaddyConfigBuilder.Build(plan, _options);
            var ok = await PostConfigAsync(config, ct);
            if (!ok)
                return Faulted("Failed to push configuration to the Caddy admin API.");

            _activeRuleCount = rules.Count(r => r.Enabled);
            return Snapshot();
        }
        finally { _gate.Release(); }
    }

    public string BuildConfigJson(ProxyPlan plan) =>
        CaddyConfigBuilder.Build(plan, _options).ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

    public async Task<ProxyValidationResult> ValidateConfigurationAsync(ProxyPlan plan, CancellationToken ct = default)
    {
        var rules = plan.Rules;
        var issues = new List<string>();

        // Structural checks always run, regardless of whether Caddy is installed.
        var enabled = rules.Where(r => r.Enabled).ToList();
        issues.AddRange(RoutePath.Conflicts(enabled));
        issues.AddRange(PlaceholderIssues(enabled));

        foreach (var r in enabled)
        {
            if (!Uri.TryCreate(r.UpstreamUrl, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                issues.Add($"Rule '{r.Domain}' has an invalid upstream URL.");
        }

        // Optional engine validation when the binary is present.
        var engineValidated = false;
        if (issues.Count == 0 && BinaryAvailable())
        {
            engineValidated = await RunCaddyValidateAsync(BuildConfigJson(plan), issues, ct);
        }

        return new ProxyValidationResult(issues.Count == 0, issues, engineValidated);
    }

    private async Task<bool> RunCaddyValidateAsync(string configJson, List<string> issues, CancellationToken ct)
    {
        try
        {
            Directory.CreateDirectory(_options.ConfigDirectory);
            var tmp = Path.Combine(_options.ConfigDirectory, $"validate-{Guid.NewGuid():N}.json");
            await File.WriteAllTextAsync(tmp, configJson, ct);
            try
            {
                var psi = CaddyEnvironment.StartInfo(_options, "validate", "--config", tmp);
                using var proc = Process.Start(psi);
                if (proc is null) return false;
                string stderr;
                try
                {
                    // Both streams drained together, so neither pipe fills while the other is read.
                    var stdout = proc.StandardOutput.ReadToEndAsync(ct);
                    stderr = await proc.StandardError.ReadToEndAsync(ct);
                    await stdout;
                    await proc.WaitForExitAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* exited */ }
                    throw;
                }
                if (proc.ExitCode != 0)
                    issues.Add($"Caddy validation failed: {_redactor.Redact(stderr.Trim())}");
                return proc.ExitCode == 0;
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* best effort */ }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // the request ended, so it gets no verdict
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not run caddy validate.");
            return false;
        }
    }

    public async Task<ProxyStatus> ApplyRawConfigAsync(string configJson, CancellationToken ct = default)
    {
        // A snapshot holds placeholders, never secret values; one that does was not written by us.
        if (_redactor.Contains(configJson))
            return Faulted("Refused: the config contains a configured secret value.");

        await _gate.WaitAsync(ct);
        try
        {
            if (_process is null || _process.HasExited)
                return Stopped("Proxy is stopped; start it before applying configuration.");

            JsonObject config;
            try
            {
                config = System.Text.Json.Nodes.JsonNode.Parse(configJson) as JsonObject
                    ?? throw new InvalidOperationException("Config is not a JSON object.");
            }
            catch (Exception ex)
            {
                return Faulted($"Invalid config JSON: {ex.Message}");
            }

            var ok = await PostConfigAsync(config, ct);
            return ok ? Snapshot() : Faulted("Failed to push configuration to the Caddy admin API.");
        }
        finally { _gate.Release(); }
    }

    public async Task<string?> GetRunningConfigJsonAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_process is null || _process.HasExited) return null;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(AdminRequestTimeout);
            using var response = await AdminClient().GetAsync("/config/", timeout.Token);
            return response.IsSuccessStatusCode ? await response.Content.ReadAsStringAsync(timeout.Token) : null;
        }
        catch (Exception ex) when (ex is HttpRequestException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            _logger.LogWarning(ex, "Could not read Caddy's running config.");
            return null;
        }
        finally { _gate.Release(); }
    }

    public async Task<MetricsSnapshot> GetMetricsAsync(CancellationToken ct = default)
    {
        var now = _clock.GetUtcNow();
        if (_process is null || _process.HasExited)
            return new MetricsSnapshot(now, false, 0, 0,
                new Dictionary<string, double>(), "Proxy is not running.");

        try
        {
            var client = _httpFactory.CreateClient("caddy-admin");
            client.BaseAddress = new Uri(_options.AdminEndpoint);
            var text = await client.GetStringAsync("/metrics", ct);
            var series = MetricsParser.Parse(text);

            var total = series.TryGetValue("caddy_http_requests_total", out var t) ? (long)t : 0;
            var inFlight = series.TryGetValue("caddy_http_requests_in_flight", out var f) ? (long)f : 0;
            return new MetricsSnapshot(now, true, total, inFlight, series, null);
        }
        catch (Exception ex)
        {
            return new MetricsSnapshot(now, false, 0, 0,
                new Dictionary<string, double>(), $"Metrics unavailable: {ex.Message}");
        }
    }

    public async Task CaptureTrafficAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try { await CaptureTrafficCoreAsync(ct); }
        finally { _gate.Release(); }
    }

    /// <summary>Feeds Caddy's current counters to the recorder. Best effort: a failed scrape loses nothing that the next one cannot see.</summary>
    private async Task CaptureTrafficCoreAsync(CancellationToken ct)
    {
        if (_process is null || _process.HasExited) return;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ScrapeTimeout);
            var text = await AdminClient().GetStringAsync("/metrics", timeout.Token);
            _traffic.Observe(CaddyTraffic.FromMetrics(text));
        }
        catch (Exception ex) when (ex is HttpRequestException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            _logger.LogDebug(ex, "Could not scrape Caddy's metrics.");
        }
    }

    private async Task<string?> WaitForAdminAsync(Process proc, CancellationToken ct)
    {
        var client = AdminClient();
        var elapsed = Stopwatch.StartNew();
        while (true)
        {
            if (proc.HasExited)
                return $"Caddy exited with code {proc.ExitCode} while starting; its output is in the API log.";
            try
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(TimeSpan.FromSeconds(1));
                using var response = await client.GetAsync("/config/", attempt.Token);
                return null;
            }
            catch (Exception ex) when (ex is HttpRequestException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
            {
                // Not listening yet.
            }
            if (elapsed.Elapsed >= AdminStartTimeout)
                return $"Caddy's admin API did not answer within {AdminStartTimeout.TotalSeconds:0} seconds.";
            await Task.Delay(100, ct);
        }
    }

    private void ForwardCaddyOutput(object? sender, DataReceivedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(e.Data)) OnCaddyOutput(e.Data);
    }

    /// <summary>One line of Caddy's stdout or stderr.</summary>
    public void OnCaddyOutput(string line)
    {
        // Access entries go to the recent-requests store only; they carry client addresses and paths.
        if (_recent.Observe(line)) return;
        _certificates.Observe(line);
        var level = line.Contains("\"level\":\"error\"") || line.Contains("\"level\":\"fatal\"") || line.Contains("\"level\":\"panic\"")
            ? LogLevel.Error
            : line.Contains("\"level\":\"warn\"") ? LogLevel.Warning : LogLevel.Debug;
        _logger.Log(level, "caddy: {Line}", _redactor.Redact(line));
    }

    private HttpClient AdminClient()
    {
        var client = _httpFactory.CreateClient("caddy-admin");
        client.BaseAddress = new Uri(_options.AdminEndpoint);
        return client;
    }

    private async Task<bool> PostConfigAsync(JsonObject config, CancellationToken ct)
    {
        // A changed config restarts Caddy's counters; count what came before it.
        await CaptureTrafficCoreAsync(ct);
        try
        {
            var client = AdminClient();
            using var content = new StringContent(config.ToJsonString(), Encoding.UTF8, "application/json");
            var resp = await client.PostAsync("/load", content, ct);
            if (!resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                _logger.LogError("Caddy /load failed ({Status}): {Body}", (int)resp.StatusCode, _redactor.Redact(body));
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error posting Caddy configuration.");
            return false;
        }
    }

    private static IEnumerable<string> PlaceholderIssues(IEnumerable<ProxyRule> rules) =>
        rules.SelectMany(r => r.PlaceholderFields().Select(f =>
            $"Rule '{r.Domain}{r.PathPrefix}' has '{{' or '}}' in {f}; Caddy would read it as a placeholder."));

    private bool BinaryAvailable()
    {
        // Absolute path: check directly. Bare command: assume resolvable via PATH
        // and let process start surface a failure if not.
        if (Path.IsPathRooted(_options.CaddyPath))
            return File.Exists(_options.CaddyPath);
        return true;
    }

    private ProxyStatus Snapshot()
    {
        ProxyState state;
        string? message = null;
        if (!BinaryAvailable())
        {
            state = ProxyState.Unavailable;
            message = "Caddy executable not found.";
        }
        else if (_process is { HasExited: false })
        {
            state = ProxyState.Running;
        }
        else
        {
            state = ProxyState.Stopped;
        }

        return new ProxyStatus(
            state,
            Engine: "caddy",
            ProcessId: _process is { HasExited: false } ? _process.Id : null,
            StartedAt: state == ProxyState.Running ? _startedAt : null,
            ActiveRuleCount: _activeRuleCount,
            Message: message);
    }

    private ProxyStatus Unavailable(string msg) =>
        new(ProxyState.Unavailable, "caddy", null, null, 0, msg);
    private ProxyStatus Faulted(string msg) =>
        new(ProxyState.Faulted, "caddy", null, null, _activeRuleCount, msg);
    private ProxyStatus Stopped(string msg) =>
        new(ProxyState.Stopped, "caddy", null, null, 0, msg);

    private void Reset()
    {
        _process?.Dispose();
        _process = null;
        _startedAt = null;
        _activeRuleCount = 0;
    }

    public void Dispose()
    {
        try
        {
            if (_process is { HasExited: false })
                _process.Kill(entireProcessTree: true);
        }
        catch { /* best effort on shutdown */ }
        _process?.Dispose();
        _gate.Dispose();
    }
}
