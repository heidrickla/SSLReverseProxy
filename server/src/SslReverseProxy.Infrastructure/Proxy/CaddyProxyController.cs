using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Manages the lifecycle and configuration of an external Caddy reverse proxy.
/// Registered as a singleton; guards its own process state with a lock. Talks to
/// Caddy only over the loopback admin API.
/// </summary>
public sealed class CaddyProxyController : IProxyController, IDisposable
{
    private readonly ProxyOptions _options;
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<CaddyProxyController> _logger;
    private readonly TimeProvider _clock;

    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _process;
    private DateTimeOffset? _startedAt;
    private int _activeRuleCount;

    public CaddyProxyController(
        IOptions<ProxyOptions> options,
        IHttpClientFactory httpFactory,
        ILogger<CaddyProxyController> logger,
        TimeProvider clock)
    {
        _options = options.Value;
        _httpFactory = httpFactory;
        _logger = logger;
        _clock = clock;
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

            var psi = new ProcessStartInfo
            {
                FileName = _options.CaddyPath,
                ArgumentList = { "run", "--config", configPath },
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
            };

            var proc = Process.Start(psi);
            if (proc is null)
                return Faulted("Failed to start the Caddy process.");

            _process = proc;
            _startedAt = _clock.GetUtcNow();
            _activeRuleCount = 0;
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
            _logger.LogInformation("Stopped Caddy.");
            return Snapshot();
        }
        finally { _gate.Release(); }
    }

    public async Task<ProxyStatus> ApplyConfigurationAsync(IReadOnlyCollection<ProxyRule> rules, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_process is null || _process.HasExited)
                return _process is null && !BinaryAvailable()
                    ? Unavailable("Caddy is not installed.")
                    : Stopped("Proxy is stopped; start it before applying configuration.");

            var config = CaddyConfigBuilder.Build(rules, _options);
            var ok = await PostConfigAsync(config, ct);
            if (!ok)
                return Faulted("Failed to push configuration to the Caddy admin API.");

            _activeRuleCount = rules.Count(r => r.Enabled);
            return Snapshot();
        }
        finally { _gate.Release(); }
    }

    public string BuildConfigJson(IReadOnlyCollection<ProxyRule> rules) =>
        CaddyConfigBuilder.Build(rules, _options).ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

    public async Task<ProxyValidationResult> ValidateConfigurationAsync(IReadOnlyCollection<ProxyRule> rules, CancellationToken ct = default)
    {
        var issues = new List<string>();

        // Structural checks always run, regardless of whether Caddy is installed.
        var enabled = rules.Where(r => r.Enabled).ToList();
        var dupes = enabled.GroupBy(r => r.Domain, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1).Select(g => g.Key);
        foreach (var d in dupes)
            issues.Add($"Duplicate domain '{d}' — only one rule per host is allowed.");

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
            engineValidated = await RunCaddyValidateAsync(BuildConfigJson(rules), issues, ct);
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
                var psi = new ProcessStartInfo
                {
                    FileName = _options.CaddyPath,
                    ArgumentList = { "validate", "--config", tmp },
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                };
                var proc = Process.Start(psi);
                if (proc is null) return false;
                var stderr = await proc.StandardError.ReadToEndAsync(ct);
                await proc.WaitForExitAsync(ct);
                if (proc.ExitCode != 0)
                    issues.Add($"Caddy validation failed: {stderr.Trim()}");
                return proc.ExitCode == 0;
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* best effort */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not run caddy validate.");
            return false;
        }
    }

    public async Task<ProxyStatus> ApplyRawConfigAsync(string configJson, CancellationToken ct = default)
    {
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

    private async Task<bool> PostConfigAsync(JsonObject config, CancellationToken ct)
    {
        try
        {
            var client = _httpFactory.CreateClient("caddy-admin");
            client.BaseAddress = new Uri(_options.AdminEndpoint);
            using var content = new StringContent(config.ToJsonString(), Encoding.UTF8, "application/json");
            var resp = await client.PostAsync("/load", content, ct);
            if (!resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                _logger.LogError("Caddy /load failed ({Status}): {Body}", (int)resp.StatusCode, body);
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
