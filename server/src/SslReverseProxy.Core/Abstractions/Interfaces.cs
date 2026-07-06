using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Core.Abstractions;

/// <summary>Snapshot of the managed proxy's runtime status.</summary>
public sealed record ProxyStatus(
    ProxyState State,
    string Engine,
    int? ProcessId,
    DateTimeOffset? StartedAt,
    int ActiveRuleCount,
    string? Message);

public sealed record ProxyValidationResult(bool Valid, IReadOnlyList<string> Issues, bool EngineValidated);

public sealed record MetricsSnapshot(
    DateTimeOffset CollectedAt,
    bool Available,
    long TotalRequests,
    long RequestsInFlight,
    IReadOnlyDictionary<string, double> Series,
    string? Message);

/// <summary>
/// Controls the lifecycle and configuration of the external reverse proxy
/// (Caddy/nginx). Implementations must treat every upstream as untrusted and
/// only ever bind the proxy admin interface to loopback.
/// </summary>
public interface IProxyController
{
    Task<ProxyStatus> GetStatusAsync(CancellationToken ct = default);
    Task<ProxyStatus> StartAsync(CancellationToken ct = default);
    Task<ProxyStatus> StopAsync(CancellationToken ct = default);

    /// <summary>Regenerate and push proxy config from the current rule set.</summary>
    Task<ProxyStatus> ApplyConfigurationAsync(IReadOnlyCollection<ProxyRule> rules, CancellationToken ct = default);

    /// <summary>Generate the proxy config JSON for a rule set without applying it (preview).</summary>
    string BuildConfigJson(IReadOnlyCollection<ProxyRule> rules);

    /// <summary>Validate a rule set (structural checks always; engine validation when available).</summary>
    Task<ProxyValidationResult> ValidateConfigurationAsync(IReadOnlyCollection<ProxyRule> rules, CancellationToken ct = default);

    /// <summary>Push a previously captured config JSON verbatim (used for rollback).</summary>
    Task<ProxyStatus> ApplyRawConfigAsync(string configJson, CancellationToken ct = default);

    /// <summary>Scrape runtime metrics from the proxy admin endpoint.</summary>
    Task<MetricsSnapshot> GetMetricsAsync(CancellationToken ct = default);
}

public sealed record UpstreamHealth(bool Reachable, int? StatusCode, long? LatencyMs, string? Error);

/// <summary>
/// Probes a proxy upstream for reachability. MUST re-apply the SSRF policy before
/// making any outbound request so the health check can't be abused as an SSRF
/// primitive.
/// </summary>
public interface IUpstreamHealthChecker
{
    Task<UpstreamHealth> CheckAsync(string upstreamUrl, CancellationToken ct = default);
}

public sealed record ProxyEvent(string Type, string Message, DateTimeOffset At, string? Actor);

/// <summary>In-process publish/subscribe stream of control-plane events for SSE.</summary>
public interface IEventStream
{
    void Publish(ProxyEvent evt);
    IAsyncEnumerable<ProxyEvent> Subscribe(CancellationToken ct);
}

/// <summary>Hashes and verifies API-key secrets. Never stores plaintext.</summary>
public interface IApiKeyHasher
{
    (byte[] hash, byte[] salt, int iterations) Hash(string secret);
    bool Verify(string secret, byte[] expectedHash, byte[] salt, int iterations);
}

public sealed record IssuedApiKey(ApiKey Record, string PlaintextToken);

public interface IApiKeyService
{
    /// <summary>Create a new key; the plaintext token is returned once and never persisted.</summary>
    Task<IssuedApiKey> CreateAsync(Guid userId, string name, TimeSpan? lifetime, CancellationToken ct = default);

    /// <summary>Resolve a presented token to its owning user, or null if invalid/expired/revoked.</summary>
    Task<User?> AuthenticateAsync(string presentedToken, CancellationToken ct = default);

    Task RevokeAsync(Guid apiKeyId, CancellationToken ct = default);
}

public interface IAuditLog
{
    Task WriteAsync(AuditEntry entry, CancellationToken ct = default);
}

/// <summary>The authenticated principal for the current request.</summary>
public interface ICurrentPrincipal
{
    Guid? UserId { get; }
    string Name { get; }
    Role Role { get; }
    bool IsAuthenticated { get; }
    bool Has(Permission permission);
}
