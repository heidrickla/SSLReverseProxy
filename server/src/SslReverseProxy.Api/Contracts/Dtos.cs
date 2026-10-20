using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Api.Contracts;

// Requests
public sealed record CreateServerRequest(string Name, string Host, string Os);

/// <summary>
/// Optional per-route hardening. Grouped into its own object rather than
/// flattened onto the rule requests so the flat shape stays readable, and
/// defaulted to null so a client that predates these settings still works —
/// omitting it leaves every value at the rule's current setting.
/// </summary>
public sealed record RuleHardeningRequest
{
    // Init properties rather than a positional record: at this width a
    // positional list is a row of same-typed slots that silently accepts a
    // wrong order, and the compiler only notices when two adjacent types
    // happen to differ.
    public string? AdditionalUpstreams { get; init; }
    public string? LoadBalancePolicy { get; init; }

    public int? DialTimeoutSeconds { get; init; }
    public int? UpstreamReadTimeoutSeconds { get; init; }
    public int? UpstreamWriteTimeoutSeconds { get; init; }

    public string? UpstreamTlsServerName { get; init; }
    public string? UpstreamTlsTrustedCaFile { get; init; }
    public bool? UpstreamTlsInsecureSkipVerify { get; init; }

    public long? MaxRequestBodyBytes { get; init; }

    public bool? EnableSecurityHeaders { get; init; }
    public int? HstsMaxAgeDays { get; init; }
    public bool? HstsIncludeSubdomains { get; init; }
    public string? FrameOptions { get; init; }

    public string? HealthCheckPath { get; init; }
    public int? HealthCheckIntervalSeconds { get; init; }
    public int? HealthCheckTimeoutSeconds { get; init; }
    public int? HealthCheckExpectStatus { get; init; }

    public bool? SkipAccessLog { get; init; }
}

/// <summary>
/// Optional path routing. Null leaves the rule's current routing; supplied, both fields are
/// replaced. A null or "/" prefix serves the whole host.
/// </summary>
public sealed record RuleRoutingRequest
{
    public string? PathPrefix { get; init; }
    public bool? StripPathPrefix { get; init; }
}

public sealed record CreateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword, RuleHardeningRequest? Hardening = null, RuleRoutingRequest? Routing = null);
public sealed record UpdateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword, RuleHardeningRequest? Hardening = null, RuleRoutingRequest? Routing = null);
public sealed record ToggleRuleRequest(bool Enabled);
public sealed record CreateUserRequest(string Name, string Email, Role Role);
public sealed record UpdateUserRequest(string Name, Role Role, bool IsActive);
public sealed record CreateApiKeyRequest(Guid UserId, string Name, int? LifetimeDays);
public sealed record RollbackRequest(long SnapshotId);

// Responses
/// <summary>Status is the background monitor's last verdict: Unknown, Active, Inactive or Error.</summary>
public sealed record ServerDto(Guid Id, string Name, string Host, string Os, int RuleCount,
    string Status, int UpstreamsUp, int UpstreamsTotal, DateTimeOffset? StatusCheckedAt);
public sealed record RuleHardeningDto
{
    public string? AdditionalUpstreams { get; init; }
    public string? LoadBalancePolicy { get; init; }

    public int? DialTimeoutSeconds { get; init; }
    public int? UpstreamReadTimeoutSeconds { get; init; }
    public int? UpstreamWriteTimeoutSeconds { get; init; }

    public string? UpstreamTlsServerName { get; init; }
    public string? UpstreamTlsTrustedCaFile { get; init; }
    public bool UpstreamTlsInsecureSkipVerify { get; init; }

    public long? MaxRequestBodyBytes { get; init; }

    public bool EnableSecurityHeaders { get; init; }
    public int? HstsMaxAgeDays { get; init; }
    public bool HstsIncludeSubdomains { get; init; }
    public string? FrameOptions { get; init; }

    public string? HealthCheckPath { get; init; }
    public int? HealthCheckIntervalSeconds { get; init; }
    public int? HealthCheckTimeoutSeconds { get; init; }
    public int? HealthCheckExpectStatus { get; init; }

    public bool SkipAccessLog { get; init; }
}

public sealed record RuleRoutingDto(string? PathPrefix, bool StripPathPrefix);
public sealed record RuleDto(Guid Id, Guid ServerId, string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, bool BasicAuthEnabled, string? BasicAuthUsername, RuleHardeningDto Hardening, RuleRoutingDto Routing, int Version);
public sealed record ProxyValidationDto(bool Valid, IReadOnlyList<string> Issues, bool EngineValidated);
public sealed record MetricsDto(DateTimeOffset CollectedAt, bool Available, long TotalRequests, long RequestsInFlight, IReadOnlyDictionary<string, double> Series, string? Message);

/// <summary>Stored traffic for the last 24 hours. Times and averages are null when there is nothing to base them on.</summary>
public sealed record TrafficDto(
    int SampleSeconds, bool ProxyRunning, int Samples, DateTimeOffset? From, DateTimeOffset? To,
    long Requests, long BytesIn, long BytesOut, long? InFlight,
    double? AvgTtfbMs, double? AvgResponseMs, double? P50Ms, double? P90Ms, double? P95Ms,
    StatusClassesDto Status, IReadOnlyList<HourlyRequestsDto> Hourly);
public sealed record StatusClassesDto(long Success, long Redirect, long ClientError, long ServerError);
public sealed record HourlyRequestsDto(DateTimeOffset Start, long Requests);
public sealed record SnapshotDto(long Id, DateTimeOffset CreatedAt, string Actor, int RuleCount, string? Note);
public sealed record UpstreamHealthDto(bool Reachable, int? StatusCode, long? LatencyMs, string? Error);
public sealed record CertStatusDto(Guid Id, string Domain, string Status, int? DaysRemaining, DateTimeOffset? ExpiresAt);
public sealed record ReadyDto(bool Ready, bool Database, string ProxyState);
/// <summary>A certificate row. Status is derived from the served certificate's dates at read time.</summary>
public sealed record CertificateDto(
    Guid Id, string Domain, string Issuer, string Status, int? DaysRemaining,
    DateTimeOffset? IssuedAt, DateTimeOffset? ExpiresAt, string? SerialNumber, string? Algorithm,
    string Source, string Challenge, string? LastError, DateTimeOffset? CheckedAt, bool RenewPending, bool Managed);
public sealed record CreateCertificateRequest(string Domain, string? Challenge);
public sealed record UpdateCertificateRequest(string Challenge);
/// <summary>A validation method and whether the server can use it now. Never carries the token.</summary>
public sealed record ChallengeDto(string Name, bool Available, bool Wildcard, string? Reason);
/// <summary>A configured alert target. Never carries the URL or token.</summary>
public sealed record AlertTargetDto(string Name, string Kind, IReadOnlyList<string> Events, string? Problem);
public sealed record AlertsDto(IReadOnlyList<AlertTargetDto> Targets, IReadOnlyList<string> Events);
public sealed record AlertTestRequest(string? Target);
public sealed record AlertDeliveryDto(string Target, bool Delivered, int? Status, string? Error, int Attempts);
public sealed record UserDto(Guid Id, string Name, string Email, string Role, bool IsActive, DateTimeOffset? LastSeenAt);
public sealed record ApiKeyDto(Guid Id, string Name, string Prefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt);
public sealed record IssuedApiKeyDto(Guid Id, string Name, string Token, DateTimeOffset? ExpiresAt);
public sealed record AuditDto(long Id, DateTimeOffset Timestamp, string Actor, string Action, string TargetType, string TargetName, bool Success, string? SourceIp);
public sealed record WhoAmIDto(Guid? UserId, string Name, string Role, string[] Permissions);
public sealed record ProxyStatusDto(string State, string Engine, int? ProcessId, DateTimeOffset? StartedAt, int ActiveRuleCount, string? Message);

public static class DtoMappings
{
    public static TrafficDto ToDto(this TrafficSummary t, int sampleSeconds, bool proxyRunning) => new(
        sampleSeconds, proxyRunning, t.Samples, t.From, t.To, t.Requests, t.BytesIn, t.BytesOut, t.InFlight,
        t.AvgTtfbMs, t.AvgResponseMs, t.P50Ms, t.P90Ms, t.P95Ms,
        new StatusClassesDto(t.Status2xx, t.Status3xx, t.Status4xx, t.Status5xx),
        t.Hourly.Select(h => new HourlyRequestsDto(h.Start, h.Requests)).ToList());

    public static ServerDto ToDto(this ProxyServer s, ServerHealth h) =>
        new(s.Id, s.Name, s.Host, s.Os, s.Rules?.Count ?? 0, h.Status.ToString(), h.UpstreamsUp, h.UpstreamsTotal, h.CheckedAt);
    public static RuleDto ToDto(this ProxyRule r) => new(r.Id, r.ServerId, r.Domain, r.UpstreamUrl, r.EnableTls, r.Enabled, r.AllowedCidrs, r.DeniedCidrs, r.RateLimitPerMinute, !string.IsNullOrEmpty(r.BasicAuthPasswordHash), r.BasicAuthUsername, r.ToHardeningDto(), new RuleRoutingDto(r.PathPrefix, r.StripPathPrefix), r.Version);

    public static RuleHardeningDto ToHardeningDto(this ProxyRule r) => new()
    {
        AdditionalUpstreams = r.AdditionalUpstreams,
        LoadBalancePolicy = r.LoadBalancePolicy,
        DialTimeoutSeconds = r.DialTimeoutSeconds,
        UpstreamReadTimeoutSeconds = r.UpstreamReadTimeoutSeconds,
        UpstreamWriteTimeoutSeconds = r.UpstreamWriteTimeoutSeconds,
        UpstreamTlsServerName = r.UpstreamTlsServerName,
        UpstreamTlsTrustedCaFile = r.UpstreamTlsTrustedCaFile,
        UpstreamTlsInsecureSkipVerify = r.UpstreamTlsInsecureSkipVerify,
        MaxRequestBodyBytes = r.MaxRequestBodyBytes,
        EnableSecurityHeaders = r.EnableSecurityHeaders,
        HstsMaxAgeDays = r.HstsMaxAgeDays,
        HstsIncludeSubdomains = r.HstsIncludeSubdomains,
        FrameOptions = r.FrameOptions,
        HealthCheckPath = r.HealthCheckPath,
        HealthCheckIntervalSeconds = r.HealthCheckIntervalSeconds,
        HealthCheckTimeoutSeconds = r.HealthCheckTimeoutSeconds,
        HealthCheckExpectStatus = r.HealthCheckExpectStatus,
        SkipAccessLog = r.SkipAccessLog,
    };
    public static SnapshotDto ToDto(this ConfigSnapshot s) => new(s.Id, s.CreatedAt, s.Actor, s.RuleCount, s.Note);
    public static CertificateDto ToDto(this Certificate c, DateTimeOffset now)
    {
        var health = CertificateStatusEvaluator.Evaluate(c, now);
        return new(c.Id, c.Domain, c.Issuer, health.Status.ToString(), health.DaysRemaining,
            c.IssuedAt, c.ExpiresAt, c.SerialNumber, c.Algorithm, c.Source.ToString(), c.Challenge.ToString(),
            c.LastError, c.CheckedAt, c.RenewFromSerial is not null, c.Managed);
    }
    public static UserDto ToDto(this User u) => new(u.Id, u.Name, u.Email, u.Role.ToString(), u.IsActive, u.LastSeenAt);
    public static ApiKeyDto ToDto(this ApiKey k) => new(k.Id, k.Name, k.Prefix, k.CreatedAt, k.ExpiresAt, k.RevokedAt);
    public static AuditDto ToDto(this AuditEntry a) => new(a.Id, a.Timestamp, a.ActorName, a.Action, a.TargetType, a.TargetName, a.Success, a.SourceIp);
}
