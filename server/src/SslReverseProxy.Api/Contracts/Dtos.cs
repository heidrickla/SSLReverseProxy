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
public sealed record RuleHardeningRequest(
    string? AdditionalUpstreams = null,
    string? LoadBalancePolicy = null,
    int? DialTimeoutSeconds = null,
    int? UpstreamReadTimeoutSeconds = null,
    int? UpstreamWriteTimeoutSeconds = null,
    long? MaxRequestBodyBytes = null,
    bool? EnableSecurityHeaders = null,
    int? HstsMaxAgeDays = null,
    bool? HstsIncludeSubdomains = null,
    string? FrameOptions = null,
    string? HealthCheckPath = null,
    int? HealthCheckIntervalSeconds = null,
    int? HealthCheckTimeoutSeconds = null,
    int? HealthCheckExpectStatus = null,
    bool? SkipAccessLog = null);

public sealed record CreateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword, RuleHardeningRequest? Hardening = null);
public sealed record UpdateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword, RuleHardeningRequest? Hardening = null);
public sealed record ToggleRuleRequest(bool Enabled);
public sealed record CreateUserRequest(string Name, string Email, Role Role);
public sealed record UpdateUserRequest(string Name, Role Role, bool IsActive);
public sealed record CreateApiKeyRequest(Guid UserId, string Name, int? LifetimeDays);
public sealed record RollbackRequest(long SnapshotId);

// Responses
public sealed record ServerDto(Guid Id, string Name, string Host, string Os, int RuleCount);
public sealed record RuleHardeningDto(
    string? AdditionalUpstreams,
    string? LoadBalancePolicy,
    int? DialTimeoutSeconds,
    int? UpstreamReadTimeoutSeconds,
    int? UpstreamWriteTimeoutSeconds,
    long? MaxRequestBodyBytes,
    bool EnableSecurityHeaders,
    int? HstsMaxAgeDays,
    bool HstsIncludeSubdomains,
    string? FrameOptions,
    string? HealthCheckPath,
    int? HealthCheckIntervalSeconds,
    int? HealthCheckTimeoutSeconds,
    int? HealthCheckExpectStatus,
    bool SkipAccessLog);

public sealed record RuleDto(Guid Id, Guid ServerId, string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, bool BasicAuthEnabled, string? BasicAuthUsername, RuleHardeningDto Hardening);
public sealed record ProxyValidationDto(bool Valid, IReadOnlyList<string> Issues, bool EngineValidated);
public sealed record MetricsDto(DateTimeOffset CollectedAt, bool Available, long TotalRequests, long RequestsInFlight, IReadOnlyDictionary<string, double> Series, string? Message);
public sealed record SnapshotDto(long Id, DateTimeOffset CreatedAt, string Actor, int RuleCount, string? Note);
public sealed record UpstreamHealthDto(bool Reachable, int? StatusCode, long? LatencyMs, string? Error);
public sealed record CertStatusDto(Guid Id, string Domain, string Status, int? DaysRemaining, DateTimeOffset? ExpiresAt);
public sealed record ReadyDto(bool Ready, bool Database, string ProxyState);
public sealed record CertificateDto(Guid Id, string Domain, string Issuer, string Status, DateTimeOffset? ExpiresAt, bool Managed);
public sealed record UserDto(Guid Id, string Name, string Email, string Role, bool IsActive, DateTimeOffset? LastSeenAt);
public sealed record ApiKeyDto(Guid Id, string Name, string Prefix, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt);
public sealed record IssuedApiKeyDto(Guid Id, string Name, string Token, DateTimeOffset? ExpiresAt);
public sealed record AuditDto(long Id, DateTimeOffset Timestamp, string Actor, string Action, string TargetType, string TargetName, bool Success, string? SourceIp);
public sealed record WhoAmIDto(Guid? UserId, string Name, string Role, string[] Permissions);
public sealed record ProxyStatusDto(string State, string Engine, int? ProcessId, DateTimeOffset? StartedAt, int ActiveRuleCount, string? Message);

public static class DtoMappings
{
    public static ServerDto ToDto(this ProxyServer s) => new(s.Id, s.Name, s.Host, s.Os, s.Rules?.Count ?? 0);
    public static RuleDto ToDto(this ProxyRule r) => new(r.Id, r.ServerId, r.Domain, r.UpstreamUrl, r.EnableTls, r.Enabled, r.AllowedCidrs, r.DeniedCidrs, r.RateLimitPerMinute, !string.IsNullOrEmpty(r.BasicAuthPasswordHash), r.BasicAuthUsername, r.ToHardeningDto());

    public static RuleHardeningDto ToHardeningDto(this ProxyRule r) => new(
        r.AdditionalUpstreams, r.LoadBalancePolicy,
        r.DialTimeoutSeconds, r.UpstreamReadTimeoutSeconds, r.UpstreamWriteTimeoutSeconds,
        r.MaxRequestBodyBytes, r.EnableSecurityHeaders, r.HstsMaxAgeDays,
        r.HstsIncludeSubdomains, r.FrameOptions,
        r.HealthCheckPath, r.HealthCheckIntervalSeconds, r.HealthCheckTimeoutSeconds,
        r.HealthCheckExpectStatus, r.SkipAccessLog);
    public static SnapshotDto ToDto(this ConfigSnapshot s) => new(s.Id, s.CreatedAt, s.Actor, s.RuleCount, s.Note);
    public static CertificateDto ToDto(this Certificate c) => new(c.Id, c.Domain, c.Issuer, c.Status.ToString(), c.ExpiresAt, c.Managed);
    public static UserDto ToDto(this User u) => new(u.Id, u.Name, u.Email, u.Role.ToString(), u.IsActive, u.LastSeenAt);
    public static ApiKeyDto ToDto(this ApiKey k) => new(k.Id, k.Name, k.Prefix, k.CreatedAt, k.ExpiresAt, k.RevokedAt);
    public static AuditDto ToDto(this AuditEntry a) => new(a.Id, a.Timestamp, a.ActorName, a.Action, a.TargetType, a.TargetName, a.Success, a.SourceIp);
}
