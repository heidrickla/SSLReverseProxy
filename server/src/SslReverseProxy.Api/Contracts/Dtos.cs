using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Api.Contracts;

// Requests
public sealed record CreateServerRequest(string Name, string Host, string Os);
public sealed record CreateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword);
public sealed record UpdateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword);
public sealed record ToggleRuleRequest(bool Enabled);
public sealed record CreateUserRequest(string Name, string Email, Role Role);
public sealed record UpdateUserRequest(string Name, Role Role, bool IsActive);
public sealed record CreateApiKeyRequest(Guid UserId, string Name, int? LifetimeDays);
public sealed record RollbackRequest(long SnapshotId);

// Responses
public sealed record ServerDto(Guid Id, string Name, string Host, string Os, int RuleCount);
public sealed record RuleDto(Guid Id, Guid ServerId, string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, bool BasicAuthEnabled, string? BasicAuthUsername);
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
    public static RuleDto ToDto(this ProxyRule r) => new(r.Id, r.ServerId, r.Domain, r.UpstreamUrl, r.EnableTls, r.Enabled, r.AllowedCidrs, r.DeniedCidrs, r.RateLimitPerMinute, !string.IsNullOrEmpty(r.BasicAuthPasswordHash), r.BasicAuthUsername);
    public static SnapshotDto ToDto(this ConfigSnapshot s) => new(s.Id, s.CreatedAt, s.Actor, s.RuleCount, s.Note);
    public static CertificateDto ToDto(this Certificate c) => new(c.Id, c.Domain, c.Issuer, c.Status.ToString(), c.ExpiresAt, c.Managed);
    public static UserDto ToDto(this User u) => new(u.Id, u.Name, u.Email, u.Role.ToString(), u.IsActive, u.LastSeenAt);
    public static ApiKeyDto ToDto(this ApiKey k) => new(k.Id, k.Name, k.Prefix, k.CreatedAt, k.ExpiresAt, k.RevokedAt);
    public static AuditDto ToDto(this AuditEntry a) => new(a.Id, a.Timestamp, a.ActorName, a.Action, a.TargetType, a.TargetName, a.Success, a.SourceIp);
}
