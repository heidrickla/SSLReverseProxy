using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;

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

/// <summary>
/// Sign-in through an identity provider. Null on a write leaves the rule's sign-in as it is; a block replaces it,
/// and a block with no provider removes it. VerifierUrl is the provider's address for authelia, authentik and
/// oauth2-proxy; TeamDomain and Audience are the Cloudflare Access application's.
/// </summary>
public sealed record RuleSignInRequest
{
    public string? Provider { get; init; }
    public string? VerifierUrl { get; init; }
    public string? TeamDomain { get; init; }
    public string? Audience { get; init; }
}

public sealed record CreateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword, RuleHardeningRequest? Hardening = null, RuleRoutingRequest? Routing = null, RuleSignInRequest? SignIn = null);
public sealed record UpdateRuleRequest(string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, string? BasicAuthUsername, string? BasicAuthPassword, RuleHardeningRequest? Hardening = null, RuleRoutingRequest? Routing = null, RuleSignInRequest? SignIn = null);
public sealed record ToggleRuleRequest(bool Enabled);
public sealed record CreateUserRequest(string Name, string Email, Role Role);
public sealed record UpdateUserRequest(string Name, Role Role, bool IsActive);
/// <summary>
/// One of LifetimeDays (a listed day count) or ExpiresAt (at most 365 days ahead). Null Scopes are full access:
/// the owner's role within the caller's permissions, fixed when the key is issued.
/// </summary>
public sealed record CreateApiKeyRequest(Guid UserId, string Name, int? LifetimeDays, DateTimeOffset? ExpiresAt = null, string[]? Scopes = null);
/// <summary>A body chooses the new key's lifetime and scopes as on create; no body keeps the old key's.</summary>
public sealed record RotateApiKeyRequest(int? LifetimeDays, DateTimeOffset? ExpiresAt = null, string[]? Scopes = null);
/// <summary>PreviewDigest, when given, is the digest of the preview the caller saw; the push is refused if it no longer matches.</summary>
public sealed record RollbackRequest(long SnapshotId, string? PreviewDigest = null);
/// <summary>PreviewDigest as on rollback. No body pushes without the check.</summary>
public sealed record ReloadRequest(string? PreviewDigest);

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
public sealed record RuleSignInDto(string Provider, string? VerifierUrl, string? TeamDomain, string? Audience);
public sealed record RuleDto(Guid Id, Guid ServerId, string Domain, string UpstreamUrl, bool EnableTls, bool Enabled, string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute, bool BasicAuthEnabled, string? BasicAuthUsername, RuleHardeningDto Hardening, RuleRoutingDto Routing, int Version, RuleSignInDto? SignIn = null);
public sealed record ProxyValidationDto(bool Valid, IReadOnlyList<string> Issues, bool EngineValidated);
/// <summary>Kind is added, removed or changed. Credential fields show as [masked].</summary>
public sealed record ConfigChangeDto(string Group, string Kind, string Path, string? Before, string? After);
/// <summary>Caddy's running config against the next push. Digest goes back with Reload or rollback.</summary>
public sealed record ProxyPreviewDto(bool RunningAvailable, string? Message, IReadOnlyList<ConfigChangeDto> Changes, bool Truncated, string Digest);
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

/// <summary>One request a rule served. <c>Seq</c> is the cursor for <c>before</c>.</summary>
public sealed record RecentRequestDto(
    long Seq, DateTimeOffset At, string Method, string Host, string Path, int Status, double DurationMs, long Size, string? ClientIp);

/// <summary>A page of a rule's requests, newest first. <c>Next</c> pages older; <c>Message</c> says why none are recorded.</summary>
public sealed record RecentRequestsDto(IReadOnlyList<RecentRequestDto> Requests, long? Next, string? Message);
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
public sealed record AuthMethodsDto(bool Passkeys);
/// <summary>A passkey sign-in: the CSRF token to send as X-CSRF-Token on unsafe requests, and who signed in.</summary>
public sealed record PasskeySignInDto(string CsrfToken, DateTimeOffset ExpiresAt, WhoAmIDto User);
public sealed record SessionDto(string CsrfToken, DateTimeOffset ExpiresAt);
public sealed record PasskeyDto(Guid Id, string Name, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, bool BackedUp);
public sealed record AlertDeliveryDto(string Target, bool Delivered, int? Status, string? Error, int Attempts);
public sealed record UserDto(Guid Id, string Name, string Email, string Role, bool IsActive, DateTimeOffset? LastSeenAt);
/// <summary>
/// UserRole is the owner's current role. Null Scopes: the bootstrap key, or a key issued before full access was
/// stored as a list; it follows its owner's role.
/// </summary>
public sealed record ApiKeyDto(Guid Id, string Name, string Prefix, Guid UserId, string UserName, string UserRole, DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt, DateTimeOffset? RevokedAt, DateTimeOffset? LastUsedAt, string[]? Scopes);
public sealed record IssuedApiKeyDto(Guid Id, string Name, string Token, DateTimeOffset? ExpiresAt, string[]? Scopes);
public sealed record ApiKeyPresetDto(string Id, string Name, string Description, string[]? Scopes);
/// <summary>What the key form offers: lifetimes in days, presets, every permission, and each role's permissions.</summary>
public sealed record ApiKeyOptionsDto(int[] LifetimeDays, int DefaultLifetimeDays, int MaxLifetimeDays,
    ApiKeyPresetDto[] Presets, string[] Permissions, Dictionary<string, string[]> Roles);
/// <summary>The key a request signed in with.</summary>
public sealed record WhoAmIKeyDto(Guid Id, string Name, DateTimeOffset? ExpiresAt, string[]? Scopes);
public sealed record AuditDto(long Id, DateTimeOffset Timestamp, string Actor, string Action, string TargetType, string TargetName, bool Success, string? SourceIp);
/// <summary>
/// Permissions are the effective ones: the role's, narrowed to the key's scopes. WholeRole is false for a key
/// narrower than its owner's role, which cannot manage passkeys.
/// </summary>
public sealed record WhoAmIDto(Guid? UserId, string Name, string Role, string[] Permissions, bool WholeRole, WhoAmIKeyDto? Key = null);
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
    public static RuleDto ToDto(this ProxyRule r) => new(r.Id, r.ServerId, r.Domain, r.UpstreamUrl, r.EnableTls, r.Enabled, r.AllowedCidrs, r.DeniedCidrs, r.RateLimitPerMinute, !string.IsNullOrEmpty(r.BasicAuthPasswordHash), r.BasicAuthUsername, r.ToHardeningDto(), new RuleRoutingDto(r.PathPrefix, r.StripPathPrefix), r.Version,
        r.SignInProvider is { } p ? new RuleSignInDto(p, r.SignInVerifierUrl, r.CloudflareTeamDomain, r.CloudflareAudience) : null);

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
    public static ApiKeyDto ToDto(this ApiKey k) => new(k.Id, k.Name, k.Prefix, k.UserId, k.User?.Name ?? "",
        k.User?.Role.ToString() ?? "", k.CreatedAt, k.ExpiresAt, k.RevokedAt, k.LastUsedAt, ScopeNames(k.Scopes));

    /// <summary>A key's stored scopes as names in permission order, or null when it follows its owner's role.</summary>
    public static string[]? ScopeNames(string? stored) =>
        ApiKeyScopes.Parse(stored)?.Order().Select(p => p.ToString()).ToArray();

    public static string[] Names(IEnumerable<Permission> permissions) =>
        permissions.Order().Select(p => p.ToString()).ToArray();
    public static AuditDto ToDto(this AuditEntry a) => new(a.Id, a.Timestamp, a.ActorName, a.Action, a.TargetType, a.TargetName, a.Success, a.SourceIp);
}
