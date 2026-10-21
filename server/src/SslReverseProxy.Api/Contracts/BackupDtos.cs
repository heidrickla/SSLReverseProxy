namespace SslReverseProxy.Api.Contracts;

/// <summary>
/// Servers, their rules and the certificate definitions, with stable ids. Rules carry the Basic Auth bcrypt
/// hash so a restore keeps the password. Keys, users, sessions, audit, traffic, snapshots, served certificate
/// state, renewal marks and configured secrets are not in it.
/// </summary>
public sealed record BackupDocument(
    int FormatVersion, DateTimeOffset ExportedAt, IReadOnlyList<BackupServer>? Servers, IReadOnlyList<BackupCertificate>? Certificates);

public sealed record BackupServer(Guid Id, string? Name, string? Host, string? Os, IReadOnlyList<BackupRule>? Rules);

public sealed record BackupRule(
    Guid Id, string? Domain, string? UpstreamUrl, bool EnableTls, bool Enabled,
    string? AllowedCidrs, string? DeniedCidrs, int? RateLimitPerMinute,
    string? BasicAuthUsername, string? BasicAuthPasswordHash,
    RuleHardeningRequest? Hardening, RuleRoutingRequest? Routing);

/// <summary>Source Manual is a name registered by hand; Rule is a TLS rule's host, kept for its chosen challenge.</summary>
public sealed record BackupCertificate(Guid Id, string? Domain, string? Source, string? Challenge);

/// <summary>Mode merge keeps rows the document does not name; replace removes them. Revision comes from the dry run.</summary>
public sealed record BackupImportRequest(BackupDocument? Document, string? Mode, string? Revision);

/// <summary>Kind is server, rule or certificate; Action add, update or remove.</summary>
public sealed record BackupChangeDto(string Kind, string Action, Guid Id, string Name, IReadOnlyList<BackupFieldDto> Fields);

/// <summary>A Basic Auth hash shows as [masked] on the side that has one.</summary>
public sealed record BackupFieldDto(string Field, string? Before, string? After);

/// <summary>
/// The dry run. Problems are keyed by document path (servers[0].rules[1].domain). Preview is Caddy's running
/// config against the config the imported rows build; null while there are problems.
/// </summary>
public sealed record BackupDryRunDto(
    string Mode, IReadOnlyList<BackupChangeDto> Changes, int Unchanged,
    IReadOnlyDictionary<string, string[]> Problems, string Revision, ProxyPreviewDto? Preview);

/// <summary>Proxy is the push made for certificate changes while Caddy runs; rule changes wait for a Reload.</summary>
public sealed record BackupImportResultDto(int Added, int Updated, int Removed, int Unchanged, bool ReloadNeeded, ProxyStatusDto? Proxy);
