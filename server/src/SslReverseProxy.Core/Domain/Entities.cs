namespace SslReverseProxy.Core.Domain;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public Role Role { get; set; } = Role.Viewer;
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastSeenAt { get; set; }

    public List<ApiKey> ApiKeys { get; set; } = new();
}

/// <summary>
/// An API key credential. Only a salted hash of the secret is ever stored; the
/// plaintext is shown to the caller exactly once at creation time.
/// </summary>
public class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Public, non-secret prefix used to look up the key without a table scan.</summary>
    public string Prefix { get; set; } = string.Empty;

    /// <summary>PBKDF2 hash of the secret portion (never the secret itself).</summary>
    public byte[] SecretHash { get; set; } = Array.Empty<byte>();
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public int Iterations { get; set; }

    public string Name { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public User? User { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }

    public bool IsActive(DateTimeOffset now) =>
        RevokedAt is null && (ExpiresAt is null || ExpiresAt > now);
}

public class ProxyServer
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty; // IP or hostname of the box
    public string Os { get; set; } = "linux";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public List<ProxyRule> Rules { get; set; } = new();
}

public class ProxyRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ServerId { get; set; }
    public ProxyServer? Server { get; set; }

    public string Domain { get; set; } = string.Empty;   // inbound host
    public string UpstreamUrl { get; set; } = string.Empty; // http(s)://target
    public bool EnableTls { get; set; } = true;
    public bool Enabled { get; set; } = true;

    // Per-route access control (native Caddy remote_ip matchers). Stored as
    // comma-separated CIDRs; empty means "no restriction".
    public string? AllowedCidrs { get; set; }
    public string? DeniedCidrs { get; set; }

    // Per-route rate limit (requests/minute per client). Emitted for the
    // caddy-ratelimit plugin; null disables it.
    public int? RateLimitPerMinute { get; set; }

    // Per-route HTTP basic auth (native Caddy). Only the bcrypt hash is stored;
    // the plaintext password is never persisted.
    public string? BasicAuthUsername { get; set; }
    public string? BasicAuthPasswordHash { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// A point-in-time copy of an applied proxy configuration, captured on every
/// successful apply so a bad or hostile change can be rolled back.
/// </summary>
public class ConfigSnapshot
{
    public long Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string Actor { get; set; } = "system";
    public string ConfigJson { get; set; } = string.Empty;
    public int RuleCount { get; set; }
    public string? Note { get; set; }
}

public class Certificate
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Domain { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public CertificateStatus Status { get; set; } = CertificateStatus.Unknown;
    public DateTimeOffset? IssuedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public string? SerialNumber { get; set; }
    public string? Algorithm { get; set; }
    public bool Managed { get; set; } = true; // issued/renewed automatically by the proxy (ACME)
}

/// <summary>Append-only audit record. Rows are never updated or deleted.</summary>
public class AuditEntry
{
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string ActorName { get; set; } = "system";
    public Guid? ActorUserId { get; set; }
    public string Action { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public string? SourceIp { get; set; }
    public string? Details { get; set; } // JSON
    public bool Success { get; set; } = true;
}
