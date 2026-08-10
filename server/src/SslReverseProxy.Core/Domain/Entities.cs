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

    // Additional upstreams for load balancing, comma-separated URLs in the same
    // form as UpstreamUrl. Empty means a single upstream and no balancing.
    public string? AdditionalUpstreams { get; set; }

    /// <summary>
    /// Caddy load-balancing selection policy. Only emitted when there is more
    /// than one upstream; null falls back to random (Caddy's own default).
    /// </summary>
    public string? LoadBalancePolicy { get; set; }

    // Per-route upstream timeouts, in seconds. Null leaves Caddy's default,
    // which for read/write is "no timeout" — an upstream that accepts the
    // connection and then stalls holds a worker open indefinitely.
    public int? DialTimeoutSeconds { get; set; }
    public int? UpstreamReadTimeoutSeconds { get; set; }
    public int? UpstreamWriteTimeoutSeconds { get; set; }

    /// <summary>
    /// Largest request body this route will forward, in bytes; null is
    /// unlimited. Enforced as the body is read rather than from
    /// Content-Length, so an oversized upload is cut off partway through
    /// instead of being refused up front. The client gets 413 (measured
    /// against Caddy 2.11.4, both just over the cap and at twice it).
    /// </summary>
    public long? MaxRequestBodyBytes { get; set; }

    /// <summary>
    /// Emits the always-safe response headers (X-Content-Type-Options,
    /// Referrer-Policy). On by default: neither can break a working site.
    /// The headers that CAN break one — HSTS and X-Frame-Options — are separate
    /// opt-in fields below.
    /// </summary>
    public bool EnableSecurityHeaders { get; set; } = true;

    /// <summary>
    /// Strict-Transport-Security max-age, in days. Deliberately opt-in and
    /// null by default: a browser that has seen HSTS refuses plaintext for the
    /// whole max-age and the operator cannot recall it, so turning this on for
    /// existing deployments is not ours to do.
    /// </summary>
    public int? HstsMaxAgeDays { get; set; }

    /// <summary>
    /// SNI / certificate name to expect from an https upstream. Without it
    /// Caddy verifies against the dial address, so a backend reached by IP or
    /// by an internal name that is not on its certificate fails the handshake.
    /// Only meaningful when the upstreams are https.
    /// </summary>
    public string? UpstreamTlsServerName { get; set; }

    /// <summary>
    /// PEM file on the proxy host holding the CA that signed the upstream's
    /// certificate. This is the right way to reach a backend with a private or
    /// self-signed certificate: the certificate is still verified, just against
    /// a CA the system store does not carry.
    /// </summary>
    public string? UpstreamTlsTrustedCaFile { get; set; }

    /// <summary>
    /// Stops verifying the upstream's certificate entirely.
    /// <para>
    /// This throws away what TLS to the backend was for — anything that can get
    /// between the proxy and the upstream can present its own certificate and
    /// read or rewrite the traffic. Prefer <see cref="UpstreamTlsServerName"/>
    /// for a name mismatch and <see cref="UpstreamTlsTrustedCaFile"/> for a
    /// private CA; reach for this only when neither is possible.
    /// </para>
    /// </summary>
    public bool UpstreamTlsInsecureSkipVerify { get; set; }

    /// <summary>
    /// Adds includeSubDomains to the HSTS header. Off by default and separate
    /// from <see cref="HstsMaxAgeDays"/> on purpose: on an apex domain it pins
    /// every subdomain to HTTPS, including hosts served by systems this rule
    /// has nothing to do with, and no later header can take that back.
    /// </summary>
    public bool HstsIncludeSubdomains { get; set; }

    /// <summary>X-Frame-Options value ("DENY" or "SAMEORIGIN"); null omits it.</summary>
    public string? FrameOptions { get; set; }

    // Caddy-native active health checking. Null path disables it and leaves
    // upstream liveness to the control plane's own out-of-band probe.
    public string? HealthCheckPath { get; set; }
    public int? HealthCheckIntervalSeconds { get; set; }
    public int? HealthCheckTimeoutSeconds { get; set; }

    /// <summary>
    /// Status the health check must see to call an upstream healthy. A
    /// single-digit value is a whole class, so 2 means "any 2xx".
    /// </summary>
    public int? HealthCheckExpectStatus { get; set; }

    /// <summary>
    /// Keeps this route's requests out of the data-plane access log. For hosts
    /// whose URLs carry things that should not be written to disk.
    /// </summary>
    public bool SkipAccessLog { get; set; }

    /// <summary>
    /// Optimistic concurrency token, incremented on every write and surfaced to
    /// clients as an ETag. Without it two operators who both loaded a rule and
    /// both saved would each write a whole rule from their own stale copy, and
    /// the later save would silently undo the earlier one.
    /// <para>
    /// A counter rather than a timestamp: UpdatedAt is only as fine-grained as
    /// the clock, so two writes in the same tick would compare equal.
    /// </para>
    /// </summary>
    public int Version { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Primary upstream first, then any additional ones, de-duplicated.</summary>
    public IReadOnlyList<string> AllUpstreams()
    {
        var all = new List<string> { UpstreamUrl };
        if (!string.IsNullOrWhiteSpace(AdditionalUpstreams))
            all.AddRange(AdditionalUpstreams.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return all.Where(u => !string.IsNullOrWhiteSpace(u))
                  .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
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
