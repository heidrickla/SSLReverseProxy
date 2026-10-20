using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Persistence;

/// <summary>
/// Sample servers, rules, certificates, users and audit entries for a new
/// Development database (<c>Seed:Demo</c>). The README screenshots and the
/// browser smoke test run against it.
/// <para>
/// Upstreams point at <paramref name="upstreamBase"/>, normally this API's own
/// address, so the health monitor gets an answer without any outside traffic.
/// One upstream uses the discard port (9), where nothing listens, and one rule
/// is disabled, so the three servers come up Active, Error and Inactive.
/// </para>
/// </summary>
public static class DemoSeeder
{
    public static async Task SeedAsync(
        AppDbContext db, string upstreamBase, string actorName, DateTimeOffset now, CancellationToken ct = default)
    {
        var up = upstreamBase.TrimEnd('/');

        db.Servers.AddRange(
            Server("Web Applications", "192.0.2.10", "linux",
                Rule("app.example.com", $"{up}/app"),
                Rule("docs.example.com", $"{up}/docs"),
                Rule("status.example.com", $"{up}/status", enableTls: false)),
            Server("Internal Services", "192.0.2.20", "linux",
                Rule("wiki.example.com", $"{up}/wiki"),
                Rule("git.example.com", "http://127.0.0.1:9")),
            Server("Windows Services", "192.0.2.30", "windows",
                Rule("files.example.com", $"{up}/files", enabled: false)));

        db.Certificates.AddRange(
            Cert("app.example.com", CertificateStatus.Valid, now, daysLeft: 60, CertificateSource.Rule),
            Cert("docs.example.com", CertificateStatus.Valid, now, daysLeft: 60, CertificateSource.Rule),
            Cert("api.example.com", CertificateStatus.Valid, now, daysLeft: 86),
            Cert("portal.example.com", CertificateStatus.Expiring, now, daysLeft: 19));

        db.Users.AddRange(
            new User { Name = "Operations Editor", Email = "operations@example.com", Role = Role.Editor, LastSeenAt = now.AddHours(-3) },
            new User { Name = "Read-only Viewer", Email = "viewer@example.com", Role = Role.Viewer, LastSeenAt = now.AddDays(-1) });

        db.AuditEntries.AddRange(
            Audit(now.AddHours(-4), actorName, "Create Server", "Server", "Web Applications"),
            Audit(now.AddHours(-3), actorName, "Create Proxy Rule", "Proxy Rule", "app.example.com"),
            Audit(now.AddHours(-2), actorName, "Register Certificate", "Certificate", "api.example.com"),
            Audit(now.AddHours(-1), actorName, "Proxy Reload", "Proxy", "Caddy"));

        await db.SaveChangesAsync(ct);
    }

    private static ProxyServer Server(string name, string host, string os, params ProxyRule[] rules) =>
        new() { Name = name, Host = host, Os = os, Rules = rules.ToList() };

    private static ProxyRule Rule(string domain, string upstream, bool enableTls = true, bool enabled = true) =>
        new() { Domain = domain, UpstreamUrl = upstream, EnableTls = enableTls, Enabled = enabled };

    private static Certificate Cert(
        string domain, CertificateStatus status, DateTimeOffset now, int daysLeft,
        CertificateSource source = CertificateSource.Manual) => new()
    {
        Domain = domain,
        Source = source,
        Issuer = "Let's Encrypt",
        Status = status,
        IssuedAt = now.AddDays(daysLeft - 90),
        ExpiresAt = now.AddDays(daysLeft),
        SerialNumber = Convert.ToHexString(Guid.NewGuid().ToByteArray()[..8]),
        Algorithm = "ECDSA P-256",
    };

    private static AuditEntry Audit(DateTimeOffset at, string actor, string action, string targetType, string targetName) => new()
    {
        Timestamp = at,
        ActorName = actor,
        Action = action,
        TargetType = targetType,
        TargetName = targetName,
        SourceIp = "127.0.0.1",
    };
}
