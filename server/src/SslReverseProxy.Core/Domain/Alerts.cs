namespace SslReverseProxy.Core.Domain;

/// <summary>Alert types a target can subscribe to, plus the test alert.</summary>
public static class AlertTypes
{
    public const string ServerDown = "server.down";
    public const string ServerUp = "server.up";
    public const string CertificateExpiring = "certificate.expiring";
    public const string CertificateExpired = "certificate.expired";
    public const string CertificateFailed = "certificate.failed";

    /// <summary>Sent only to the target a test names, whatever its event list.</summary>
    public const string Test = "test";

    public static readonly IReadOnlyList<string> Subscribable =
        [ServerDown, ServerUp, CertificateExpiring, CertificateExpired, CertificateFailed];
}

public enum AlertSeverity
{
    Info,
    Warning,
    Critical,
}

/// <summary>One notification. <paramref name="Subject"/> is the server name or certificate name it concerns.</summary>
public sealed record Alert(
    string Type, AlertSeverity Severity, string Subject, string Title, string Message, DateTimeOffset At);

/// <summary>
/// The alert a certificate's latest reading calls for. Expiring and Expired alert once per expiry date,
/// Failed once until the name reads Valid again. Issuing and Unknown leave the record alone, so a probe
/// that briefly finds nothing does not repeat an alert.
/// </summary>
public static class CertificateAlerts
{
    public static Alert? Evaluate(Certificate cert, DateTimeOffset now)
    {
        switch (cert.Status)
        {
            case CertificateStatus.Valid:
                cert.AlertedStatus = null;
                cert.AlertedExpiresAt = null;
                return null;
            case CertificateStatus.Expiring or CertificateStatus.Expired or CertificateStatus.Failed:
                var expiry = cert.Status == CertificateStatus.Failed ? null : cert.ExpiresAt;
                if (cert.AlertedStatus == cert.Status && cert.AlertedExpiresAt == expiry) return null;
                cert.AlertedStatus = cert.Status;
                cert.AlertedExpiresAt = expiry;
                return Build(cert, now);
            default:
                return null;
        }
    }

    private static Alert Build(Certificate cert, DateTimeOffset now)
    {
        var error = string.IsNullOrEmpty(cert.LastError) ? "" : $" Last error: {cert.LastError}";
        var expires = cert.ExpiresAt is { } at ? at.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'") : "an unknown date";
        return cert.Status switch
        {
            CertificateStatus.Expiring => new Alert(AlertTypes.CertificateExpiring, AlertSeverity.Warning, cert.Domain,
                $"Certificate expiring: {cert.Domain}",
                $"{cert.Domain} expires {expires}, {Math.Max(0, (int)((cert.ExpiresAt ?? now) - now).TotalDays)} days from now.{error}", now),
            CertificateStatus.Expired => new Alert(AlertTypes.CertificateExpired, AlertSeverity.Critical, cert.Domain,
                $"Certificate expired: {cert.Domain}", $"{cert.Domain} expired {expires}.{error}", now),
            _ => new Alert(AlertTypes.CertificateFailed, AlertSeverity.Warning, cert.Domain,
                $"Certificate failed: {cert.Domain}",
                $"No certificate is served for {cert.Domain}.{error}", now),
        };
    }
}
