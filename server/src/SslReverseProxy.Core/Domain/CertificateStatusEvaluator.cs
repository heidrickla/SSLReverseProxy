namespace SslReverseProxy.Core.Domain;

public readonly record struct CertificateHealth(
    CertificateStatus Status,
    int? DaysRemaining);

/// <summary>
/// Pure logic for deriving a certificate's health from its dates. Used by the
/// status endpoint so the UI reflects real expiry rather than a stored flag.
/// </summary>
public static class CertificateStatusEvaluator
{
    public const int ExpiringWindowDays = 30;

    public static CertificateHealth Evaluate(Certificate cert, DateTimeOffset now)
    {
        if (cert.Status == CertificateStatus.Issuing || cert.Status == CertificateStatus.Failed)
            return new CertificateHealth(cert.Status, null);

        return FromDates(cert.IssuedAt, cert.ExpiresAt, now);
    }

    /// <summary>
    /// Expiring once less than <see cref="ExpiringWindowDays"/> or a third of the lifetime remains, whichever is
    /// shorter. Caddy renews at a third remaining, so a short-lived certificate (Caddy's internal CA issues 12-hour
    /// ones) reads as expiring only when its renewal is due.
    /// </summary>
    public static CertificateHealth FromDates(DateTimeOffset? issuedAt, DateTimeOffset? expiresAt, DateTimeOffset now)
    {
        if (expiresAt is not { } expires)
            return new CertificateHealth(CertificateStatus.Unknown, null);

        var remaining = expires - now;
        var days = (int)Math.Floor(remaining.TotalDays);
        if (expires <= now)
            return new CertificateHealth(CertificateStatus.Expired, days);

        var window = TimeSpan.FromDays(ExpiringWindowDays);
        if (issuedAt is { } issued && expires > issued)
        {
            var third = (expires - issued) / 3;
            if (third < window) window = third;
        }
        return remaining <= window
            ? new CertificateHealth(CertificateStatus.Expiring, days)
            : new CertificateHealth(CertificateStatus.Valid, days);
    }
}
