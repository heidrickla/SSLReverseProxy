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

        if (cert.ExpiresAt is not { } expires)
            return new CertificateHealth(CertificateStatus.Unknown, null);

        var days = (int)Math.Floor((expires - now).TotalDays);
        if (expires <= now)
            return new CertificateHealth(CertificateStatus.Expired, days);
        if (days <= ExpiringWindowDays)
            return new CertificateHealth(CertificateStatus.Expiring, days);
        return new CertificateHealth(CertificateStatus.Valid, days);
    }
}
