namespace SslReverseProxy.Core.Domain;

/// <summary>A certificate the config has to say something about beyond what the rules imply.</summary>
/// <param name="Automate">Caddy obtains and renews it without a route naming the host (a manual row).</param>
/// <param name="RenewPending">A forced renewal is waiting for a new serial.</param>
public sealed record CertificatePlan(string Domain, CertificateChallenge Challenge, bool Automate, bool RenewPending)
{
    public static CertificatePlan From(Certificate c) => new(
        c.Domain, c.Challenge, c.Source == CertificateSource.Manual, c.RenewFromSerial is not null);
}

/// <summary>Everything the proxy config is built from: the rules and the certificate rows.</summary>
public sealed record ProxyPlan(IReadOnlyCollection<ProxyRule> Rules, IReadOnlyCollection<CertificatePlan> Certificates)
{
    public ProxyPlan(IReadOnlyCollection<ProxyRule> rules) : this(rules, []) { }

    /// <summary>The plan with no forced renewal, for configs kept for rollback.</summary>
    public ProxyPlan WithoutPendingRenewals() =>
        this with { Certificates = Certificates.Select(c => c with { RenewPending = false }).ToList() };
}
