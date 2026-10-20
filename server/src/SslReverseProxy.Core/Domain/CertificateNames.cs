namespace SslReverseProxy.Core.Domain;

/// <summary>Names a certificate row may hold: a hostname, or <c>*.</c> and a hostname of two or more labels.</summary>
public static class CertificateNames
{
    /// <summary>The label put in front of a wildcard's base to ask Caddy which certificate it serves for it.</summary>
    public const string ProbeLabel = "sslrp-check";

    public static string Normalize(string domain) => domain.Trim().TrimEnd('.').ToLowerInvariant();

    public static bool IsWildcard(string domain) => domain.StartsWith("*.", StringComparison.Ordinal);

    /// <summary>The SNI name whose handshake shows the certificate for <paramref name="domain"/>.</summary>
    public static string ProbeHost(string domain) => IsWildcard(domain) ? $"{ProbeLabel}.{domain[2..]}" : domain;

    public static string? Problem(string? input)
    {
        var d = Normalize(input ?? string.Empty);
        if (d.Length is 0 or > 253) return "Domain is required and must be at most 253 characters.";
        var host = IsWildcard(d) ? d[2..] : d;
        if (IsWildcard(d) && !host.Contains('.'))
            return "A wildcard needs a base of two or more labels, such as *.example.com.";
        if (host.Contains('*') || Uri.CheckHostName(host) != UriHostNameType.Dns)
            return "Domain is not a valid hostname.";
        return null;
    }
}
