using System.Net;
using System.Net.Sockets;

namespace SslReverseProxy.Core.Security;

public readonly record struct ValidationResult(bool Ok, string? Reason)
{
    public static ValidationResult Success() => new(true, null);
    public static ValidationResult Fail(string reason) => new(false, reason);
}

/// <summary>
/// Authoritative validation for reverse-proxy upstream targets and inbound
/// domains. This is the real SSRF boundary — it runs server-side before any
/// config is written to the proxy. The browser performs a matching advisory
/// check, but this one is trusted.
/// </summary>
public sealed class ProxyTargetValidator
{
    private readonly ProxyTargetPolicy _policy;

    public ProxyTargetValidator(ProxyTargetPolicy? policy = null)
        => _policy = policy ?? new ProxyTargetPolicy();

    public ValidationResult ValidateDomain(string domain)
    {
        var d = (domain ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(d) || d.Length > 253)
            return ValidationResult.Fail("Domain is required and must be at most 253 characters.");
        if (Uri.CheckHostName(d) == UriHostNameType.Unknown)
            return ValidationResult.Fail("Domain is not a valid hostname.");
        return ValidationResult.Success();
    }

    /// <summary>
    /// Validate an upstream URL. Rejects non-http(s) schemes, missing hosts, and
    /// (by default) cloud-metadata / link-local addresses. Loopback and private
    /// ranges are allowed only when the policy opts in, since a reverse proxy to
    /// an internal upstream is legitimate but is also the classic SSRF pivot.
    /// </summary>
    public ValidationResult ValidateUpstream(string upstream)
    {
        var v = (upstream ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(v))
            return ValidationResult.Fail("Upstream target is required.");

        if (!Uri.TryCreate(v, UriKind.Absolute, out var uri))
            return ValidationResult.Fail("Enter an absolute URL, e.g. http://10.0.0.10:8080.");

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return ValidationResult.Fail("Only http:// and https:// upstreams are allowed.");

        if (string.IsNullOrEmpty(uri.Host))
            return ValidationResult.Fail("Upstream must include a host.");

        // Metadata endpoints are never a valid upstream.
        var host = uri.DnsSafeHost.ToLowerInvariant();
        if (host is "metadata.google.internal" or "metadata.goog")
            return ValidationResult.Fail("Cloud metadata hosts are not allowed as upstreams.");

        if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip))
        {
            var classified = Classify(ip);
            if (classified == IpClass.LinkLocalOrMetadata)
                return ValidationResult.Fail("Link-local / metadata addresses are not allowed as upstreams.");
            if (classified == IpClass.Loopback && !_policy.AllowLoopback)
                return ValidationResult.Fail("Loopback upstreams are not allowed by policy.");
            if (classified == IpClass.Private && !_policy.AllowPrivateNetworks)
                return ValidationResult.Fail("Private-network upstreams are not allowed by policy.");
        }

        return ValidationResult.Success();
    }

    private enum IpClass { Public, Private, Loopback, LinkLocalOrMetadata }

    private static IpClass Classify(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            else
            {
                if (IPAddress.IsLoopback(ip)) return IpClass.Loopback;
                if (ip.IsIPv6LinkLocal) return IpClass.LinkLocalOrMetadata;
                var b0 = ip.GetAddressBytes()[0];
                if ((b0 & 0xFE) == 0xFC) return IpClass.Private; // fc00::/7 ULA
                return IpClass.Public;
            }
        }

        var b = ip.GetAddressBytes();
        if (b[0] == 127) return IpClass.Loopback;
        if (b[0] == 169 && b[1] == 254) return IpClass.LinkLocalOrMetadata; // includes 169.254.169.254
        if (b[0] == 10) return IpClass.Private;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return IpClass.Private;
        if (b[0] == 192 && b[1] == 168) return IpClass.Private;
        return IpClass.Public;
    }
}

/// <summary>Deployment policy for what upstream ranges are permitted.</summary>
public sealed class ProxyTargetPolicy
{
    public bool AllowLoopback { get; set; } = true;
    public bool AllowPrivateNetworks { get; set; } = true;
}
