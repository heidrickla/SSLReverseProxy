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
    /// <summary>A host name's addresses, or null when it does not resolve.</summary>
    public delegate IReadOnlyList<IPAddress>? HostResolver(string host);

    public static readonly TimeSpan ResolveTimeout = TimeSpan.FromSeconds(3);

    private readonly ProxyTargetPolicy _policy;
    private readonly HostResolver _resolve;

    public ProxyTargetValidator(ProxyTargetPolicy? policy = null, HostResolver? resolve = null)
    {
        _policy = policy ?? new ProxyTargetPolicy();
        _resolve = resolve ?? SystemResolve;
    }

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
    /// A host name is resolved and every address it resolves to is classified;
    /// a name that does not resolve now is checked again wherever this service dials it.
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
        var host = uri.DnsSafeHost.TrimEnd('.').ToLowerInvariant();
        if (host is "metadata.google.internal" or "metadata.goog")
            return ValidationResult.Fail("Cloud metadata hosts are not allowed as upstreams.");

        if (IPAddress.TryParse(host, out var ip))
            return CheckAddress(ip);

        // RFC 6761: localhost and every name under it are loopback, whatever a resolver answers.
        if (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal))
            return CheckClass(IpClass.Loopback);

        var addresses = _resolve(host);
        if (addresses is null) return ValidationResult.Success();
        foreach (var address in addresses)
        {
            var check = CheckAddress(address);
            if (!check.Ok) return ValidationResult.Fail($"{host} resolves to {address}. {check.Reason}");
        }
        return ValidationResult.Success();
    }

    /// <summary>The policy for one address, as dialled.</summary>
    public ValidationResult CheckAddress(IPAddress address) => CheckClass(Classify(address));

    private ValidationResult CheckClass(IpClass classified) => classified switch
    {
        IpClass.LinkLocalOrMetadata => ValidationResult.Fail("Link-local / metadata addresses are not allowed as upstreams."),
        IpClass.Loopback when !_policy.AllowLoopback => ValidationResult.Fail("Loopback upstreams are not allowed by policy."),
        IpClass.Private when !_policy.AllowPrivateNetworks => ValidationResult.Fail("Private-network upstreams are not allowed by policy."),
        _ => ValidationResult.Success(),
    };

    private static IReadOnlyList<IPAddress>? SystemResolve(string host)
    {
        try
        {
            using var cts = new CancellationTokenSource(ResolveTimeout);
            return Dns.GetHostAddressesAsync(host, cts.Token).GetAwaiter().GetResult();
        }
        catch (SocketException) { return null; }
        catch (OperationCanceledException) { return null; }
        catch (ArgumentException) { return null; }
    }

    private enum IpClass { Public, Private, Loopback, LinkLocalOrMetadata }

    // AWS's IPv6 instance metadata endpoint.
    private static readonly IPAddress AwsMetadataV6 = IPAddress.Parse("fd00:ec2::254");

    private static IpClass Classify(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            else
            {
                // A connect to :: reaches the local host.
                if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6Any)) return IpClass.Loopback;
                if (ip.IsIPv6LinkLocal) return IpClass.LinkLocalOrMetadata;
                if (new IPAddress(ip.GetAddressBytes()).Equals(AwsMetadataV6)) return IpClass.LinkLocalOrMetadata;
                var b0 = ip.GetAddressBytes()[0];
                if ((b0 & 0xFE) == 0xFC) return IpClass.Private; // fc00::/7 ULA
                return IpClass.Public;
            }
        }

        var b = ip.GetAddressBytes();
        if (b[0] == 127) return IpClass.Loopback;
        if (b[0] == 0) return IpClass.Loopback; // 0.0.0.0/8: a connect to 0.0.0.0 reaches the local host
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
