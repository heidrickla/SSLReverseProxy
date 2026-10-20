using System.Text.RegularExpressions;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Whether <see cref="ProxyOptions.CloudflareApiToken"/> can be handed to Caddy. caddy-dns/cloudflare
/// v0.2.4 refuses any other shape in Provision and echoes the value in its error, so a malformed
/// token is never referenced from a config.
/// </summary>
public static partial class CloudflareToken
{
    [GeneratedRegex("^[A-Za-z0-9_-]{35,50}$")]
    private static partial Regex Legacy();

    [GeneratedRegex("^cf(ut|at)_[A-Za-z0-9_-]{32,256}$")]
    private static partial Regex Scoped();

    public static string? Problem(ProxyOptions options)
    {
        var token = options.CloudflareApiToken?.Trim();
        if (string.IsNullOrEmpty(token)) return "Proxy:CloudflareApiToken is not set.";
        return Legacy().IsMatch(token) || Scoped().IsMatch(token)
            ? null
            : "Proxy:CloudflareApiToken is not in a format Cloudflare issues.";
    }

    public static bool Usable(ProxyOptions options) => Problem(options) is null;
}
