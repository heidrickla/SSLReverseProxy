using System.Diagnostics;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// The environment Caddy runs with. Caddy resolves <c>{env.*}</c> placeholders, so it gets
/// only what it needs to run, find its data directory and reach an ACME CA, plus the
/// Cloudflare token its DNS provider reads, never the API's own settings and secrets.
/// </summary>
public static class CaddyEnvironment
{
    public const string CloudflareTokenVariable = "SSLRP_CLOUDFLARE_API_TOKEN";

    private static readonly string[] Inherited =
    [
        // Process start and the Windows runtime.
        "PATH", "PATHEXT", "SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP", "TMPDIR",
        // Caddy's data and config directories (caddy.AppDataDir, AppConfigDir).
        "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
        // Outbound proxies and trust stores for ACME and DNS API calls.
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR",
        "TZ", "GOMEMLIMIT", "GOGC",
    ];

    /// <summary>Every Caddy process the control plane starts is built here.</summary>
    public static ProcessStartInfo StartInfo(ProxyOptions options, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = options.CaddyPath,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        Apply(psi, options);
        return psi;
    }

    public static void Apply(ProcessStartInfo psi, ProxyOptions options)
    {
        psi.Environment.Clear();
        foreach (var name in Inherited)
        {
            // GetEnvironmentVariable ignores case on Windows, where PATH is stored as "Path".
            if (Environment.GetEnvironmentVariable(name) is { } value && !psi.Environment.ContainsKey(name))
                psi.Environment[name] = value;
        }
        if (!string.IsNullOrWhiteSpace(options.CloudflareApiToken))
            psi.Environment[CloudflareTokenVariable] = options.CloudflareApiToken.Trim();
    }
}
