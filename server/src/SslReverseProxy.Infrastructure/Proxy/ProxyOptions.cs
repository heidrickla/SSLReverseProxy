namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// Configuration for the external proxy the control service manages. All values
/// come from configuration (appsettings / user-secrets / environment), never
/// from source. The admin endpoint MUST stay bound to loopback.
/// </summary>
public sealed class ProxyOptions
{
    public const string SectionName = "Proxy";

    /// <summary>Path to the Caddy executable. If missing/not found, the proxy reports Unavailable.</summary>
    public string CaddyPath { get; set; } = "caddy";

    /// <summary>Caddy admin API base — must be a loopback address.</summary>
    public string AdminEndpoint { get; set; } = "http://127.0.0.1:2019";

    /// <summary>Directory where generated proxy config is written.</summary>
    public string ConfigDirectory { get; set; } = "proxy-config";

    /// <summary>Email used for ACME registration (Caddy's automatic HTTPS).</summary>
    public string? AcmeContactEmail { get; set; }

    /// <summary>When true, Caddy uses the ACME staging endpoint (for testing).</summary>
    public bool UseAcmeStaging { get; set; }

    public bool AllowLoopbackUpstreams { get; set; } = true;
    public bool AllowPrivateUpstreams { get; set; } = true;
}
