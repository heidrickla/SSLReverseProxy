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

    /// <summary>
    /// Where certificates come from: "acme" (public CA, the default) or
    /// "internal" (Caddy's local CA, for hosts no public CA can validate).
    /// Caddy is told not to install its root in the system trust store.
    /// </summary>
    public string CertificateIssuer { get; set; } = "acme";

    /// <summary>
    /// Caddy's listeners. Redirects and ACME validation still name 80 and 443,
    /// so non-default ports need those forwarded to them.
    /// </summary>
    public int HttpPort { get; set; } = 80;
    public int HttpsPort { get; set; } = 443;

    /// <summary>
    /// Cloudflare API token for DNS-01 challenges, needing Zone:Read and DNS:Edit on the zones.
    /// Caddy reads it from its environment; the config holds only a placeholder.
    /// </summary>
    public string? CloudflareApiToken { get; set; }

    /// <summary>DNS resolvers Caddy asks to see a DNS-01 record propagate, comma-separated host:port. Null uses the system's.</summary>
    public string? DnsChallengeResolvers { get; set; }

    /// <summary>Seconds between reads of the certificate Caddy serves for each name. 0 turns the monitor off.</summary>
    public int CertificateCheckSeconds { get; set; } = 300;

    /// <summary>
    /// Caddy's certificate maintenance interval, which also bounds how soon a forced renewal starts.
    /// Caddy fixes it when the proxy process starts, so it is written into every config.
    /// </summary>
    public int RenewCheckSeconds { get; set; } = 60;

    /// <summary>A forced renewal is refused for a certificate issued less than this long ago (ACME CAs rate-limit reissues).</summary>
    public int RenewMinimumAgeMinutes { get; set; } = 60;

    /// <summary>A forced renewal with no new serial after this long is recorded as failed.</summary>
    public int RenewTimeoutMinutes { get; set; } = 10;

    public bool AllowLoopbackUpstreams { get; set; } = true;
    public bool AllowPrivateUpstreams { get; set; } = true;

    /// <summary>
    /// CIDRs of L7 proxies/load balancers in front of this one, comma-separated.
    /// Only these sources are believed when they send X-Forwarded-For, and only
    /// then do the per-rule IP allow/deny lists see the real client address.
    /// Empty (the default, meaning this proxy faces clients directly) is the
    /// safe setting: an unset trust list means no forwarding header is honoured,
    /// so nobody can spoof their way past an allow-list.
    /// <para>
    /// Plain IPs and CIDRs only — unlike the matchers, this list rejects an
    /// IPv6 zone suffix ("fe80::1%eth0") outright and takes the proxy down
    /// with it.
    /// </para>
    /// </summary>
    public string? TrustedProxyCidrs { get; set; }

    /// <summary>
    /// Minimum TLS version Caddy will negotiate. Only "tls1.2" and "tls1.3"
    /// exist as far as Caddy is concerned — it looks the value up in a map and
    /// ignores a miss, so "tls1.1" would load cleanly and quietly do nothing.
    /// Anything unrecognised is therefore treated as tls1.2.
    /// </summary>
    public string TlsMinVersion { get; set; } = "tls1.2";

    /// <summary>
    /// TLS 1.2 cipher suites, comma-separated Go names (for example
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256). Null keeps Go's defaults, which
    /// are already sound — set this only to satisfy an external policy.
    /// <para>
    /// Two sharp edges. A name Caddy does not recognise fails the whole config
    /// load, taking every site down, not just this setting — run the /validate
    /// endpoint after changing it. And the list is ignored on TLS 1.3, whose
    /// suites the protocol fixes, so listing only 1.3 suite names leaves no
    /// usable 1.2 suite and every TLS 1.2 handshake fails.
    /// </para>
    /// </summary>
    public string? TlsCipherSuites { get; set; }

    // Data-plane timeouts, in seconds. 0 leaves Caddy's default in place.
    // Caddy ships no read/write timeout by default, so a client that opens a
    // connection and dribbles bytes can hold it open for as long as it likes.
    public int ReadHeaderTimeoutSeconds { get; set; } = 10;
    public int ReadTimeoutSeconds { get; set; }
    public int WriteTimeoutSeconds { get; set; }
    public int IdleTimeoutSeconds { get; set; } = 120;

    /// <summary>
    /// File the data-plane access log is written to, as JSON lines. Null
    /// disables access logging, which is the default: request logs contain
    /// client IPs and URLs, so turning them on is a decision with a retention
    /// obligation attached, not a default.
    /// </summary>
    public string? AccessLogPath { get; set; }

    /// <summary>Size at which the access log rolls, in megabytes.</summary>
    public int AccessLogRollSizeMb { get; set; } = 100;

    /// <summary>How long rolled access logs are kept, in days.</summary>
    public int AccessLogKeepDays { get; set; } = 14;

    /// <summary>
    /// Keeps each rule's recent requests in memory (the RecentRequests store): time, method, host,
    /// path without its query, status, duration, size and client IP, for 24 hours or 10,000 requests.
    /// Caddy's encoder drops headers, the query and the Basic Auth user before the line leaves Caddy.
    /// </summary>
    public bool RecentRequests { get; set; } = true;

    /// <summary>
    /// Seconds between background probes of every enabled rule's upstreams,
    /// which set each server's status. 0 turns the monitor off.
    /// </summary>
    public int ServerHealthIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// Seconds between samples of Caddy's traffic counters for the dashboard
    /// (25 hours are kept). 0 turns sampling off.
    /// </summary>
    public int TrafficSampleSeconds { get; set; } = 60;
}
