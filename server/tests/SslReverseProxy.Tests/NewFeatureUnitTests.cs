using System.Net.Http;
using System.Text.Json.Nodes;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Proxy;
using Xunit;

namespace SslReverseProxy.Tests;

public class MetricsParserTests
{
    [Fact]
    public void SumsFamiliesAcrossLabelSets()
    {
        var text = """
            # HELP caddy_http_requests_total Counter
            # TYPE caddy_http_requests_total counter
            caddy_http_requests_total{server="srv0",code="200"} 10
            caddy_http_requests_total{server="srv0",code="404"} 5
            caddy_http_requests_in_flight{server="srv0"} 2
            """;
        var series = MetricsParser.Parse(text);
        Assert.Equal(15, series["caddy_http_requests_total"]);
        Assert.Equal(2, series["caddy_http_requests_in_flight"]);
    }

    [Fact]
    public void IgnoresCommentsAndBlankLines() =>
        Assert.Empty(MetricsParser.Parse("# just a comment\n\n"));
}

public class CertificateStatusEvaluatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Valid_WhenFarFromExpiry()
    {
        var cert = new Certificate { Status = CertificateStatus.Valid, ExpiresAt = Now.AddDays(60) };
        var h = CertificateStatusEvaluator.Evaluate(cert, Now);
        Assert.Equal(CertificateStatus.Valid, h.Status);
        Assert.Equal(60, h.DaysRemaining);
    }

    [Fact]
    public void Expiring_WithinWindow()
    {
        var cert = new Certificate { Status = CertificateStatus.Valid, ExpiresAt = Now.AddDays(10) };
        Assert.Equal(CertificateStatus.Expiring, CertificateStatusEvaluator.Evaluate(cert, Now).Status);
    }

    [Fact]
    public void Expired_WhenPast()
    {
        var cert = new Certificate { Status = CertificateStatus.Valid, ExpiresAt = Now.AddDays(-1) };
        Assert.Equal(CertificateStatus.Expired, CertificateStatusEvaluator.Evaluate(cert, Now).Status);
    }
}

public class CaddyConfigBuilderTests
{
    private readonly ProxyOptions _opts = new();

    [Fact]
    public void EmitsReverseProxyDialWithSchemePort()
    {
        var rules = new[] { new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true } };
        var json = CaddyConfigBuilder.Build(rules, _opts).ToJsonString();
        Assert.Contains("\"reverse_proxy\"", json);
        Assert.Contains("10.0.0.5:80", json); // default http port derived
        Assert.Contains("127.0.0.1:2019", json); // admin pinned to loopback
    }

    [Fact]
    public void DeniedCidrs_ProduceForbiddenMatcher()
    {
        var rules = new[] { new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true, DeniedCidrs = "192.0.2.0/24" } };
        var json = CaddyConfigBuilder.Build(rules, _opts).ToJsonString();
        // client_ip, not remote_ip: see CaddyHardeningTests for why.
        Assert.Contains("client_ip", json);
        Assert.Contains("192.0.2.0/24", json);
        Assert.Contains("static_response", json);
    }

    [Fact]
    public void DisabledRules_AreExcluded()
    {
        var rules = new[] { new ProxyRule { Domain = "off.example.com", UpstreamUrl = "http://10.0.0.9", Enabled = false } };
        var json = CaddyConfigBuilder.Build(rules, _opts).ToJsonString();
        Assert.DoesNotContain("off.example.com", json);
    }

    [Fact]
    public void RateLimit_EmitsRateLimitHandler()
    {
        var rules = new[] { new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true, RateLimitPerMinute = 60 } };
        var json = CaddyConfigBuilder.Build(rules, _opts).ToJsonString();
        Assert.Contains("\"rate_limit\"", json);
        Assert.Contains("\"events\":60", json.Replace(" ", ""));
        // {http.request.remote_host} is not a real placeholder - it never
        // resolves, so every client would share one bucket and the per-IP
        // limit would silently be a global one.
        Assert.Contains("{http.vars.client_ip}", json);
        Assert.DoesNotContain("remote_host", json);
    }

    [Fact]
    public void BasicAuth_EmitsHttpBasicWithBcryptHash()
    {
        var hash = BCrypt.Net.BCrypt.HashPassword("s3cret");
        var rules = new[] { new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true, BasicAuthUsername = "ops", BasicAuthPasswordHash = hash } };
        var json = CaddyConfigBuilder.Build(rules, _opts).ToJsonString();
        Assert.Contains("http_basic", json);
        Assert.Contains("\"algorithm\":\"bcrypt\"", json.Replace(" ", ""));
        Assert.Contains(hash, json);
        Assert.DoesNotContain("s3cret", json); // plaintext never present
    }
}

/// <summary>
/// Covers the hardening settings emitted into the Caddy config. These assert on
/// exact JSON key names on purpose: Caddy ignores keys it does not recognise
/// rather than rejecting them, so a misspelled key is a setting that silently
/// does nothing instead of an error anyone would notice.
/// </summary>
public class CaddyHardeningTests
{
    private static ProxyRule Rule(Action<ProxyRule>? tweak = null)
    {
        var r = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true };
        tweak?.Invoke(r);
        return r;
    }

    private static JsonNode Build(ProxyRule rule, ProxyOptions? opts = null) =>
        CaddyConfigBuilder.Build([rule], opts ?? new ProxyOptions());

    private static JsonNode Srv(JsonNode cfg) => cfg["apps"]!["http"]!["servers"]!["srv0"]!;
    private static JsonArray Handlers(JsonNode cfg) => (JsonArray)Srv(cfg)["routes"]![0]!["handle"]!;

    private static JsonNode Handler(JsonNode cfg, string name) =>
        Handlers(cfg).First(h => (string?)h!["handler"] == name)!;

    // --- Trusted proxies + client IP -------------------------------------

    [Fact]
    public void AccessControl_MatchesOnClientIp_NotTheDirectPeer()
    {
        // remote_ip would match the load balancer's address, not the client's,
        // wherever this proxy sits behind another one.
        var json = Build(Rule(r => r.AllowedCidrs = "203.0.113.0/24")).ToJsonString();
        Assert.Contains("client_ip", json);
        Assert.DoesNotContain("remote_ip", json);
    }

    [Fact]
    public void TrustedProxies_EmittedAsStaticSource_WithStrictParsing()
    {
        var cfg = Build(Rule(), new ProxyOptions { TrustedProxyCidrs = "10.0.0.0/8, 192.0.2.1" });
        var tp = Srv(cfg)["trusted_proxies"]!;
        Assert.Equal("static", (string?)tp["source"]);
        Assert.Equal(["10.0.0.0/8", "192.0.2.1"], ((JsonArray)tp["ranges"]!).Select(n => (string?)n));
        // Non-strict parsing trusts the leftmost XFF entry, which the client writes.
        Assert.Equal(1, (int?)Srv(cfg)["trusted_proxies_strict"]);
    }

    [Fact]
    public void TrustedProxies_OmittedEntirely_WhenNotConfigured()
    {
        var srv = Srv(Build(Rule()));
        Assert.Null(srv["trusted_proxies"]);
        Assert.Null(srv["trusted_proxies_strict"]);
    }

    // --- Security headers -------------------------------------------------

    [Fact]
    public void SecurityHeaders_AreDeferred_AndPrecedeTheProxy()
    {
        var cfg = Build(Rule());
        var headers = Handler(cfg, "headers");
        Assert.True((bool?)headers["response"]!["deferred"]);

        var set = headers["response"]!["set"]!;
        Assert.Equal("nosniff", (string?)set["X-Content-Type-Options"]![0]);
        Assert.Equal("strict-origin-when-cross-origin", (string?)set["Referrer-Policy"]![0]);

        // Without deferral the upstream's own values are appended alongside
        // ours; after reverse_proxy the handler never runs at all.
        var names = Handlers(cfg).Select(h => (string?)h!["handler"]).ToList();
        Assert.True(names.IndexOf("headers") < names.IndexOf("reverse_proxy"));
    }

    [Fact]
    public void SecurityHeaders_AlsoCoverTheRoutesOwnErrorResponses()
    {
        // The 403 an ACL returns is a response a browser renders too. Placing
        // the headers handler after the access handlers would leave every
        // 403/429/413/401 bare, since those terminate the chain.
        var cfg = Build(Rule(r => { r.DeniedCidrs = "192.0.2.0/24"; r.MaxRequestBodyBytes = 1024; }));
        var names = Handlers(cfg).Select(h => (string?)h!["handler"]).ToList();
        Assert.Equal(0, names.IndexOf("headers"));
        Assert.True(names.IndexOf("headers") < names.IndexOf("subroute"));
        Assert.True(names.IndexOf("headers") < names.IndexOf("request_body"));
    }

    [Fact]
    public void SecurityHeaders_CanBeTurnedOff()
    {
        var cfg = Build(Rule(r => r.EnableSecurityHeaders = false));
        Assert.DoesNotContain(Handlers(cfg), h => (string?)h!["handler"] == "headers");
    }

    [Fact]
    public void Hsts_IsSingleHeaderValue_NotTwoArrayEntries()
    {
        // Caddy comma-joins a multi-element array, which would produce
        // "max-age=...,includeSubDomains" — malformed, and silently so.
        var cfg = Build(Rule(r => { r.HstsMaxAgeDays = 365; r.EnableTls = true; r.HstsIncludeSubdomains = true; }));
        var hsts = (JsonArray)Handler(cfg, "headers")["response"]!["set"]!["Strict-Transport-Security"]!;
        Assert.Single(hsts);
        Assert.Equal("max-age=31536000; includeSubDomains", (string?)hsts[0]);
    }

    [Fact]
    public void Hsts_OmitsIncludeSubDomains_ByDefault()
    {
        // On an apex domain includeSubDomains pins every sibling host to HTTPS
        // for the whole max-age, including hosts this rule does not serve, and
        // nothing sent later can undo it. It has to be asked for.
        var cfg = Build(Rule(r => { r.HstsMaxAgeDays = 365; r.EnableTls = true; }));
        var hsts = (JsonArray)Handler(cfg, "headers")["response"]!["set"]!["Strict-Transport-Security"]!;
        Assert.Equal("max-age=31536000", (string?)hsts[0]);
    }

    [Fact]
    public void Hsts_IsSuppressed_OnAPlaintextRoute()
    {
        var cfg = Build(Rule(r => { r.HstsMaxAgeDays = 365; r.EnableTls = false; }));
        Assert.Null(Handler(cfg, "headers")["response"]!["set"]!["Strict-Transport-Security"]);
    }

    [Fact]
    public void FrameOptions_EmittedOnlyWhenSet()
    {
        Assert.Null(Handler(Build(Rule()), "headers")["response"]!["set"]!["X-Frame-Options"]);
        var cfg = Build(Rule(r => r.FrameOptions = "sameorigin"));
        Assert.Equal("SAMEORIGIN", (string?)Handler(cfg, "headers")["response"]!["set"]!["X-Frame-Options"]![0]);
    }

    // --- Timeouts ---------------------------------------------------------

    [Fact]
    public void ServerTimeouts_UseDurationStrings()
    {
        var cfg = Build(Rule(), new ProxyOptions
        {
            ReadTimeoutSeconds = 30,
            ReadHeaderTimeoutSeconds = 10,
            WriteTimeoutSeconds = 30,
            IdleTimeoutSeconds = 120,
        });
        var srv = Srv(cfg);
        // A bare integer would be read as nanoseconds: 30 means 30ns, not 30s.
        Assert.Equal("30s", (string?)srv["read_timeout"]);
        Assert.Equal("10s", (string?)srv["read_header_timeout"]);
        Assert.Equal("30s", (string?)srv["write_timeout"]);
        Assert.Equal("120s", (string?)srv["idle_timeout"]);
    }

    [Fact]
    public void ServerTimeouts_OmittedWhenZero()
    {
        var srv = Srv(Build(Rule(), new ProxyOptions
        {
            ReadTimeoutSeconds = 0,
            ReadHeaderTimeoutSeconds = 0,
            WriteTimeoutSeconds = 0,
            IdleTimeoutSeconds = 0,
        }));
        Assert.Null(srv["read_timeout"]);
        Assert.Null(srv["idle_timeout"]);
    }

    [Fact]
    public void UpstreamTimeouts_LiveOnTheTransport_WithTheProtocolDiscriminator()
    {
        var cfg = Build(Rule(r =>
        {
            r.DialTimeoutSeconds = 5;
            r.UpstreamReadTimeoutSeconds = 60;
            r.UpstreamWriteTimeoutSeconds = 60;
        }));
        var transport = Handler(cfg, "reverse_proxy")["transport"]!;
        Assert.Equal("http", (string?)transport["protocol"]);
        Assert.Equal("5s", (string?)transport["dial_timeout"]);
        Assert.Equal("60s", (string?)transport["read_timeout"]);
        Assert.Equal("60s", (string?)transport["write_timeout"]);
    }

    // --- HTTPS upstreams --------------------------------------------------

    [Fact]
    public void HttpsUpstream_GetsATlsTransport()
    {
        // "dial" carries no scheme, so without transport.tls Caddy speaks
        // cleartext at port 443.
        var cfg = Build(Rule(r => r.UpstreamUrl = "https://backend.example.com"));
        var proxy = Handler(cfg, "reverse_proxy");
        Assert.Equal("backend.example.com:443", (string?)proxy["upstreams"]![0]!["dial"]);
        Assert.NotNull(proxy["transport"]!["tls"]);
    }

    [Fact]
    public void HttpUpstream_GetsNoTlsTransport()
    {
        var proxy = Handler(Build(Rule()), "reverse_proxy");
        Assert.Null(proxy["transport"]?["tls"]);
    }

    [Fact]
    public void HttpsUpstream_KeepsTls_WhenTimeoutsAlsoSet()
    {
        // transport is replaced wholesale, so adding a timeout must not drop tls.
        var cfg = Build(Rule(r =>
        {
            r.UpstreamUrl = "https://backend.example.com";
            r.DialTimeoutSeconds = 5;
        }));
        var transport = Handler(cfg, "reverse_proxy")["transport"]!;
        Assert.NotNull(transport["tls"]);
        Assert.Equal("5s", (string?)transport["dial_timeout"]);
    }

    // --- Request body cap --------------------------------------------------

    [Fact]
    public void MaxRequestBody_EmitsByteCount_BeforeTheProxy()
    {
        var cfg = Build(Rule(r => r.MaxRequestBodyBytes = 10 * 1024 * 1024));
        // max_size is int64 bytes; "10MB" is Caddyfile sugar and fails to parse.
        Assert.Equal(10485760, (long?)Handler(cfg, "request_body")["max_size"]);

        var names = Handlers(cfg).Select(h => (string?)h!["handler"]).ToList();
        Assert.True(names.IndexOf("request_body") < names.IndexOf("reverse_proxy"));
    }

    // --- TLS connection policy ---------------------------------------------

    [Fact]
    public void TlsPolicy_IsACatchAll_SoCertificateSelectionStillWorks()
    {
        var policies = (JsonArray)Srv(Build(Rule(r => r.EnableTls = true)))["tls_connection_policies"]!;
        var policy = policies.Single()!;
        // A policy carrying a "match" that nothing matches kills the handshake
        // before any certificate is chosen.
        Assert.Null(policy["match"]);
        Assert.Equal("tls1.2", (string?)policy["protocol_min"]);
    }

    [Theory]
    [InlineData("tls1.3", "tls1.3")]
    [InlineData("tls1.2", "tls1.2")]
    [InlineData("tls1.0", "tls1.2")]  // Caddy would ignore this outright
    [InlineData("TLS1.2", "tls1.2")]  // and the lookup is case-sensitive
    [InlineData("nonsense", "tls1.2")]
    public void TlsMinVersion_FallsBackToASupportedValue(string configured, string expected)
    {
        var policy = ((JsonArray)Srv(Build(Rule(r => r.EnableTls = true),
            new ProxyOptions { TlsMinVersion = configured }))["tls_connection_policies"]!).Single()!;
        Assert.Equal(expected, (string?)policy["protocol_min"]);
    }

    [Fact]
    public void CipherSuites_EmittedOnlyWhenConfigured()
    {
        var plain = ((JsonArray)Srv(Build(Rule(r => r.EnableTls = true)))["tls_connection_policies"]!).Single()!;
        Assert.Null(plain["cipher_suites"]);

        var cfg = Build(Rule(r => r.EnableTls = true), new ProxyOptions
        {
            TlsCipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        });
        var suites = (JsonArray)((JsonArray)Srv(cfg)["tls_connection_policies"]!).Single()!["cipher_suites"]!;
        Assert.Equal(2, suites.Count);
    }

    // --- Health checks -----------------------------------------------------

    [Fact]
    public void HealthCheck_UsesUriNotTheDeprecatedPath()
    {
        var cfg = Build(Rule(r =>
        {
            r.HealthCheckPath = "/healthz";
            r.HealthCheckIntervalSeconds = 30;
            r.HealthCheckTimeoutSeconds = 5;
        }));
        var active = Handler(cfg, "reverse_proxy")["health_checks"]!["active"]!;
        Assert.Equal("/healthz", (string?)active["uri"]);
        Assert.Null(active["path"]);
        Assert.Equal("30s", (string?)active["interval"]);
        Assert.Equal("5s", (string?)active["timeout"]);
        // Left unset so Caddy's own 200-399 applies. Defaulting to 2 would mean
        // "2xx only", which is stricter than Caddy's default and would mark a
        // backend that redirects its health endpoint as down.
        Assert.Null(active["expect_status"]);
    }

    [Fact]
    public void HealthCheck_EmitsExpectStatus_WhenAskedFor()
    {
        var cfg = Build(Rule(r => { r.HealthCheckPath = "/healthz"; r.HealthCheckExpectStatus = 2; }));
        Assert.Equal(2, (int?)Handler(cfg, "reverse_proxy")["health_checks"]!["active"]!["expect_status"]);
    }

    [Fact]
    public void HealthCheck_OmittedWithoutAUri_BecauseItWouldBeANoOp()
    {
        var cfg = Build(Rule(r => r.HealthCheckIntervalSeconds = 30));
        Assert.Null(Handler(cfg, "reverse_proxy")["health_checks"]);
    }

    // --- Load balancing ----------------------------------------------------

    [Fact]
    public void MultipleUpstreams_GetASelectionPolicy()
    {
        var cfg = Build(Rule(r =>
        {
            r.AdditionalUpstreams = "http://10.0.0.6,http://10.0.0.7:8080";
            r.LoadBalancePolicy = "least_conn";
        }));
        var proxy = Handler(cfg, "reverse_proxy");
        Assert.Equal(["10.0.0.5:80", "10.0.0.6:80", "10.0.0.7:8080"],
            ((JsonArray)proxy["upstreams"]!).Select(u => (string?)u!["dial"]));
        Assert.Equal("least_conn", (string?)proxy["load_balancing"]!["selection_policy"]!["policy"]);
    }

    [Fact]
    public void SingleUpstream_GetsNoBalancing()
    {
        Assert.Null(Handler(Build(Rule()), "reverse_proxy")["load_balancing"]);
    }

    [Fact]
    public void DuplicateUpstreams_AreCollapsed()
    {
        var rule = Rule(r => r.AdditionalUpstreams = "http://10.0.0.5,http://10.0.0.6");
        Assert.Equal(["http://10.0.0.5", "http://10.0.0.6"], rule.AllUpstreams());
    }

    [Fact]
    public void UpstreamsSpelledDifferently_ResolveToOneBackend()
    {
        // Same host, same port, three spellings. Listing it three times would
        // give it three shares of the traffic and turn a single backend into a
        // "load balanced" pool of itself.
        var cfg = Build(Rule(r => r.AdditionalUpstreams = "http://10.0.0.5:80,http://10.0.0.5/"));
        var proxy = Handler(cfg, "reverse_proxy");
        Assert.Equal(["10.0.0.5:80"], ((JsonArray)proxy["upstreams"]!).Select(u => (string?)u!["dial"]));
        Assert.Null(proxy["load_balancing"]);
    }

    // --- Access logging ----------------------------------------------------

    [Fact]
    public void AccessLog_RoutesByLoggerName_AndKeepsItOffStderr()
    {
        var cfg = Build(Rule(), new ProxyOptions { AccessLogPath = "/var/log/caddy/access.log" });

        Assert.Equal("access", (string?)Srv(cfg)["logs"]!["default_logger_name"]);

        var logs = cfg["logging"]!["logs"]!;
        // Routing is by logger name, not by the map key, and the name is
        // "http.log.access." + default_logger_name.
        Assert.Equal("http.log.access.access", (string?)logs["access"]!["include"]![0]);
        Assert.Equal("file", (string?)logs["access"]!["writer"]!["output"]);
        Assert.Equal("/var/log/caddy/access.log", (string?)logs["access"]!["writer"]!["filename"]);
        // Without the exclude, every request is logged twice.
        Assert.Equal("http.log.access.access", (string?)logs["default"]!["exclude"]![0]);
    }

    [Fact]
    public void AccessLog_AbsentWhenNoPathConfigured()
    {
        var cfg = Build(Rule());
        Assert.Null(cfg["logging"]);
        Assert.Null(Srv(cfg)["logs"]);
    }

    [Fact]
    public void AccessLog_SkipsOptedOutHosts()
    {
        var cfg = Build(Rule(r => r.SkipAccessLog = true), new ProxyOptions { AccessLogPath = "/tmp/a.log" });
        Assert.Equal("a.example.com", (string?)Srv(cfg)["logs"]!["skip_hosts"]![0]);
    }

    // --- Automatic HTTPS ---------------------------------------------------

    [Fact]
    public void TlsPolicy_OmittedWhenNothingIsServedOverTls()
    {
        // A connection policy is what makes :443 a TLS listener, so emitting one
        // for an all-plaintext config stands up a TLS port with nothing behind it.
        Assert.Null(Srv(Build(Rule(r => r.EnableTls = false)))["tls_connection_policies"]);
        Assert.Null(Srv(CaddyConfigBuilder.Build([], new ProxyOptions()))["tls_connection_policies"]);
    }

    [Fact]
    public void MalformedTrustedProxyEntries_AreDroppedNotEmitted()
    {
        // Caddy refuses to start on a malformed range, and this same config is
        // written at startup - so emitting one would mean the proxy never comes
        // up. Dropping fails closed: an untrusted proxy just gets its
        // X-Forwarded-For ignored.
        var cfg = Build(Rule(), new ProxyOptions
        {
            TrustedProxyCidrs = "10.0.0.0/8, 10.0.0.0/33, fe80::1%eth0, not-an-ip, 192.0.2.1",
        });
        Assert.Equal(["10.0.0.0/8", "192.0.2.1"],
            ((JsonArray)Srv(cfg)["trusted_proxies"]!["ranges"]!).Select(n => (string?)n));
    }

    [Fact]
    public void TlsDisabledRule_IsSkippedByAutomaticHttps()
    {
        // Otherwise Caddy issues a certificate and redirects :80 to :443 for a
        // host the operator explicitly marked as plaintext.
        var cfg = Build(Rule(r => r.EnableTls = false));
        Assert.Equal("a.example.com", (string?)Srv(cfg)["automatic_https"]!["skip"]![0]);
    }

    [Fact]
    public void TlsEnabledRule_LeavesAutomaticHttpsAlone()
    {
        Assert.Null(Srv(Build(Rule()))["automatic_https"]);
    }
}

public class BasicAuthHashingTests
{
    [Fact]
    public void Bcrypt_HashVerifies_AndIsNotPlaintext()
    {
        var hash = BCrypt.Net.BCrypt.HashPassword("correct horse");
        Assert.NotEqual("correct horse", hash);
        Assert.True(BCrypt.Net.BCrypt.Verify("correct horse", hash));
        Assert.False(BCrypt.Net.BCrypt.Verify("wrong", hash));
    }
}

public class UpstreamHealthCheckerTests
{
    // A factory that fails the test if any HTTP client is ever requested.
    private sealed class ThrowingHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            throw new Xunit.Sdk.XunitException("HTTP client must not be created for a blocked SSRF target.");
    }

    [Fact]
    public async Task MetadataTarget_IsRefused_WithoutAnyRequest()
    {
        var checker = new UpstreamHealthChecker(new ThrowingHttpClientFactory(), new ProxyTargetValidator());
        var result = await checker.CheckAsync("http://169.254.169.254/latest/meta-data/");
        Assert.False(result.Reachable);
        Assert.NotNull(result.Error);
    }
}
