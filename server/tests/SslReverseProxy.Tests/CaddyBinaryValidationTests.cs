using System.Diagnostics;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Proxy;
using Xunit;
using Xunit.Abstractions;

namespace SslReverseProxy.Tests;

/// <summary>
/// Runs the generated configs through a real <c>caddy validate</c>.
/// <para>
/// The other tests assert on key names, which catches a typo but cannot catch a
/// key that is spelled correctly and does not belong where we put it. Caddy
/// decodes module configs with DisallowUnknownFields, so it rejects both — but
/// only an actual binary can tell us that.
/// </para>
/// <para>
/// Point <c>SSLRP_TEST_CADDY</c> at a caddy binary, or put one on PATH. With
/// neither, these no-op so the suite runs on a box without Caddy. CI sets
/// <c>SSLRP_REQUIRE_CADDY=1</c>, which turns a missing binary, or one without
/// the caddy-ratelimit plugin, into a failure.
/// <see cref="Validation_IsActuallyRunning"/> guards against a matrix that
/// passes vacuously.
/// </para>
/// </summary>
public class CaddyBinaryValidationTests
{
    private readonly ITestOutputHelper _out;
    public CaddyBinaryValidationTests(ITestOutputHelper output) => _out = output;

    /// <summary>
    /// A real PEM on disk. Caddy reads the CA pool at provision time, not just
    /// at request time, so a made-up path fails validation for a reason that
    /// has nothing to do with the config being right.
    /// </summary>
    private static readonly Lazy<string> TrustedCaPem = new(() =>
    {
        var path = Path.Combine(Path.GetTempPath(), "sslrp-test-ca.pem");
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=sslrp-test-ca", rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllText(path, cert.ExportCertificatePem());
        return path;
    });

    private static ProxyRule R(string domain, string upstream, Action<ProxyRule>? t = null)
    {
        var r = new ProxyRule { Domain = domain, UpstreamUrl = upstream, Enabled = true };
        t?.Invoke(r);
        return r;
    }

    public static TheoryData<string> CaseNames()
    {
        var data = new TheoryData<string>();
        foreach (var k in Cases.Keys) data.Add(k);
        return data;
    }

    // caddy validate opens the log file, so the path must be one the test user can create.
    private static readonly string AccessLog = Path.Combine(Path.GetTempPath(), "sslrp-validate", "access.log");

    private static readonly Dictionary<string, (ProxyRule[] Rules, ProxyOptions Options)> Cases = new()
    {
        ["minimal"] = ([R("a.example.com", "http://10.0.0.5")], new ProxyOptions()),

        ["https-upstream"] = ([R("a.example.com", "https://backend.example.com")], new ProxyOptions()),

        ["https-upstream-with-timeouts"] = ([R("a.example.com", "https://backend.example.com", r =>
        {
            r.DialTimeoutSeconds = 5;
            r.UpstreamReadTimeoutSeconds = 60;
            r.UpstreamWriteTimeoutSeconds = 60;
        })], new ProxyOptions()),

        ["acls-and-trusted-proxies"] = ([R("a.example.com", "http://10.0.0.5", r =>
        {
            r.AllowedCidrs = "203.0.113.0/24,198.51.100.7";
            r.DeniedCidrs = "192.0.2.0/24";
        })], new ProxyOptions { TrustedProxyCidrs = "10.0.0.0/8,172.16.0.0/12" }),

        ["security-headers"] = ([R("a.example.com", "http://10.0.0.5", r =>
        {
            r.HstsMaxAgeDays = 365;
            r.FrameOptions = "DENY";
        })], new ProxyOptions()),

        ["body-limit-and-basic-auth"] = ([R("a.example.com", "http://10.0.0.5", r =>
        {
            r.MaxRequestBodyBytes = 10 * 1024 * 1024;
            r.BasicAuthUsername = "ops";
            r.BasicAuthPasswordHash = BCrypt.Net.BCrypt.HashPassword("s3cret");
        })], new ProxyOptions()),

        ["load-balancing-and-health-checks"] = ([R("a.example.com", "http://10.0.0.5", r =>
        {
            r.AdditionalUpstreams = "http://10.0.0.6,http://10.0.0.7:8080";
            r.LoadBalancePolicy = "least_conn";
            r.HealthCheckPath = "/healthz";
            r.HealthCheckIntervalSeconds = 30;
            r.HealthCheckTimeoutSeconds = 5;
            r.HealthCheckExpectStatus = 2;
        })], new ProxyOptions()),

        ["access-logging"] = ([
            R("a.example.com", "http://10.0.0.5"),
            R("quiet.example.com", "http://10.0.0.6", r => r.SkipAccessLog = true),
        ], new ProxyOptions { AccessLogPath = AccessLog }),

        ["server-timeouts-and-tls13"] = ([R("a.example.com", "http://10.0.0.5")], new ProxyOptions
        {
            ReadTimeoutSeconds = 30,
            ReadHeaderTimeoutSeconds = 10,
            WriteTimeoutSeconds = 30,
            IdleTimeoutSeconds = 120,
            TlsMinVersion = "tls1.3",
        }),

        ["cipher-suites"] = ([R("a.example.com", "http://10.0.0.5")], new ProxyOptions
        {
            TlsCipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        }),

        ["upstream-tls-options"] = ([R("a.example.com", "https://10.0.0.5:8443", r =>
        {
            r.UpstreamTlsServerName = "backend.internal";
            r.UpstreamTlsTrustedCaFile = TrustedCaPem.Value;
        })], new ProxyOptions()),

        ["upstream-tls-skip-verify"] = ([R("a.example.com", "https://10.0.0.5:8443",
            r => r.UpstreamTlsInsecureSkipVerify = true)], new ProxyOptions()),

        ["plaintext-host"] = ([R("plain.example.com", "http://10.0.0.5", r => r.EnableTls = false)],
            new ProxyOptions()),

        ["acme"] = ([R("a.example.com", "http://10.0.0.5")],
            new ProxyOptions { AcmeContactEmail = "ops@example.com", UseAcmeStaging = true }),

        ["internal-issuer-and-custom-ports"] = ([
            R("a.example.com", "http://10.0.0.5"),
            R("plain.example.com", "http://10.0.0.6", r => r.EnableTls = false),
        ], new ProxyOptions { CertificateIssuer = "internal", HttpPort = 8080, HttpsPort = 8443 }),

        // Needs the caddy-ratelimit plugin, which the image and CI build include.
        ["rate-limit"] = ([R("a.example.com", "http://10.0.0.5", r => r.RateLimitPerMinute = 120)],
            new ProxyOptions()),

        ["path-routes"] = ([
            R("a.example.com", "http://10.0.0.5", r => r.RateLimitPerMinute = 600),
            R("a.example.com", "http://10.0.0.6", r => { r.PathPrefix = "/api"; r.StripPathPrefix = true; r.RateLimitPerMinute = 60; }),
            R("a.example.com", "http://10.0.0.7", r => r.PathPrefix = "/api/v2"),
            R("plain.example.com", "http://10.0.0.8", r => { r.EnableTls = false; r.PathPrefix = "/x"; }),
        ], new ProxyOptions()),

        ["everything-at-once"] = ([
            R("a.example.com", "https://backend.example.com", r =>
            {
                r.AllowedCidrs = "203.0.113.0/24";
                r.DeniedCidrs = "192.0.2.0/24";
                r.MaxRequestBodyBytes = 5_242_880;
                r.BasicAuthUsername = "ops";
                r.BasicAuthPasswordHash = BCrypt.Net.BCrypt.HashPassword("s3cret");
                r.HstsMaxAgeDays = 180;
                r.FrameOptions = "SAMEORIGIN";
                r.DialTimeoutSeconds = 5;
                r.UpstreamReadTimeoutSeconds = 60;
                r.UpstreamWriteTimeoutSeconds = 60;
                r.AdditionalUpstreams = "https://backend2.example.com";
                r.LoadBalancePolicy = "round_robin";
                r.HealthCheckPath = "/healthz";
                r.HealthCheckIntervalSeconds = 30;
                r.HealthCheckTimeoutSeconds = 5;
                r.RateLimitPerMinute = 600;
            }),
            R("plain.example.com", "http://10.0.0.9", r => { r.EnableTls = false; r.SkipAccessLog = true; }),
        ], new ProxyOptions
        {
            TrustedProxyCidrs = "10.0.0.0/8",
            AccessLogPath = AccessLog,
            ReadHeaderTimeoutSeconds = 10,
            IdleTimeoutSeconds = 120,
            AcmeContactEmail = "ops@example.com",
        }),

        ["sign-in"] = ([
            SignInBuilderTests.Rule(SignInProviders.Authelia, r => { r.EnableTls = true; r.SignInVerifierUrl = "https://authelia.internal:9091"; }),
            SignInBuilderTests.Rule(SignInProviders.Authentik, r => r.PathPrefix = "/app", "b.example.com"),
            SignInBuilderTests.Rule(SignInProviders.OAuth2Proxy, domain: "c.example.com"),
            SignInBuilderTests.Rule(SignInProviders.OAuth2Proxy, r => r.PathPrefix = "/api", "c.example.com"),
            SignInBuilderTests.Rule(SignInProviders.CloudflareAccess, domain: "d.example.com"),
        ], new ProxyOptions()),
    };

    private const string AuthentikHeaders =
        "X-Authentik-Username X-Authentik-Groups X-Authentik-Entitlements X-Authentik-Email X-Authentik-Name X-Authentik-Uid " +
        "X-Authentik-Jwt X-Authentik-Meta-Jwks X-Authentik-Meta-Outpost X-Authentik-Meta-Provider X-Authentik-Meta-App X-Authentik-Meta-Version";

    // Each provider's Caddy example, with its copy_headers in the provider's own order.
    private static readonly Dictionary<string, string> ForwardAuthCaddyfiles = new()
    {
        [SignInProviders.Authelia] = """
            forward_auth idp.internal:9091 {
                uri /api/authz/forward-auth
                copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
            }
            """,
        [SignInProviders.Authentik] = """
            route {
                reverse_proxy /outpost.goauthentik.io/* http://idp.internal:9091
                forward_auth http://idp.internal:9091 {
                    uri /outpost.goauthentik.io/auth/caddy
                    copy_headers HEADERS
                }
            }
            """.Replace("HEADERS", AuthentikHeaders, StringComparison.Ordinal),
        [SignInProviders.OAuth2Proxy] = """
            handle /oauth2/* {
                reverse_proxy idp.internal:9091 {
                    header_up X-Real-IP {remote_host}
                    header_up X-Forwarded-Uri {uri}
                }
            }
            handle {
                forward_auth idp.internal:9091 {
                    uri /oauth2/auth
                    copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Groups X-Auth-Request-Preferred-Username
                    @error status 401
                    handle_response @error {
                        redir * /oauth2/sign_in?rd={scheme}://{host}{uri}
                    }
                }
            }
            """,
    };

    /// <summary>
    /// The builder writes forward_auth's expansion out by hand. Caddy's own adapter expands each provider's
    /// example, and the verify call and the callback proxy must come out the same.
    /// </summary>
    [Theory]
    [InlineData(SignInProviders.Authelia)]
    [InlineData(SignInProviders.Authentik)]
    [InlineData(SignInProviders.OAuth2Proxy)]
    public void ForwardAuth_IsWhatCaddyExpandsItTo(string provider)
    {
        if (Caddy() is not { } caddy) return;

        var caddyfile = "{\n\tadmin off\n\tauto_https off\n}\nhttp://a.example.com {\n" + ForwardAuthCaddyfiles[provider] + "\n}\n";
        var path = Path.Combine(Path.GetTempPath(), $"sslrp-adapt-{Guid.NewGuid():N}.caddyfile");
        File.WriteAllText(path, caddyfile);
        System.Text.Json.Nodes.JsonNode adapted;
        try
        {
            var (exit, stdout, stderr) = RunSplit(caddy, "adapt", "--config", path, "--adapter", "caddyfile");
            Assert.True(exit == 0, stderr);
            adapted = System.Text.Json.Nodes.JsonNode.Parse(stdout)!;
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }

        var proxies = Descendants(adapted).Where(o => (string?)o["handler"] == "reverse_proxy").ToList();
        var rule = SignInBuilderTests.Rule(provider);
        var built = CaddyConfigBuilder.Build([rule], new ProxyOptions());
        var ours = SignInBuilderTests.SignInHandler(built, rule);
        var theirs = proxies.Single(o => o["rewrite"] is not null);
        Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(theirs, ours), $"caddy:\n{theirs.ToJsonString()}\nours:\n{ours.ToJsonString()}");

        var callback = proxies.SingleOrDefault(o => o["rewrite"] is null);
        if (callback is null)
        {
            Assert.Single(SignInBuilderTests.Routes(built));
            return;
        }
        var ourCallback = SignInBuilderTests.Routes(built)[0]!["handle"]![0]!;
        Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(callback, ourCallback), $"caddy:\n{callback.ToJsonString()}\nours:\n{ourCallback.ToJsonString()}");
    }

    private static IEnumerable<System.Text.Json.Nodes.JsonObject> Descendants(System.Text.Json.Nodes.JsonNode? node)
    {
        if (node is System.Text.Json.Nodes.JsonObject o)
        {
            yield return o;
            foreach (var (_, v) in o) foreach (var d in Descendants(v)) yield return d;
        }
        else if (node is System.Text.Json.Nodes.JsonArray a)
            foreach (var v in a) foreach (var d in Descendants(v)) yield return d;
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void GeneratedConfig_IsAcceptedByCaddy(string caseName)
    {
        if (Caddy() is not { } caddy) return;

        var (rules, options) = Cases[caseName];
        if (rules.Any(r => r.RateLimitPerMinute is > 0) && !HasRateLimitPlugin(caddy))
        {
            Assert.False(Required, $"{caddy} lacks http.handlers.rate_limit (the caddy-ratelimit plugin).");
            _out.WriteLine("Caddy without the caddy-ratelimit plugin; skipping.");
            return;
        }
        var json = CaddyConfigBuilder.Build(rules, options)
            .ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        var (exit, output) = Validate(caddy, json);
        Assert.True(exit == 0, $"caddy rejected the '{caseName}' config:\n{output}\n\n{json}");
    }

    [Fact]
    public void Validation_IsActuallyRunning()
    {
        // Without this, a caddy that always exited 0 — or a Validate() that
        // silently failed to launch it — would turn the whole matrix above into
        // a set of assertions that prove nothing.
        if (Caddy() is not { } caddy) return;

        var json = CaddyConfigBuilder.Build([R("a.example.com", "http://10.0.0.5")], new ProxyOptions())
            .ToJsonString();
        var corrupted = json.Replace("\"handler\":\"reverse_proxy\"",
                                     "\"handler\":\"reverse_proxy\",\"not_a_real_field\":1");
        Assert.NotEqual(json, corrupted); // the substitution actually happened

        var (exit, output) = Validate(caddy, corrupted);
        Assert.True(exit != 0, "caddy accepted a config with an unknown field, so validation proves nothing.");
        _out.WriteLine(output);
    }

    internal static bool Required => Environment.GetEnvironmentVariable("SSLRP_REQUIRE_CADDY") == "1";

    private string? Caddy()
    {
        var caddy = FindCaddy();
        if (caddy is null)
        {
            Assert.False(Required, "SSLRP_REQUIRE_CADDY=1 but no caddy binary: set SSLRP_TEST_CADDY.");
            _out.WriteLine("No caddy binary; set SSLRP_TEST_CADDY to run this.");
        }
        return caddy;
    }

    private static bool HasRateLimitPlugin(string caddy)
    {
        var (exit, output) = Run(caddy, "list-modules");
        return exit == 0 && output.Split('\n').Any(l => l.Trim() == "http.handlers.rate_limit");
    }

    private static (int Exit, string Output) Run(string caddy, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = caddy,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var proc = Process.Start(psi)!;
        // Both streams read concurrently, so neither pipe fills while the other is drained.
        var stderr = proc.StandardError.ReadToEndAsync();
        var output = proc.StandardOutput.ReadToEnd() + stderr.GetAwaiter().GetResult();
        proc.WaitForExit(60_000);
        return (proc.ExitCode, output);
    }

    private static (int Exit, string Stdout, string Stderr) RunSplit(string caddy, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = caddy,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var proc = Process.Start(psi)!;
        var stderr = proc.StandardError.ReadToEndAsync();
        var stdout = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(60_000);
        return (proc.ExitCode, stdout, stderr.GetAwaiter().GetResult());
    }

    private static (int Exit, string Output) Validate(string caddy, string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sslrp-validate-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        try
        {
            return Run(caddy, "validate", "--config", path);
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }

    internal static string? FindCaddy()
    {
        var configured = Environment.GetEnvironmentVariable("SSLRP_TEST_CADDY");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured)) return configured;

        var exe = OperatingSystem.IsWindows() ? "caddy.exe" : "caddy";
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "")
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), exe);
                if (File.Exists(candidate)) return candidate;
            }
            catch (ArgumentException) { /* malformed PATH entry */ }
        }
        return null;
    }
}
