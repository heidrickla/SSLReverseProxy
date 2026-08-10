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
/// Opt-in: point <c>SSLRP_TEST_CADDY</c> at a caddy binary, or put one on PATH.
/// With neither, these no-op rather than fail, so the suite still runs on a box
/// without Caddy installed. <see cref="Validation_IsActuallyRunning"/> is the
/// guard against that leniency turning into a matrix that passes vacuously.
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

    // Rate limiting is deliberately absent: it needs the caddy-ratelimit plugin,
    // which a stock binary does not have, so including it would make this suite
    // fail for a reason that is not a defect.
    public static TheoryData<string> CaseNames()
    {
        var data = new TheoryData<string>();
        foreach (var k in Cases.Keys) data.Add(k);
        return data;
    }

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
        ], new ProxyOptions { AccessLogPath = "/var/log/caddy/access.log" }),

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
            }),
            R("plain.example.com", "http://10.0.0.9", r => { r.EnableTls = false; r.SkipAccessLog = true; }),
        ], new ProxyOptions
        {
            TrustedProxyCidrs = "10.0.0.0/8",
            AccessLogPath = "/var/log/caddy/access.log",
            ReadHeaderTimeoutSeconds = 10,
            IdleTimeoutSeconds = 120,
            AcmeContactEmail = "ops@example.com",
        }),
    };

    [Theory]
    [MemberData(nameof(CaseNames))]
    public void GeneratedConfig_IsAcceptedByCaddy(string caseName)
    {
        if (FindCaddy() is not { } caddy)
        {
            _out.WriteLine("No caddy binary; set SSLRP_TEST_CADDY to run this.");
            return;
        }

        var (rules, options) = Cases[caseName];
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
        if (FindCaddy() is not { } caddy)
        {
            _out.WriteLine("No caddy binary; set SSLRP_TEST_CADDY to run this.");
            return;
        }

        var json = CaddyConfigBuilder.Build([R("a.example.com", "http://10.0.0.5")], new ProxyOptions())
            .ToJsonString();
        var corrupted = json.Replace("\"handler\":\"reverse_proxy\"",
                                     "\"handler\":\"reverse_proxy\",\"not_a_real_field\":1");
        Assert.NotEqual(json, corrupted); // the substitution actually happened

        var (exit, output) = Validate(caddy, corrupted);
        Assert.True(exit != 0, "caddy accepted a config with an unknown field, so validation proves nothing.");
        _out.WriteLine(output);
    }

    private static (int Exit, string Output) Validate(string caddy, string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"sslrp-validate-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = caddy,
                ArgumentList = { "validate", "--config", path },
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
            proc.WaitForExit(60_000);
            return (proc.ExitCode, output);
        }
        finally
        {
            try { File.Delete(path); } catch { /* best effort */ }
        }
    }

    private static string? FindCaddy()
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
