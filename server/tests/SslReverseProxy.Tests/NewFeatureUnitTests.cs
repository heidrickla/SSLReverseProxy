using System.Net.Http;
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
        Assert.Contains("remote_ip", json);
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
