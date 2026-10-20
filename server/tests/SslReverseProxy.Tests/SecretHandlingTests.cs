using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class SecretRedactorTests
{
    [Fact]
    public void Redact_MasksEveryExactValue_LongestFirst()
    {
        var r = new SecretRedactor(["abcdefgh", "abcdefgh-longer", null, "", "short"]);

        Assert.Equal("x [redacted] y [redacted] short", r.Redact("x abcdefgh-longer y abcdefgh short"));
        Assert.True(r.Contains("..abcdefgh.."));
        Assert.False(r.Contains("abcdefg"));
    }

    [Fact]
    public void FromConfiguration_CoversPepperCloudflareTokenAndAlertTargets()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:ApiKeyPepper"] = "pepper-value-1234",
            ["Proxy:CloudflareApiToken"] = "cf-token-value-1234",
            ["Alerts:Targets:0:Url"] = "http://ha.local:8123/api/webhook/hook-id-1234",
            ["Alerts:Targets:1:Url"] = "https://ntfy.example.com/topic",
            ["Alerts:Targets:1:Token"] = "tk_ntfy-token-1234",
        }).Build();

        var r = SecretRedactor.FromConfiguration(config);

        foreach (var secret in new[] { "pepper-value-1234", "cf-token-value-1234", "http://ha.local:8123/api/webhook/hook-id-1234", "tk_ntfy-token-1234" })
            Assert.Equal("[redacted]", r.Redact(secret));
    }

    [Fact]
    public void FromConfiguration_CoversValuesAsTheyAreUsed()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Proxy:CloudflareApiToken"] = "  cf-token-value-1234\n",
            ["Alerts:Targets:0:Url"] = " http://HA.Local:8123/api/webhook/hook-id-1234 ",
            ["Alerts:Targets:0:Token"] = "tk_ntfy-token-1234 ",
        }).Build();

        var r = SecretRedactor.FromConfiguration(config);

        // Caddy's environment gets the trimmed token; the sender requests the parsed URL.
        Assert.Equal("Caddy said [redacted].", r.Redact("Caddy said cf-token-value-1234."));
        Assert.Equal("POST [redacted] failed", r.Redact("POST http://ha.local:8123/api/webhook/hook-id-1234 failed"));
        Assert.Equal("Bearer [redacted]", r.Redact("Bearer tk_ntfy-token-1234"));
    }
}

public class CaddyEnvironmentTests
{
    [Fact]
    public void Apply_KeepsOnlyTheAllowList_AndAddsTheToken()
    {
        var planted = $"SSLRP_TEST_PLANTED_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(planted, "should-not-pass");
        try
        {
            var psi = new ProcessStartInfo("caddy");
            CaddyEnvironment.Apply(psi, new ProxyOptions { CloudflareApiToken = " cf-token " });

            Assert.False(psi.Environment.ContainsKey(planted));
            Assert.True(psi.Environment.ContainsKey("PATH"));
            Assert.Equal("cf-token", psi.Environment[CaddyEnvironment.CloudflareTokenVariable]);
        }
        finally { Environment.SetEnvironmentVariable(planted, null); }
    }

    [Fact]
    public void Apply_WithoutAToken_SetsNoTokenVariable()
    {
        var psi = new ProcessStartInfo("caddy");
        CaddyEnvironment.Apply(psi, new ProxyOptions());
        Assert.False(psi.Environment.ContainsKey(CaddyEnvironment.CloudflareTokenVariable));
    }

    [Fact]
    public void OnlyCaddyEnvironment_BuildsAProcessStartInfo()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src", "SslReverseProxy.Infrastructure")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var offenders = Directory.EnumerateFiles(Path.Combine(dir!.FullName, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .Where(f => Path.GetFileName(f) != "CaddyEnvironment.cs")
            .Where(f => File.ReadAllText(f).Contains("ProcessStartInfo"))
            .Select(Path.GetFileName)
            .ToList();
        Assert.Empty(offenders);
    }

    /// <summary>Asks the real Caddy what environment it sees.</summary>
    [Fact]
    public void Caddy_SeesThePlantedVariableOnlyWithoutTheFilter()
    {
        var caddy = CaddyBinaryValidationTests.FindCaddy();
        if (caddy is null)
        {
            Assert.False(CaddyBinaryValidationTests.Required, "SSLRP_REQUIRE_CADDY=1 but no caddy binary.");
            return;
        }
        var planted = $"SSLRP_TEST_PLANTED_{Guid.NewGuid():N}";
        Environment.SetEnvironmentVariable(planted, "visible");
        try
        {
            // Positive control: the same probe without the filter sees the variable.
            Assert.Contains(planted, Environ(caddy, filtered: false));
            var seen = Environ(caddy, filtered: true);
            Assert.DoesNotContain(planted, seen);
            Assert.Contains($"{CaddyEnvironment.CloudflareTokenVariable}=", seen);
        }
        finally { Environment.SetEnvironmentVariable(planted, null); }
    }

    private static string Environ(string caddy, bool filtered)
    {
        var psi = CaddyEnvironment.StartInfo(new ProxyOptions { CaddyPath = caddy, CloudflareApiToken = "test-token-value" }, "environ");
        if (!filtered)
        {
            psi.Environment.Clear();
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
                psi.Environment[(string)e.Key] = (string?)e.Value;
        }
        using var p = Process.Start(psi)!;
        var err = p.StandardError.ReadToEndAsync();
        var output = p.StandardOutput.ReadToEnd() + err.GetAwaiter().GetResult();
        p.WaitForExit(30_000);
        return output;
    }
}

public class RulePlaceholderTests
{
    private readonly ProxyOptions _opts = new();

    [Fact]
    public void EveryStringField_IsChecked()
    {
        foreach (var prop in typeof(ProxyRule).GetProperties().Where(p => p.PropertyType == typeof(string) && p.CanWrite))
        {
            var rule = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5" };
            prop.SetValue(rule, "{env.X}");
            Assert.Contains(prop.Name, rule.PlaceholderFields());
        }
    }

    [Fact]
    public void Builder_RefusesABracedRule()
    {
        var rule = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true, BasicAuthUsername = "{env.Security__ApiKeyPepper}", BasicAuthPasswordHash = "x" };
        var ex = Assert.Throws<InvalidOperationException>(() => CaddyConfigBuilder.Build([rule], _opts));
        Assert.Contains("BasicAuthUsername", ex.Message);
    }

    [Fact]
    public async Task Validation_ReportsABracedRule()
    {
        using var c = new CaddyProxyController(
            Options.Create(new ProxyOptions { CaddyPath = Path.Combine(Path.GetTempPath(), $"no-caddy-{Guid.NewGuid():N}.exe") }),
            new NoHttp(), NullLogger<CaddyProxyController>.Instance, TimeProvider.System, new TrafficRecorder(), SecretRedactor.None,
        new CaddyCertificateLog(SecretRedactor.None, TimeProvider.System));
        var rule = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true, HealthCheckPath = "/{env.HOME}" };

        var result = await c.ValidateConfigurationAsync(new ProxyPlan([rule]));

        Assert.False(result.Valid);
        Assert.Contains(result.Issues, i => i.Contains("HealthCheckPath"));
    }

    [Fact]
    public async Task RawConfig_WithASecretValue_IsRefused()
    {
        using var c = new CaddyProxyController(
            Options.Create(new ProxyOptions()), new NoHttp(), NullLogger<CaddyProxyController>.Instance,
            TimeProvider.System, new TrafficRecorder(), new SecretRedactor(["cf-token-value-1234"]),
            new CaddyCertificateLog(SecretRedactor.None, TimeProvider.System));

        var status = await c.ApplyRawConfigAsync("{\"apps\":{\"x\":\"cf-token-value-1234\"}}");

        Assert.Equal(ProxyState.Faulted, status.State);
        Assert.Contains("secret", status.Message);
    }

    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new Xunit.Sdk.XunitException("No HTTP expected.");
    }
}

public class RulePlaceholderEndpointTests : IClassFixture<NewEndpointsIntegrationTests.AuthedFactory>
{
    private readonly NewEndpointsIntegrationTests.AuthedFactory _factory;
    public RulePlaceholderEndpointTests(NewEndpointsIntegrationTests.AuthedFactory factory) => _factory = factory;

    private sealed record IdOnly(Guid id);
    private sealed record Versioned(Guid id, int version);

    [Theory]
    [InlineData("basicAuthUsername")]
    [InlineData("healthCheckPath")]
    [InlineData("upstreamTlsTrustedCaFile")]
    public async Task BracedStrings_AreRefusedOnCreateAndUpdate(string field)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", _factory.AdminKey);
        var server = await (await client.PostAsJsonAsync("/api/servers", new { name = $"b-{Guid.NewGuid():N}", host = "10.0.0.9", os = "linux" }))
            .Content.ReadFromJsonAsync<IdOnly>();
        // Each case its own host: the cases share one database, and enabled rules may not share a host and path.
        var domain = $"{field.ToLowerInvariant()}.example.com";

        object Body(bool braced) => field switch
        {
            "basicAuthUsername" => new
            {
                domain, upstreamUrl = "http://10.0.0.20:8080", enableTls = true, enabled = true,
                basicAuthUsername = braced ? "{env.Security__ApiKeyPepper}" : "ops", basicAuthPassword = "pw",
            },
            "healthCheckPath" => new
            {
                domain, upstreamUrl = "http://10.0.0.20:8080", enableTls = true, enabled = true,
                hardening = new { healthCheckPath = braced ? "/{env.HOME}" : "/health" },
            },
            _ => new
            {
                domain, upstreamUrl = "https://10.0.0.20:8443", enableTls = true, enabled = true,
                hardening = new { upstreamTlsTrustedCaFile = braced ? "/{env.HOME}/ca.pem" : "/etc/ca.pem" },
            },
        };

        var refused = await client.PostAsJsonAsync($"/api/servers/{server!.id}/rules", Body(braced: true));
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains(field, await refused.Content.ReadAsStringAsync());

        var created = await client.PostAsJsonAsync($"/api/servers/{server.id}/rules", Body(braced: false));
        created.EnsureSuccessStatusCode();
        var rule = (await created.Content.ReadFromJsonAsync<Versioned>())!;
        var put = new HttpRequestMessage(HttpMethod.Put, $"/api/servers/{server.id}/rules/{rule.id}") { Content = JsonContent.Create(Body(braced: true)) };
        put.Headers.TryAddWithoutValidation("If-Match", $"\"{rule.version}\"");
        var updated = await client.SendAsync(put);
        Assert.Equal(HttpStatusCode.BadRequest, updated.StatusCode);
        Assert.Contains(field, await updated.Content.ReadAsStringAsync());
    }
}
