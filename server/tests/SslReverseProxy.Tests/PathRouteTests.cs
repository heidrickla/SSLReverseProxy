using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class RoutePathTests
{
    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("/", null)]
    [InlineData("  /api  ", "/api")]
    [InlineData("/api/", "/api")]
    [InlineData("/api/v1", "/api/v1")]
    [InlineData("/A-b_c.d~e", "/A-b_c.d~e")]
    public void Normalize_Accepts(string? input, string? expected)
    {
        Assert.True(RoutePath.TryNormalize(input, out var prefix, out var error));
        Assert.Null(error);
        Assert.Equal(expected, prefix);
    }

    [Theory]
    [InlineData("api")]
    [InlineData("/{env.SSLRP_CLOUDFLARE_API_TOKEN}")]
    [InlineData("/api*")]
    [InlineData("/api?x=1")]
    [InlineData("/api#x")]
    [InlineData("/a%2e")]
    [InlineData("/a/../b")]
    [InlineData("/a/./b")]
    [InlineData("/a//b")]
    [InlineData("/a b")]
    public void Normalize_Rejects(string input)
    {
        Assert.False(RoutePath.TryNormalize(input, out var prefix, out var error));
        Assert.Null(prefix);
        Assert.NotNull(error);
    }

    [Fact]
    public void Normalize_RejectsOverLength()
    {
        Assert.True(RoutePath.TryNormalize("/" + new string('a', RoutePath.MaxLength - 1), out _, out _));
        Assert.False(RoutePath.TryNormalize("/" + new string('a', RoutePath.MaxLength), out _, out _));
    }
}

public class PathRouteBuilderTests
{
    private readonly ProxyOptions _opts = new() { AdminEndpoint = "http://127.0.0.1:2019" };

    private static JsonArray Routes(JsonObject config, string server = CaddyConfigBuilder.HttpsServer) =>
        config["apps"]!["http"]!["servers"]![server]!["routes"]!.AsArray();

    private static string PathOf(JsonNode? route) =>
        route!["match"]![0]!["path"]?[0]?.GetValue<string>() ?? "(host)";

    [Fact]
    public void PathRules_GoBeforeTheWholeHostRule_LongestFirst()
    {
        var rules = new[]
        {
            new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.1", Enabled = true },
            new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.2", Enabled = true, PathPrefix = "/api" },
            new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.3", Enabled = true, PathPrefix = "/api/v2" },
        };

        var routes = Routes(CaddyConfigBuilder.Build(rules, _opts));

        Assert.Equal(["/api/v2", "/api", "(host)"], routes.Select(PathOf).ToArray());
    }

    [Fact]
    public void PathMatch_CoversThePrefixAndBelowIt()
    {
        var rules = new[] { new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.2", Enabled = true, PathPrefix = "/api" } };

        var match = Routes(CaddyConfigBuilder.Build(rules, _opts))[0]!["match"]![0]!;

        Assert.Equal("a.example.com", match["host"]![0]!.GetValue<string>());
        Assert.Equal(["/api", "/api/*"], match["path"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray());
    }

    [Fact]
    public void Strip_EmitsRewriteImmediatelyBeforeTheProxy()
    {
        var rules = new[]
        {
            new ProxyRule
            {
                Domain = "a.example.com", UpstreamUrl = "http://10.0.0.2", Enabled = true,
                PathPrefix = "/api", StripPathPrefix = true, BasicAuthUsername = "ops",
                BasicAuthPasswordHash = BCrypt.Net.BCrypt.HashPassword("x"),
            },
        };

        var handlers = Routes(CaddyConfigBuilder.Build(rules, _opts))[0]!["handle"]!.AsArray()
            .Select(h => h!["handler"]!.GetValue<string>()).ToArray();

        Assert.Equal(["headers", "authentication", "rewrite", "reverse_proxy"], handlers);
        var rewrite = Routes(CaddyConfigBuilder.Build(rules, _opts))[0]!["handle"]![2]!;
        Assert.Equal("/api", rewrite["strip_path_prefix"]!.GetValue<string>());
    }

    [Fact]
    public void NoStrip_EmitsNoRewrite()
    {
        var rules = new[] { new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.2", Enabled = true, PathPrefix = "/api" } };

        Assert.DoesNotContain("rewrite", CaddyConfigBuilder.Build(rules, _opts).ToJsonString());
    }

    [Fact]
    public void EachRateLimitedRule_GetsItsOwnZone()
    {
        var a = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.1", Enabled = true, RateLimitPerMinute = 5 };
        var b = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.2", Enabled = true, RateLimitPerMinute = 500, PathPrefix = "/api" };

        var zones = Routes(CaddyConfigBuilder.Build([a, b], _opts))
            .Select(r => r!["handle"]!.AsArray().First(h => h!["handler"]!.GetValue<string>() == "rate_limit")!["rate_limits"]!.AsObject().Single())
            .ToDictionary(z => z.Key, z => z.Value!["max_events"]!.GetValue<int>());

        Assert.Equal(500, zones[CaddyConfigBuilder.RateLimitZone(b.Id)]);
        Assert.Equal(5, zones[CaddyConfigBuilder.RateLimitZone(a.Id)]);
    }
}

public class PathRouteStructuralValidationTests
{
    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new Xunit.Sdk.XunitException("No HTTP expected.");
    }

    private static CaddyProxyController Controller() => new(
        Options.Create(new ProxyOptions { CaddyPath = Path.Combine(Path.GetTempPath(), $"no-caddy-{Guid.NewGuid():N}.exe") }),
        new NoHttp(), NullLogger<CaddyProxyController>.Instance, TimeProvider.System, new TrafficRecorder(), SecretRedactor.None);

    private static ProxyRule Rule(string domain, string? prefix, bool tls = true) =>
        new() { Domain = domain, UpstreamUrl = "http://10.0.0.2", Enabled = true, EnableTls = tls, PathPrefix = prefix };

    [Fact]
    public async Task SameHost_DifferentPaths_IsValid()
    {
        using var c = Controller();
        var result = await c.ValidateConfigurationAsync([Rule("a.example.com", null), Rule("a.example.com", "/api"), Rule("A.example.com", "/web")]);
        Assert.True(result.Valid, string.Join("; ", result.Issues));
    }

    [Fact]
    public async Task SameHostAndPath_IsDuplicate_IgnoringCase()
    {
        using var c = Controller();
        var result = await c.ValidateConfigurationAsync([Rule("a.example.com", "/api"), Rule("A.example.com", "/API")]);
        Assert.False(result.Valid);
        Assert.Contains(result.Issues, i => i.Contains("Duplicate route"));
    }

    [Fact]
    public async Task SameHost_MixedTls_IsRejected()
    {
        using var c = Controller();
        var result = await c.ValidateConfigurationAsync([Rule("a.example.com", null, tls: true), Rule("a.example.com", "/api", tls: false)]);
        Assert.False(result.Valid);
        Assert.Contains(result.Issues, i => i.Contains("disagree on TLS"));
    }
}

public class PathRouteEndpointTests : IClassFixture<NewEndpointsIntegrationTests.AuthedFactory>
{
    private readonly NewEndpointsIntegrationTests.AuthedFactory _factory;
    public PathRouteEndpointTests(NewEndpointsIntegrationTests.AuthedFactory factory) => _factory = factory;

    private sealed record Routing(string? pathPrefix, bool stripPathPrefix);
    private sealed record RuleBody(Guid id, string domain, Routing routing, int version);
    private sealed record IdOnly(Guid id);

    private HttpClient Authed()
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Add("X-Api-Key", _factory.AdminKey);
        return c;
    }

    private static async Task<Guid> NewServerAsync(HttpClient client)
    {
        var resp = await client.PostAsJsonAsync("/api/servers", new { name = $"p-{Guid.NewGuid():N}", host = "10.0.0.9", os = "linux" });
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<IdOnly>())!.id;
    }

    private static object Body(string domain, object? routing) => new
    {
        domain, upstreamUrl = "http://10.0.0.20:8080", enableTls = true, enabled = true, routing,
    };

    [Fact]
    public async Task Create_StoresTheNormalisedPrefix_AndPutWithoutRoutingKeepsIt()
    {
        var client = Authed();
        var serverId = await NewServerAsync(client);
        var created = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules",
            Body("p1.example.com", new { pathPrefix = "/api/", stripPathPrefix = true }));
        created.EnsureSuccessStatusCode();
        var rule = (await created.Content.ReadFromJsonAsync<RuleBody>())!;
        Assert.Equal(new Routing("/api", true), rule.routing);

        var put = new HttpRequestMessage(HttpMethod.Put, $"/api/servers/{serverId}/rules/{rule.id}")
        {
            Content = JsonContent.Create(Body("p1.example.com", null)),
        };
        put.Headers.TryAddWithoutValidation("If-Match", $"\"{rule.version}\"");
        var updated = await client.SendAsync(put);
        updated.EnsureSuccessStatusCode();
        Assert.Equal(new Routing("/api", true), (await updated.Content.ReadFromJsonAsync<RuleBody>())!.routing);
    }

    [Fact]
    public async Task SlashPrefix_MeansWholeHost_AndClearsStrip()
    {
        var client = Authed();
        var serverId = await NewServerAsync(client);
        var created = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules",
            Body("p2.example.com", new { pathPrefix = "/", stripPathPrefix = false }));
        created.EnsureSuccessStatusCode();
        Assert.Equal(new Routing(null, false), (await created.Content.ReadFromJsonAsync<RuleBody>())!.routing);
    }

    [Theory]
    [InlineData("/{env.Security__ApiKeyPepper}", false, "routing.pathPrefix")]
    [InlineData("api", false, "routing.pathPrefix")]
    [InlineData(null, true, "routing.stripPathPrefix")]
    public async Task InvalidRouting_IsRejected(string? prefix, bool strip, string field)
    {
        var client = Authed();
        var serverId = await NewServerAsync(client);
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules",
            Body("p3.example.com", new { pathPrefix = prefix, stripPathPrefix = strip }));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains(field, await resp.Content.ReadAsStringAsync());
    }
}
