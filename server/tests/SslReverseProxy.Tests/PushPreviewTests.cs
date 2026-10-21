using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class ConfigDiffTests
{
    private static readonly ProxyOptions Options = new();

    // One id per route, as a row keeps across edits: each route's log_append names it.
    private static ProxyRule Rule(string domain, string upstream = "http://10.0.0.5", string? prefix = null) =>
        new()
        {
            Id = new Guid(System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(domain + prefix))),
            Domain = domain, UpstreamUrl = upstream, Enabled = true, EnableTls = true, PathPrefix = prefix,
        };

    private static string Config(params ProxyRule[] rules) =>
        CaddyConfigBuilder.Build(new ProxyPlan(rules, []), Options).ToJsonString();

    [Fact]
    public void TheSameConfig_HasNoChanges()
    {
        var c = Config(Rule("a.example.com"), Rule("b.example.com"));
        var p = ConfigDiff.Compare(c, c, SecretRedactor.None);
        Assert.True(p.RunningAvailable);
        Assert.Empty(p.Changes);
        Assert.False(p.Truncated);
    }

    [Fact]
    public void AnInsertedRoute_IsOneAddition_NamedByHostAndPath()
    {
        var before = Config(Rule("a.example.com"), Rule("c.example.com"));
        var after = Config(Rule("a.example.com"), Rule("b.example.com", prefix: "/api"), Rule("c.example.com"));
        var change = Assert.Single(ConfigDiff.Compare(before, after, SecretRedactor.None).Changes);
        Assert.Equal(("b.example.com/api (https)", "added", ""), (change.Group, change.Kind, change.Path));
        Assert.Null(change.Before);
        Assert.Contains("10.0.0.5:80", change.After);
    }

    [Fact]
    public void AChangedUpstream_IsOneLeafChange()
    {
        var before = Config(Rule("a.example.com"), Rule("b.example.com"));
        var after = Config(Rule("a.example.com"), Rule("b.example.com", "http://10.0.0.6"));
        var change = Assert.Single(ConfigDiff.Compare(before, after, SecretRedactor.None).Changes);
        Assert.Equal(("b.example.com (https)", "changed", "/handle/reverse_proxy/upstreams/0/dial"), (change.Group, change.Kind, change.Path));
        Assert.Equal("\"10.0.0.5:80\"", change.Before);
        Assert.Equal("\"10.0.0.6:80\"", change.After);
    }

    [Fact]
    public void AnInsertedHandler_IsOneAddition_AndTheRestStayPut()
    {
        var before = Config(Rule("a.example.com"));
        var limited = Rule("a.example.com");
        limited.RateLimitPerMinute = 60;
        var change = Assert.Single(ConfigDiff.Compare(before, Config(limited), SecretRedactor.None).Changes);
        Assert.Equal(("a.example.com (https)", "added", "/handle/rate_limit"), (change.Group, change.Kind, change.Path));
    }

    [Fact]
    public void ATlsToggle_ShowsTheRouteLeavingOneServerAndJoiningTheOther()
    {
        var plain = Rule("a.example.com");
        plain.EnableTls = false;
        var changes = ConfigDiff.Compare(Config(Rule("a.example.com")), Config(plain), SecretRedactor.None).Changes;
        Assert.Contains(changes, c => c is { Group: "a.example.com (https)", Kind: "removed", Path: "" });
        Assert.Contains(changes, c => c is { Group: "a.example.com (http)", Kind: "added", Path: "" });
    }

    [Fact]
    public void ABasicAuthHashChange_ShowsAsChanged_WithNeitherHash()
    {
        var oldHash = BCrypt.Net.BCrypt.HashPassword("first-password");
        var newHash = BCrypt.Net.BCrypt.HashPassword("second-password");
        ProxyRule Guarded(string hash)
        {
            var r = Rule("a.example.com");
            r.BasicAuthUsername = "ops";
            r.BasicAuthPasswordHash = hash;
            return r;
        }

        var p = ConfigDiff.Compare(Config(Guarded(oldHash)), Config(Guarded(newHash)), SecretRedactor.None);
        var change = Assert.Single(p.Changes);
        Assert.Equal(("changed", ConfigDiff.Masked, ConfigDiff.Masked), (change.Kind, change.Before, change.After));
        Assert.EndsWith("/password", change.Path);

        // Added whole, the route's hash is masked inside the rendered value too.
        var added = Assert.Single(ConfigDiff.Compare(Config(), Config(Guarded(newHash)), SecretRedactor.None).Changes,
            c => c.Group == "a.example.com (https)");
        Assert.DoesNotContain(newHash, added.After);
        Assert.Contains(ConfigDiff.Masked, added.After);
    }

    [Fact]
    public void AConfiguredSecret_IsRedactedOnBothSides()
    {
        const string secret = "configured-secret-value";
        var redactor = new SecretRedactor([secret]);
        var p = ConfigDiff.Compare(
            "{\"apps\":{\"x\":{\"note\":\"" + secret + "-old\"}}}",
            "{\"apps\":{\"x\":{\"note\":\"" + secret + "-new\"}}}", redactor);
        var change = Assert.Single(p.Changes);
        Assert.Equal(("x app", "/note"), (change.Group, change.Path));
        Assert.DoesNotContain(secret, change.Before);
        Assert.DoesNotContain(secret, change.After);
        Assert.Equal($"\"{SecretRedactor.Mask}-new\"", change.After);
    }

    [Fact]
    public void WithoutARunningConfig_ThereIsNothingToCompare()
    {
        var next = Config(Rule("a.example.com"));
        var p = ConfigDiff.Compare(null, next, SecretRedactor.None);
        Assert.False(p.RunningAvailable);
        Assert.Empty(p.Changes);
        Assert.NotEqual(ConfigDiff.Digest("", next), p.Digest);
    }

    [Fact]
    public void TheDigest_FollowsBothSides()
    {
        var a = Config(Rule("a.example.com"));
        var b = Config(Rule("b.example.com"));
        Assert.Equal(ConfigDiff.Digest(a, b), ConfigDiff.Compare(a, b, SecretRedactor.None).Digest);
        Assert.NotEqual(ConfigDiff.Digest(a, b), ConfigDiff.Digest(b, b));
        Assert.NotEqual(ConfigDiff.Digest(a, b), ConfigDiff.Digest(a, a));
        // The framing keeps the two sides apart.
        Assert.NotEqual(ConfigDiff.Digest("ab", "c"), ConfigDiff.Digest("a", "bc"));
    }

    [Fact]
    public void ALongList_StopsAtTheCap_AndSaysSo()
    {
        var before = Config();
        var after = Config(Enumerable.Range(0, ConfigDiff.MaxChanges + 20).Select(i => Rule($"h{i}.example.com")).ToArray());
        var p = ConfigDiff.Compare(before, after, SecretRedactor.None);
        Assert.True(p.Truncated);
        Assert.Equal(ConfigDiff.MaxChanges, p.Changes.Count);
    }

    [Fact]
    public void ALongValue_IsCut()
    {
        var p = ConfigDiff.Compare("""{"admin":{"x":"a"}}""", "{\"admin\":{\"x\":\"" + new string('v', 5000) + "\"}}", SecretRedactor.None);
        var change = Assert.Single(p.Changes);
        Assert.Equal(ConfigDiff.MaxValueLength + 1, change.After!.Length);
        Assert.EndsWith("…", change.After);
    }
}

public class PushPreviewEndpointTests : IDisposable
{
    private readonly CertificateFactory _factory = new(cloudflareToken: null);

    public void Dispose() => _factory.Dispose();

    private async Task<Guid> AddRule(string domain, string upstream = "http://10.0.0.5")
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var server = new ProxyServer { Name = $"s-{Guid.NewGuid():N}", Host = "192.0.2.9", Os = "linux" };
        var rule = new ProxyRule { Domain = domain, UpstreamUrl = upstream, EnableTls = true, Enabled = true };
        server.Rules.Add(rule);
        db.Servers.Add(server);
        await db.SaveChangesAsync();
        return rule.Id;
    }

    private HttpClient Scoped(params Permission[] scopes)
    {
        using var scope = _factory.Services.CreateScope();
        var admin = scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.First(u => u.Role == Role.Admin);
        var token = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
            .CreateAsync(admin.Id, "preview", _factory.Clock.GetUtcNow().AddDays(30), scopes).GetAwaiter().GetResult().PlaintextToken;
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Add("X-Api-Key", token);
        return c;
    }

    private static async Task<JsonNode> Preview(HttpClient c, string url = "/api/proxy/preview")
    {
        var r = await c.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return JsonNode.Parse(await r.Content.ReadAsStringAsync())!;
    }

    [Fact]
    public async Task AfterAReload_ThePreviewIsEmpty_AndARuleEditShowsExactlyThatRoute()
    {
        var c = _factory.Authed();
        await AddRule("a.example.com");
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync("/api/proxy/reload", null)).StatusCode);
        var clean = await Preview(c);
        Assert.True((bool)clean["runningAvailable"]!);
        Assert.Empty(clean["changes"]!.AsArray());

        await AddRule("b.example.com");
        var p = await Preview(c);
        var change = Assert.Single(p["changes"]!.AsArray());
        Assert.Equal("b.example.com (https)", (string)change!["group"]!);
        Assert.Equal("added", (string)change["kind"]!);
    }

    [Fact]
    public async Task AReloadWithAStaleDigest_IsRefused_AndPushesNothing()
    {
        var c = _factory.Authed();
        await AddRule("a.example.com");
        await c.PostAsync("/api/proxy/reload", null);
        var digest = (string)(await Preview(c))["digest"]!;

        await AddRule("b.example.com");
        var applied = _factory.Proxy.Applied.Count;
        var stale = await c.PostAsJsonAsync("/api/proxy/reload", new { previewDigest = digest });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal(applied, _factory.Proxy.Applied.Count);

        var fresh = (string)(await Preview(c))["digest"]!;
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsJsonAsync("/api/proxy/reload", new { previewDigest = fresh })).StatusCode);
        Assert.Equal(applied + 1, _factory.Proxy.Applied.Count);
        Assert.Contains("b.example.com", _factory.Proxy.RunningConfig);
    }

    [Fact]
    public async Task AReloadWithNoBody_PushesWithoutTheCheck_WithOrWithoutAContentType()
    {
        var c = _factory.Authed();
        await AddRule("a.example.com");
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync("/api/proxy/reload", null)).StatusCode);
        var empty = new StringContent("", System.Text.Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync("/api/proxy/reload", empty)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsJsonAsync("/api/proxy/reload", new { previewDigest = (string?)null })).StatusCode);
        Assert.Equal(3, _factory.Proxy.Applied.Count);
    }

    [Fact]
    public async Task ADigestFromAnotherPreview_IsRefused()
    {
        var c = _factory.Authed();
        await AddRule("a.example.com");
        await c.PostAsync("/api/proxy/reload", null);
        var stopped = ConfigDiff.Digest(null, _factory.Proxy.RunningConfig!);
        Assert.Equal(HttpStatusCode.Conflict, (await c.PostAsJsonAsync("/api/proxy/reload", new { previewDigest = stopped })).StatusCode);
    }

    [Fact]
    public async Task ARollbackPreview_ComparesTheSnapshot_AndAStaleDigestIsRefused()
    {
        var c = _factory.Authed();
        await AddRule("a.example.com");
        await c.PostAsync("/api/proxy/reload", null);
        var snapshot = (long)(await c.GetFromJsonAsync<JsonArray>("/api/proxy/snapshots"))![0]!["id"]!;
        await AddRule("b.example.com");
        await c.PostAsync("/api/proxy/reload", null);

        var p = await Preview(c, $"/api/proxy/snapshots/{snapshot}/preview");
        var change = Assert.Single(p["changes"]!.AsArray());
        Assert.Equal(("b.example.com (https)", "removed"), ((string)change!["group"]!, (string)change["kind"]!));
        var digest = (string)p["digest"]!;

        await AddRule("c.example.com");
        await c.PostAsync("/api/proxy/reload", null);
        var raw = _factory.Proxy.RawApplied;
        var stale = await c.PostAsJsonAsync("/api/proxy/rollback", new { snapshotId = snapshot, previewDigest = digest });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal(raw, _factory.Proxy.RawApplied);

        var fresh = (string)(await Preview(c, $"/api/proxy/snapshots/{snapshot}/preview"))["digest"]!;
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsJsonAsync("/api/proxy/rollback", new { snapshotId = snapshot, previewDigest = fresh })).StatusCode);
        Assert.Equal(raw + 1, _factory.Proxy.RawApplied);
    }

    [Fact]
    public async Task WithCaddyStopped_ThePreviewSaysThereIsNoRunningConfig()
    {
        var c = _factory.Authed();
        await AddRule("a.example.com");
        await c.PostAsync("/api/proxy/reload", null);
        _factory.Proxy.State = ProxyState.Stopped;
        var p = await Preview(c);
        Assert.False((bool)p["runningAvailable"]!);
        Assert.Contains("not running", (string)p["message"]!);
        Assert.Empty(p["changes"]!.AsArray());
    }

    [Fact]
    public async Task ThePreviewNeedsProxyReload_AndTheRollbackPreviewProxyControl()
    {
        var admin = _factory.Authed();
        await AddRule("a.example.com");
        await admin.PostAsync("/api/proxy/reload", null);
        var snapshot = (long)(await admin.GetFromJsonAsync<JsonArray>("/api/proxy/snapshots"))![0]!["id"]!;

        Assert.Equal(HttpStatusCode.Forbidden, (await Scoped(Permission.ServerRead).GetAsync("/api/proxy/preview")).StatusCode);
        var reloader = Scoped(Permission.ServerRead, Permission.ProxyReload);
        Assert.Equal(HttpStatusCode.OK, (await reloader.GetAsync("/api/proxy/preview")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reloader.GetAsync($"/api/proxy/snapshots/{snapshot}/preview")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Scoped(Permission.ProxyControl).GetAsync($"/api/proxy/snapshots/{snapshot}/preview")).StatusCode);
    }

    [Fact]
    public async Task APreviewOfAMissingSnapshot_IsNotFound()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await _factory.Authed().GetAsync("/api/proxy/snapshots/999999/preview")).StatusCode);
    }
}
