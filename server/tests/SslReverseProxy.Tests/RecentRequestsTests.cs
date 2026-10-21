using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class RecentRequestsTests
{
    private readonly ManualClock _clock = new(new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero));
    private static readonly Guid A = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid B = Guid.Parse("22222222-2222-2222-2222-222222222222");

    // A line as Caddy's access logger writes it, headers included, as with an encoder that keeps them.
    internal static string Line(Guid? rule, DateTimeOffset at, string uri = "/x", int status = 200, string host = "a.example.com",
        string method = "GET", string ip = "198.51.100.7", double duration = 0.0125, long size = 42, string logger = "http.log.access.access")
    {
        var entry = new Dictionary<string, object?>
        {
            ["level"] = "info", ["ts"] = at.ToUnixTimeMilliseconds() / 1000.0, ["logger"] = logger, ["msg"] = "handled request",
            ["request"] = new Dictionary<string, object?>
            {
                ["remote_ip"] = "10.9.8.7", ["client_ip"] = ip, ["proto"] = "HTTP/1.1", ["method"] = method, ["host"] = host, ["uri"] = uri,
                ["headers"] = new Dictionary<string, string[]> { ["Authorization"] = ["Basic b3BzOmh1bnRlcjI="], ["Cookie"] = ["sid=s3cr3t"] },
            },
            ["user_id"] = "ops", ["duration"] = duration, ["size"] = size, ["status"] = status,
        };
        if (rule is { } r) entry[RecentRequests.RuleField] = r.ToString();
        return JsonSerializer.Serialize(entry);
    }

    private static Func<int, bool> All => _ => true;

    [Fact]
    public void AnAccessLine_IsKept_WithoutItsQueryHeadersOrUser()
    {
        var store = new RecentRequests(_clock);
        Assert.True(store.Observe(Line(A, _clock.GetUtcNow(), uri: "/a/b?token=SECRET#frag", host: "App.Example.COM")));

        var e = Assert.Single(store.Query(A, 50, All, null).Requests);
        Assert.Equal((1L, "GET", "app.example.com", "/a/b", 200, 12.5, 42L, "198.51.100.7"),
            (e.Seq, e.Method, e.Host, e.Path, e.Status, e.DurationMs, e.Size, e.ClientIp));
        Assert.Equal(_clock.GetUtcNow(), e.At);
        var kept = JsonSerializer.Serialize(e);
        foreach (var secret in new[] { "SECRET", "frag", "b3BzOmh1bnRlcjI", "s3cr3t", "ops", "10.9.8.7" })
            Assert.DoesNotContain(secret, kept);
    }

    [Fact]
    public void OnlyTopLevelAccessEntries_AreTakenFromTheLog()
    {
        var store = new RecentRequests(_clock);
        Assert.False(store.Observe("""{"level":"info","logger":"tls.obtain","msg":"certificate obtained successfully"}"""));
        Assert.False(store.Observe("""{"level":"info","logger":"http.log.access.access","msg":"cut short"""));
        Assert.False(store.Observe("""{"level":"info","logger":"admin.api","x":{"logger":"http.log.access.access"}}"""));
        // An access entry outside any rule's route (no route matched) is consumed and not kept.
        Assert.True(store.Observe(Line(null, _clock.GetUtcNow())));

        Assert.True(store.Observe(Line(A, _clock.GetUtcNow())));
        Assert.Equal(1, Assert.Single(store.Query(A, 50, All, null).Requests).Seq);
    }

    [Fact]
    public void OddValues_AreCleanedOrDropped()
    {
        var store = new RecentRequests(_clock);
        var longPath = "/" + new string('p', 600);
        store.Observe(Line(A, _clock.GetUtcNow(), uri: "/a\u0007b", method: "G\u0000ET", ip: "not-an-ip", status: 1200, duration: -1));
        store.Observe(Line(A, _clock.GetUtcNow(), uri: longPath));

        var (requests, _) = store.Query(A, 50, All, null);
        Assert.Equal(RecentRequests.MaxPathLength + 1, requests[0].Path.Length);
        Assert.EndsWith("…", requests[0].Path);
        Assert.Equal(("/ab", "?", (string?)null, 0, 0.0), (requests[1].Path, requests[1].Method, requests[1].ClientIp, requests[1].Status, requests[1].DurationMs));
    }

    [Fact]
    public void Query_PagesNewestFirst_ForOneRule_AndFiltersByStatus()
    {
        var store = new RecentRequests(_clock);
        var statuses = new[] { 200, 404, 200, 500, 200, 404, 200 };
        foreach (var s in statuses)
        {
            store.Observe(Line(A, _clock.GetUtcNow(), status: s));
            store.Observe(Line(B, _clock.GetUtcNow(), status: s));
        }

        var first = store.Query(A, 3, All, null);
        Assert.Equal([13L, 11, 9], first.Requests.Select(r => r.Seq));
        Assert.Equal(9, first.Next);
        var second = store.Query(A, 3, All, first.Next);
        Assert.Equal([7L, 5, 3], second.Requests.Select(r => r.Seq));
        var last = store.Query(A, 3, All, second.Next);
        Assert.Equal([1L], last.Requests.Select(r => r.Seq));
        Assert.Null(last.Next);

        var missing = store.Query(A, 2, s => s / 100 == 4, null);
        Assert.Equal([404, 404], missing.Requests.Select(r => r.Status));
        Assert.Null(missing.Next);
    }

    [Fact]
    public void TheStore_KeepsTheLastCapacityRequests()
    {
        var store = new RecentRequests(_clock);
        for (var i = 0; i < RecentRequests.Capacity + 3; i++) store.Observe(Line(A, _clock.GetUtcNow()));

        Assert.Empty(store.Query(A, 500, All, 4).Requests);
        Assert.Equal(4, Assert.Single(store.Query(A, 1, All, 5).Requests).Seq);
        Assert.Equal(RecentRequests.Capacity + 3, store.Query(A, 1, All, null).Requests[0].Seq);
    }

    [Fact]
    public void Requests_OlderThanADay_AreNotReturned()
    {
        var store = new RecentRequests(_clock);
        store.Observe(Line(A, _clock.GetUtcNow()));
        _clock.Advance(RecentRequests.MaxAge + TimeSpan.FromSeconds(1));
        Assert.Empty(store.Query(A, 50, All, null).Requests);

        store.Observe(Line(A, _clock.GetUtcNow()));
        Assert.Equal(2, Assert.Single(store.Query(A, 50, All, null).Requests).Seq);
    }
}

public class RecentRequestsEndpointTests : IDisposable
{
    private readonly CertificateFactory _factory = new(cloudflareToken: null);
    private readonly HttpClient _admin;

    public RecentRequestsEndpointTests() => _admin = _factory.Authed();

    public void Dispose() => _factory.Dispose();

    private RecentRequests Store => _factory.Services.GetRequiredService<RecentRequests>();

    private async Task<(string Server, string Rule)> AddRule(string domain, bool skipAccessLog = false)
    {
        var server = await _admin.PostAsJsonAsync("/api/servers", new { name = $"S {domain}", host = "192.0.2.20", os = "linux" });
        var serverId = (string)JsonNode.Parse(await server.Content.ReadAsStringAsync())!["id"]!;
        var rule = await _admin.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain, upstreamUrl = "http://10.0.0.5", enableTls = false, enabled = true,
            hardening = new { skipAccessLog },
        });
        Assert.True(rule.StatusCode == HttpStatusCode.Created, await rule.Content.ReadAsStringAsync());
        return (serverId, (string)JsonNode.Parse(await rule.Content.ReadAsStringAsync())!["id"]!);
    }

    private async Task<JsonObject> Get(string url)
    {
        var r = await _admin.GetAsync(url);
        Assert.True(r.StatusCode == HttpStatusCode.OK, await r.Content.ReadAsStringAsync());
        return JsonNode.Parse(await r.Content.ReadAsStringAsync())!.AsObject();
    }

    [Fact]
    public async Task ARulesRequests_ComeNewestFirst_InPages_AndByStatus()
    {
        var (server, rule) = await AddRule("a.example.com");
        var (_, other) = await AddRule("b.example.com");
        var now = _factory.Clock.GetUtcNow();
        foreach (var status in new[] { 200, 502, 200 })
        {
            Store.Observe(RecentRequestsTests.Line(Guid.Parse(rule), now, uri: "/p?q=1", status: status));
            Store.Observe(RecentRequestsTests.Line(Guid.Parse(other), now, status: status));
        }

        var url = $"/api/servers/{server}/rules/{rule}/requests";
        var all = await Get(url);
        Assert.Null(all["message"]);
        Assert.Null(all["next"]);
        var requests = all["requests"]!.AsArray();
        Assert.Equal([5L, 3, 1], requests.Select(r => (long)r!["seq"]!));
        Assert.Equal(["seq", "at", "method", "host", "path", "status", "durationMs", "size", "clientIp"], requests[0]!.AsObject().Select(p => p.Key));
        Assert.Equal("/p", (string?)requests[0]!["path"]);

        var page = await Get($"{url}?take=1");
        Assert.Equal(5, (long)page["next"]!);
        Assert.Equal([3L], (await Get($"{url}?take=1&before=5"))["requests"]!.AsArray().Select(r => (long)r!["seq"]!));
        Assert.Equal([502], (await Get($"{url}?status=5xx"))["requests"]!.AsArray().Select(r => (int)r!["status"]!));
        Assert.Equal([3L], (await Get($"{url}?status=502"))["requests"]!.AsArray().Select(r => (long)r!["seq"]!));
    }

    [Fact]
    public async Task BadQueries_AndAnotherServersRule_AreRefused()
    {
        var (server, rule) = await AddRule("a.example.com");
        var (otherServer, _) = await AddRule("b.example.com");
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync($"/api/servers/{otherServer}/rules/{rule}/requests")).StatusCode);
        foreach (var query in new[] { "take=0", "take=501", "status=6xx", "status=40", "status=4x1", "status=abc", "before=0" })
        {
            var r = await _admin.GetAsync($"/api/servers/{server}/rules/{rule}/requests?{query}");
            Assert.True(r.StatusCode == HttpStatusCode.BadRequest, query);
        }
    }

    [Fact]
    public async Task AHostThatSkipsTheAccessLog_SaysItsRequestsAreNotRecorded()
    {
        var (server, rule) = await AddRule("quiet.example.com", skipAccessLog: true);
        var body = await Get($"/api/servers/{server}/rules/{rule}/requests");
        Assert.Contains("skips the access log", (string?)body["message"]);
    }

    [Fact]
    public async Task TheRequests_NeedRecentRequestsRead()
    {
        var (server, rule) = await AddRule("a.example.com");
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var viewer = new User { Name = "Viewer", Email = "viewer@example.com", Role = Role.Viewer };
        var editor = new User { Name = "Editor", Email = "editor@example.com", Role = Role.Editor };
        db.Users.AddRange(viewer, editor);
        db.SaveChanges();
        var admin = db.Users.First(u => u.Role == Role.Admin);
        var keys = scope.ServiceProvider.GetRequiredService<IApiKeyService>();
        var expires = _factory.Clock.GetUtcNow().AddDays(30);
        var cases = new[]
        {
            (viewer.Id, (Permission[]?)null, HttpStatusCode.Forbidden),
            (admin.Id, Enum.GetValues<Permission>().Where(p => p != Permission.RecentRequestsRead).ToArray(), HttpStatusCode.Forbidden),
            (editor.Id, null, HttpStatusCode.OK),
        };
        foreach (var (owner, scopes, expected) in cases)
        {
            var c = _factory.CreateClient();
            c.DefaultRequestHeaders.Add("X-Api-Key", (await keys.CreateAsync(owner, "requests", expires, scopes)).PlaintextToken);
            Assert.Equal(expected, (await c.GetAsync($"/api/servers/{server}/rules/{rule}/requests")).StatusCode);
        }
    }
}

public class CaddyOutputTests
{
    private sealed class RecordingLogger : ILogger<CaddyProxyController>
    {
        public List<string> Lines { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Add(formatter(state, exception));
    }

    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new Xunit.Sdk.XunitException("No HTTP expected.");
    }

    [Fact]
    public void AccessEntries_GoToTheStoreOnly_AndOtherLinesAreLogged()
    {
        var clock = new ManualClock(new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero));
        var recent = new RecentRequests(clock);
        var logger = new RecordingLogger();
        using var c = new CaddyProxyController(Options.Create(new ProxyOptions()), new NoHttp(), logger, clock, new TrafficRecorder(),
            SecretRedactor.None, new CaddyCertificateLog(SecretRedactor.None, clock), recent);
        var rule = Guid.NewGuid();

        c.OnCaddyOutput(RecentRequestsTests.Line(rule, clock.GetUtcNow(), uri: "/a?k=query-secret"));
        c.OnCaddyOutput(RecentRequestsTests.Line(null, clock.GetUtcNow(), uri: "/nop?k=query-secret"));
        c.OnCaddyOutput("""{"level":"info","logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"a.example.com"}""");

        Assert.Equal("/a", Assert.Single(recent.Query(rule, 50, _ => true, null).Requests).Path);
        Assert.Contains("tls.obtain", Assert.Single(logger.Lines));
    }
}
