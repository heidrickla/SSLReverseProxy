using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SslReverseProxy.Api.Alerts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Alerts;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

public class CertificateAlertTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

    private static Certificate Cert(CertificateStatus status, int daysLeft = 10, string? error = null) => new()
    {
        Domain = "a.example.com", Status = status, ExpiresAt = Now.AddDays(daysLeft), LastError = error,
    };

    private static string? Step(Certificate c, CertificateStatus status, DateTimeOffset? expires = null)
    {
        c.Status = status;
        if (expires is not null) c.ExpiresAt = expires;
        return CertificateAlerts.Evaluate(c, Now)?.Type;
    }

    [Fact]
    public void Expiring_AlertsOncePerExpiryDate_ThroughABriefMiss()
    {
        var c = Cert(CertificateStatus.Valid);
        Assert.Null(Step(c, CertificateStatus.Valid));
        Assert.Equal(AlertTypes.CertificateExpiring, Step(c, CertificateStatus.Expiring));
        Assert.Null(Step(c, CertificateStatus.Expiring));
        Assert.Null(Step(c, CertificateStatus.Issuing));
        Assert.Null(Step(c, CertificateStatus.Expiring));
        Assert.Equal(AlertTypes.CertificateExpired, Step(c, CertificateStatus.Expired));
        Assert.Null(Step(c, CertificateStatus.Expired));
    }

    [Fact]
    public void AnotherExpiryDate_AlertsAgain()
    {
        var c = Cert(CertificateStatus.Expiring);
        Assert.Equal(AlertTypes.CertificateExpiring, Step(c, CertificateStatus.Expiring));
        Assert.Equal(AlertTypes.CertificateExpiring, Step(c, CertificateStatus.Expiring, Now.AddDays(5)));
    }

    [Fact]
    public void Failed_AlertsOnceUntilValid()
    {
        var c = Cert(CertificateStatus.Failed, error: "HTTP 403");
        var alert = CertificateAlerts.Evaluate(c, Now);
        Assert.Equal((AlertTypes.CertificateFailed, AlertSeverity.Warning), (alert!.Type, alert.Severity));
        Assert.Contains("HTTP 403", alert.Message);
        Assert.Null(Step(c, CertificateStatus.Issuing));
        Assert.Null(Step(c, CertificateStatus.Failed));
        Assert.Null(Step(c, CertificateStatus.Valid));
        Assert.Equal(AlertTypes.CertificateFailed, Step(c, CertificateStatus.Failed));
    }

    [Fact]
    public void Messages_NameTheCertificateAndItsExpiry()
    {
        var alert = CertificateAlerts.Evaluate(Cert(CertificateStatus.Expiring, daysLeft: 9), Now)!;
        Assert.Equal("Certificate expiring: a.example.com", alert.Title);
        Assert.Equal($"a.example.com expires {Now.AddDays(9):yyyy-MM-dd HH:mm} UTC, 9 days from now.", alert.Message);
        Assert.Equal(AlertSeverity.Critical, CertificateAlerts.Evaluate(Cert(CertificateStatus.Expired, -1), Now)!.Severity);
    }
}

public class ServerAlertTrackerTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Id = Guid.NewGuid();
    private static readonly ServerHealth Error = new(ServerHealthStatus.Error, 1, 3, Now);
    private static readonly ServerHealth Active = new(ServerHealthStatus.Active, 3, 3, Now);
    private static readonly ServerHealth Inactive = new(ServerHealthStatus.Inactive, 0, 0, Now);

    [Fact]
    public void Down_AfterTheConfiguredFailingChecks_ThenUpOnce()
    {
        var t = new ServerAlertTracker(2);
        Assert.Null(t.Observe(Id, "web", Error, Now));
        var down = t.Observe(Id, "web", Error, Now)!;
        Assert.Equal((AlertTypes.ServerDown, AlertSeverity.Critical, "web"), (down.Type, down.Severity, down.Subject));
        Assert.Equal("2 of 3 upstreams of web do not answer.", down.Message);
        Assert.Null(t.Observe(Id, "web", Error, Now));
        Assert.Equal(AlertTypes.ServerUp, t.Observe(Id, "web", Active, Now)!.Type);
        Assert.Null(t.Observe(Id, "web", Active, Now));
    }

    [Fact]
    public void OneFailingCheck_BetweenGoodOnes_DoesNotAlert()
    {
        var t = new ServerAlertTracker(2);
        Assert.Null(t.Observe(Id, "web", Error, Now));
        Assert.Null(t.Observe(Id, "web", Active, Now));
        Assert.Null(t.Observe(Id, "web", Error, Now));
    }

    [Fact]
    public void Inactive_AndForget_EndADownStateSilently()
    {
        var t = new ServerAlertTracker(1);
        Assert.NotNull(t.Observe(Id, "web", Error, Now));
        Assert.Null(t.Observe(Id, "web", Inactive, Now));
        Assert.Null(t.Observe(Id, "web", Active, Now));

        Assert.NotNull(t.Observe(Id, "web", Error, Now));
        t.Forget(Id);
        Assert.Null(t.Observe(Id, "web", Active, Now));
    }
}

public class AlertTargetTests
{
    private static AlertTarget One(AlertTargetOptions t) => AlertTargets.From(new AlertOptions { Targets = [t] }).Single();

    private static AlertTargetOptions Hook(string url = "https://ha.example.com/api/webhook/abc123") =>
        new() { Name = "ha", Kind = "webhook", Url = url };

    [Fact]
    public void ValidTargets_AreUsable()
    {
        var ha = One(Hook());
        Assert.True(ha.Usable);
        Assert.True(ha.Wants(AlertTypes.ServerDown));
        var ntfy = One(new AlertTargetOptions
        {
            Name = "phone", Kind = "NTFY", Url = "https://ntfy.sh/sslrp-alerts", Token = "tk_abc", Events = ["server.down"],
        });
        Assert.Equal(("ntfy", true), (ntfy.Kind, ntfy.Usable));
        Assert.True(ntfy.Wants(AlertTypes.ServerDown));
        Assert.False(ntfy.Wants(AlertTypes.ServerUp));
    }

    [Theory]
    [InlineData("", "webhook", "https://h.example/x", null, null, "Name must be")]
    [InlineData("ha", "email", "https://h.example/x", null, null, "Kind must be")]
    [InlineData("ha", "webhook", "ftp://h.example/x", null, null, "absolute http or https")]
    [InlineData("ha", "webhook", "/relative", null, null, "absolute http or https")]
    [InlineData("ha", "webhook", "https://user:pw@h.example/x", null, null, "user name or password")]
    [InlineData("ha", "ntfy", "https://ntfy.sh/", null, null, "ends in the topic")]
    [InlineData("ha", "ntfy", "https://ntfy.sh/topic?x=1", null, null, "ends in the topic")]
    [InlineData("ha", "webhook", "https://h.example/x", "has space", null, "printable ASCII")]
    [InlineData("ha", "webhook", "https://h.example/x", null, "server.sideways", "Unknown event 'server.sideways'")]
    public void Problems_AreNamed_AndTheTargetIsNotUsed(string name, string kind, string url, string? token, string? evt, string problem)
    {
        var t = One(new AlertTargetOptions { Name = name, Kind = kind, Url = url, Token = token, Events = evt is null ? [] : [evt] });
        Assert.False(t.Usable);
        Assert.False(t.Wants(AlertTypes.ServerDown));
        Assert.Null(t.Url);
        Assert.Contains(problem, t.Problem);
        Assert.DoesNotContain("pw", t.Problem);
    }

    [Fact]
    public void DuplicateNames_KeepTheFirst()
    {
        var targets = AlertTargets.From(new AlertOptions { Targets = [Hook(), Hook()] });
        Assert.True(targets[0].Usable);
        Assert.Equal("Another target has this name.", targets[1].Problem);
    }
}

public class AlertRequestTests
{
    private static readonly Alert Down = new(AlertTypes.ServerDown, AlertSeverity.Critical, "web", "Server down: web",
        "1 of 2 upstreams of web do not answer.", new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero));

    private static AlertTarget Target(string kind, string url, string? token = null) =>
        AlertTargets.From(new AlertOptions { Targets = [new() { Name = "t", Kind = kind, Url = url, Token = token }] }).Single();

    [Fact]
    public async Task Webhook_PostsTheAlertAsJson_WithTheBearerToken()
    {
        using var request = AlertRequests.Build(Target("webhook", "https://ha.example.com/api/webhook/abc", "s3cret-token"), Down);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://ha.example.com/api/webhook/abc", request.RequestUri!.ToString());
        Assert.Equal("Bearer s3cret-token", request.Headers.Authorization!.ToString());
        var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync())!;
        Assert.Equal("server.down", (string?)body["type"]);
        Assert.Equal("critical", (string?)body["severity"]);
        Assert.Equal("web", (string?)body["subject"]);
        Assert.Equal("Server down: web", (string?)body["title"]);
        Assert.Equal("2026-10-20T12:00:00.0000000+00:00", (string?)body["at"]);
    }

    [Theory]
    [InlineData("https://ntfy.sh/sslrp", "https://ntfy.sh/", "sslrp")]
    [InlineData("https://push.example.com/ntfy/sslrp", "https://push.example.com/ntfy/", "sslrp")]
    public async Task Ntfy_PublishesJsonToTheServerRoot(string url, string root, string topic)
    {
        using var request = AlertRequests.Build(Target("ntfy", url), Down);
        Assert.Equal(root, request.RequestUri!.ToString());
        Assert.Null(request.Headers.Authorization);
        var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync())!;
        Assert.Equal(topic, (string?)body["topic"]);
        Assert.Equal(5, (int)body["priority"]!);
        Assert.Equal("rotating_light", (string?)body["tags"]![0]);
        Assert.Equal("1 of 2 upstreams of web do not answer.", (string?)body["message"]);
    }
}

public class AlertSenderTests
{
    private static readonly Alert Down = new(AlertTypes.ServerDown, AlertSeverity.Critical, "web", "Server down: web", "m",
        DateTimeOffset.UnixEpoch);

    private const string Url = "https://ha.example.com/api/webhook/hook-secret-0123";
    private const string Token = "token-secret-4567";

    private static readonly AlertTarget Target =
        AlertTargets.From(new AlertOptions { Targets = [new() { Name = "ha", Kind = "webhook", Url = Url, Token = Token }] }).Single();

    private sealed class Handler(Func<int, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            respond(Interlocked.Increment(ref Calls), ct);
    }

    private sealed class Factory(HttpMessageHandler handler, TimeSpan? timeout = null) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { Timeout = timeout ?? AlertSender.RequestTimeout };
    }

    /// <summary>Fires every timer at once and records the delays asked for.</summary>
    private sealed class InstantTime : TimeProvider
    {
        public ConcurrentQueue<TimeSpan> Delays { get; } = new();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (dueTime != Timeout.InfiniteTimeSpan) Delays.Enqueue(dueTime);
            return System.CreateTimer(callback, state, TimeSpan.Zero, Timeout.InfiniteTimeSpan);
        }
    }

    private static (AlertSender Sender, Handler Handler, InstantTime Time, ListLogger<AlertSender> Log) Make(
        Func<int, CancellationToken, Task<HttpResponseMessage>> respond, TimeSpan? timeout = null)
    {
        var handler = new Handler(respond);
        var time = new InstantTime();
        var log = new ListLogger<AlertSender>();
        return (new AlertSender(new Factory(handler, timeout), time, log), handler, time, log);
    }

    private static Task<HttpResponseMessage> Status(HttpStatusCode code) => Task.FromResult(new HttpResponseMessage(code));

    [Fact]
    public async Task ServerErrors_AreRetriedWithBackoff()
    {
        var (sender, handler, time, _) = Make((n, _) => Status(n < 3 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK));
        var result = await sender.SendAsync(Target, Down, CancellationToken.None);
        Assert.Equal(new AlertDelivery("ha", true, 200, null, 3), result);
        Assert.Equal(3, handler.Calls);
        Assert.Equal([TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10)], time.Delays);
    }

    [Fact]
    public async Task ThreeFailures_GiveUp()
    {
        var (sender, handler, _, log) = Make((_, _) => Status(HttpStatusCode.BadGateway));
        var result = await sender.SendAsync(Target, Down, CancellationToken.None);
        Assert.Equal(new AlertDelivery("ha", false, 502, "HTTP 502", 3), result);
        Assert.Equal(3, handler.Calls);
        Assert.Contains(log.Messages, m => m.Contains("failed after 3 tries: HTTP 502"));
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Redirect)]
    public async Task OtherRefusals_AreNotRetried(HttpStatusCode code)
    {
        var (sender, handler, _, _) = Make((_, _) => Status(code));
        var result = await sender.SendAsync(Target, Down, CancellationToken.None);
        Assert.False(result.Delivered);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Timeouts_AndConnectionErrors_AreRetried_AndNamedByClass()
    {
        var (slow, slowHandler, _, _) = Make(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }, TimeSpan.FromMilliseconds(50));
        Assert.Equal(new AlertDelivery("ha", false, null, "timed out", 3), await slow.SendAsync(Target, Down, CancellationToken.None));
        Assert.Equal(3, slowHandler.Calls);

        var (refused, _, _, log) = Make((_, _) =>
            throw new HttpRequestException(HttpRequestError.ConnectionError, $"No connection to {Url}"));
        Assert.Equal("connection failed", (await refused.SendAsync(Target, Down, CancellationToken.None)).Error);
        Assert.DoesNotContain(log.Messages, m => m.Contains("ha.example.com"));
    }

    [Fact]
    public async Task UnusableTarget_IsNotCalled()
    {
        var bad = AlertTargets.From(new AlertOptions { Targets = [new() { Name = "x", Kind = "pager", Url = Url }] }).Single();
        var (sender, handler, _, _) = Make((_, _) => Status(HttpStatusCode.OK));
        var result = await sender.SendAsync(bad, Down, CancellationToken.None);
        Assert.Equal((false, 0), (result.Delivered, result.Attempts));
        Assert.Equal(0, handler.Calls);
    }
}

internal sealed class ListLogger<T> : ILogger<T>
{
    private readonly ConcurrentQueue<string> _messages = new();
    public IReadOnlyList<string> Messages => _messages.ToList();
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        _messages.Enqueue(formatter(state, exception) + (exception is null ? "" : " " + exception));
}

/// <summary>A local listener that records what the alert targets receive.</summary>
internal sealed class AlertListener : IAsyncDisposable
{
    private readonly WebApplication _app;
    public ConcurrentQueue<(string Path, string? Authorization, JsonNode Body)> Received { get; } = new();
    public string BaseUrl { get; }

    private AlertListener(WebApplication app, string baseUrl)
    {
        _app = app;
        BaseUrl = baseUrl;
    }

    public static async Task<AlertListener> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        var app = builder.Build();
        AlertListener? self = null;
        app.MapPost("/{**path}", async (HttpContext ctx) =>
        {
            var body = await JsonNode.ParseAsync(ctx.Request.Body);
            self!.Received.Enqueue(("/" + ctx.Request.RouteValues["path"], ctx.Request.Headers.Authorization.ToString(), body!));
            return Results.Ok();
        });
        await app.StartAsync();
        var address = app.Urls.First();
        self = new AlertListener(app, address);
        return self;
    }

    public async Task<(string Path, string? Authorization, JsonNode Body)> WaitForAsync(Func<JsonNode, bool> match, int seconds = 15)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            var hit = Received.FirstOrDefault(r => match(r.Body));
            if (hit.Body is not null) return hit;
            await Task.Delay(50);
        }
        throw new Xunit.Sdk.XunitException($"No matching alert arrived; got {Received.Count}.");
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

/// <summary>The alert endpoints and the server monitor's alerts, through the real HTTP client against a local listener.</summary>
public class AlertEndpointTests : IAsyncLifetime
{
    private const string HookSecret = "hook-secret-89abcdef";
    private const string Token = "bearer-secret-01234567";
    private AlertListener _listener = null!;
    private AlertFactory _factory = null!;

    public async Task InitializeAsync()
    {
        _listener = await AlertListener.StartAsync();
        _factory = new AlertFactory(_listener.BaseUrl, HookSecret, Token);
    }

    public async Task DisposeAsync()
    {
        _factory.Dispose();
        await _listener.DisposeAsync();
    }

    [Fact]
    public async Task List_NamesTargets_WithoutUrlsOrTokens()
    {
        var raw = await _factory.Client(Role.Admin).GetStringAsync("/api/alerts");
        Assert.DoesNotContain(HookSecret, raw);
        Assert.DoesNotContain(Token, raw);
        var body = JsonNode.Parse(raw)!;
        var targets = body["targets"]!.AsArray();
        Assert.Equal(["ha:webhook:", "broken:email:Kind must be webhook or ntfy."],
            targets.Select(t => $"{t!["name"]}:{t["kind"]}:{t["problem"]}"));
        Assert.Contains("server.down", body["events"]!.AsArray().Select(e => (string?)e));
    }

    [Fact]
    public async Task Test_ReachesTheTarget_IsAudited_AndLogsNoSecret()
    {
        var response = await _factory.Client(Role.Admin).PostAsJsonAsync("/api/alerts/test", new { target = "ha" });
        response.EnsureSuccessStatusCode();
        var result = (await response.Content.ReadFromJsonAsync<JsonArray>())!.Single()!;
        Assert.Equal((true, 200), ((bool)result["delivered"]!, (int)result["status"]!));

        var got = await _listener.WaitForAsync(b => (string?)b["type"] == "test");
        Assert.Equal($"/api/webhook/{HookSecret}", got.Path);
        Assert.Equal($"Bearer {Token}", got.Authorization);
        Assert.Equal("ha", (string?)got.Body["subject"]);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            Assert.True(await db.AuditEntries.AnyAsync(a => a.Action == "Test Alert" && a.TargetName == "ha" && a.Success));
        }
        Assert.Contains(_factory.Logs.Messages, m => m.Contains("Alert test for ha sent to ha: HTTP 200."));
        Assert.DoesNotContain(_factory.Logs.Messages, m => m.Contains(HookSecret) || m.Contains(Token));
    }

    [Fact]
    public async Task Test_RefusesUnknownTargets_AndNonAdmins()
    {
        var admin = _factory.Client(Role.Admin);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsJsonAsync("/api/alerts/test", new { target = "nope" })).StatusCode);
        var broken = (await (await admin.PostAsJsonAsync("/api/alerts/test", new { target = "broken" }))
            .Content.ReadFromJsonAsync<JsonArray>())!.Single()!;
        Assert.Equal((false, "Kind must be webhook or ntfy."), ((bool)broken["delivered"]!, (string?)broken["error"]));

        var editor = _factory.Client(Role.Editor);
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.GetAsync("/api/alerts")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.PostAsJsonAsync("/api/alerts/test", new { target = "ha" })).StatusCode);
    }

    [Fact]
    public async Task ServerMonitor_SendsDownToTheTarget()
    {
        _ = _factory.Server;
        var got = await _listener.WaitForAsync(b => (string?)b["type"] == "server.down" && (string?)b["subject"] == "Internal Services");
        Assert.Equal("Server down: Internal Services", (string?)got.Body["title"]);
        Assert.Equal("critical", (string?)got.Body["severity"]);
    }

    private sealed class DownOnPort9 : IUpstreamHealthChecker
    {
        public Task<UpstreamHealth> CheckAsync(string upstreamUrl, CancellationToken ct = default) =>
            Task.FromResult(upstreamUrl.EndsWith(":9", StringComparison.Ordinal)
                ? new UpstreamHealth(false, null, 1, "Connection refused")
                : new UpstreamHealth(true, 200, 1, null));
    }

    private sealed class CapturingProvider(ListLogger<object> sink) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => sink;
        public void Dispose() { }
    }

    private sealed class AlertFactory(string listener, string hookSecret, string token) : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-alerts-{Guid.NewGuid():N}.db");
        public ListLogger<object> Logs { get; } = new();

        public HttpClient Client(Role role)
        {
            using var scope = Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var user = db.Users.FirstOrDefault(u => u.Role == role);
            if (user is null)
            {
                user = new User { Name = $"{role} user", Email = $"{role}@example.com", Role = role };
                db.Users.Add(user);
                db.SaveChanges();
            }
            var key = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
                .CreateAsync(user.Id, "alert-tests", null).GetAwaiter().GetResult().PlaintextToken;
            var client = CreateClient();
            client.DefaultRequestHeaders.Add("X-Api-Key", key);
            return client;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureLogging(l => l.SetMinimumLevel(LogLevel.Trace).AddProvider(new CapturingProvider(Logs)));
            builder.ConfigureTestServices(s =>
            {
                s.RemoveAll<IUpstreamHealthChecker>();
                s.AddScoped<IUpstreamHealthChecker, DownOnPort9>();
            });
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureHostConfiguration(cfg =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                    ["Seed:Demo"] = "true",
                    ["Seed:DemoUpstreamBase"] = "http://127.0.0.1:5195",
                    ["Proxy:ServerHealthIntervalSeconds"] = "1",
                    ["Proxy:CertificateCheckSeconds"] = "0",
                    ["Alerts:ServerDownChecks"] = "2",
                    ["Alerts:Targets:0:Name"] = "ha",
                    ["Alerts:Targets:0:Kind"] = "webhook",
                    ["Alerts:Targets:0:Url"] = $"{listener}/api/webhook/{hookSecret}",
                    ["Alerts:Targets:0:Token"] = token,
                    ["Alerts:Targets:1:Name"] = "broken",
                    ["Alerts:Targets:1:Kind"] = "email",
                    ["Alerts:Targets:1:Url"] = $"{listener}/x",
                }));
            return base.CreateHost(builder);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
        }
    }
}

internal sealed class RecordingAlerts : IAlertSink
{
    private readonly ConcurrentQueue<Alert> _raised = new();
    public IReadOnlyList<Alert> Raised => _raised.ToList();
    public void Raise(Alert alert) => _raised.Enqueue(alert);
}
