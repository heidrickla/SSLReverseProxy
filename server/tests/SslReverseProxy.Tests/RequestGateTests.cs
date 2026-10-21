using System.Collections.Concurrent;
using System.Data.Common;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Security;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>
/// State-changing requests run one at a time from before authentication through their audit row, so a request that
/// changes who may do what lands wholly before or wholly after each of them.
/// </summary>
public class RequestGateTests
{
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(1);

    private static async Task<bool> FinishesWithin(Task t, TimeSpan wait) => await Task.WhenAny(t, Task.Delay(wait)) == t;

    private static Guid NewUser(PasskeyFactory f, Role role) => f.Db(db =>
    {
        var u = new User { Name = $"{role} {Guid.NewGuid():N}", Email = $"{Guid.NewGuid():N}@example.com", Role = role };
        db.Users.Add(u);
        db.SaveChanges();
        return u.Id;
    });

    private static async Task<(HttpClient Client, Guid KeyId)> Key(PasskeyFactory f, Guid owner, params string[] scopes)
    {
        var (admin, _) = f.WithKey();
        var r = await admin.PostAsJsonAsync("/api/apikeys",
            new { userId = owner, name = "caller", lifetimeDays = 30, scopes = scopes.Length == 0 ? null : scopes });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        var body = JsonNode.Parse(await r.Content.ReadAsStringAsync())!;
        var client = f.Anonymous();
        client.DefaultRequestHeaders.Add("X-Api-Key", (string)body["token"]!);
        return (client, Guid.Parse((string)body["id"]!));
    }

    // The latest audit row for the action.
    private static long Order(PasskeyFactory f, string action) =>
        f.Db(db => db.AuditEntries.Where(a => a.Action == action).Max(a => a.Id));

    private static string Path(RoutePattern pattern) => "/" + string.Join("/", pattern.PathSegments.Select(segment =>
        string.Concat(segment.Parts.Select(part => part switch
        {
            RoutePatternLiteralPart literal => literal.Content,
            RoutePatternSeparatorPart separator => separator.Content,
            RoutePatternParameterPart p when p.ParameterPolicies.Any(x => x.Content == "guid") => Guid.Empty.ToString(),
            RoutePatternParameterPart p when p.ParameterPolicies.Any(x => x.Content is "long" or "int") => "0",
            _ => "x",
        }))));

    private static string? GatedMethod(RouteEndpoint e)
    {
        var methods = e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? [];
        return methods.FirstOrDefault(m => !HttpMethods.IsGet(m) && !HttpMethods.IsHead(m) && !HttpMethods.IsOptions(m))
            ?? (e.Metadata.GetMetadata<ChangesState>() is not null ? HttpMethods.Get : null);
    }

    [Fact]
    public async Task EveryStateChangingRouteWaitsForTheGate_WhileReadsDoNot()
    {
        using var f = new PasskeyFactory();
        var (admin, _) = f.WithKey();
        var anonymous = f.Anonymous();
        var routes = f.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()
            .Select(e => (Method: GatedMethod(e), Path: Path(e.RoutePattern)))
            .Where(r => r.Method is not null)
            .ToList();
        Assert.True(routes.Count >= 30, $"found {routes.Count} state-changing routes");
        Assert.Equal(3, routes.Count(r => r.Method == HttpMethods.Get)); // backup export, instance, bootstrap key

        var gate = f.Services.GetRequiredService<RequestGate>();
        await gate.WaitAsync(CancellationToken.None);
        List<Task<HttpResponseMessage>> sent;
        try
        {
            sent = routes.Select(r => anonymous.SendAsync(new HttpRequestMessage(new HttpMethod(r.Method!), r.Path)
            {
                Content = r.Method == HttpMethods.Get ? null : JsonContent.Create(new { }),
            })).ToList();
            var read = admin.GetAsync("/api/whoami");
            Assert.True(await FinishesWithin(read, TimeSpan.FromSeconds(10)), "a read waited for the gate");
            Assert.Equal(HttpStatusCode.OK, (await read).StatusCode);
            await Task.Delay(Settle);
            Assert.Empty(routes.Zip(sent).Where(x => x.Second.IsCompleted).Select(x => $"{x.First.Method} {x.First.Path}"));
        }
        finally
        {
            gate.Release();
        }
        await Task.WhenAll(sent).WaitAsync(TimeSpan.FromSeconds(60));
    }

    [Fact]
    public async Task TheGateIsTakenBeforeAuthentication()
    {
        using var f = new PasskeyFactory();
        var (admin, userId) = f.WithKey();
        DateTimeOffset? LastUsed() => f.Db(db => db.ApiKeys.Single(k => k.UserId == userId && k.Name == "passkey-tests").LastUsedAt);

        var gate = f.Services.GetRequiredService<RequestGate>();
        await gate.WaitAsync(CancellationToken.None);
        Task<HttpResponseMessage> post;
        try
        {
            post = admin.PostAsJsonAsync("/api/users", new { name = "", email = "" });
            await Task.Delay(Settle);
            Assert.False(post.IsCompleted);
            Assert.Null(LastUsed()); // authentication records the key's use, and it has not run
        }
        finally
        {
            gate.Release();
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await post).StatusCode);
        Assert.NotNull(LastUsed());
    }

    [Fact]
    public async Task RevokingTheCallerDuringItsCreate_LandsAfterTheKeyAndItsAuditRow()
    {
        var step = new StepGate();
        using var f = new PasskeyFactory(interceptor: step);
        var (admin, _) = f.WithKey();
        var owner = NewUser(f, Role.Admin);
        var (caller, callerKey) = await Key(f, NewUser(f, Role.Admin), "ApiKeyManage", "ServerRead");

        step.HoldUserRead(1); // the endpoint's read of the owner
        var create = caller.PostAsJsonAsync("/api/apikeys",
            new { userId = owner, name = "racing", lifetimeDays = 30, scopes = new[] { "ServerRead" } });
        await step.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        var revoke = admin.PostAsync($"/api/apikeys/{callerKey}/revoke", null);
        var revokedFirst = await FinishesWithin(revoke, Settle);
        step.Release();

        Assert.False(revokedFirst, "the caller's key was revoked while its request was under way");
        Assert.Equal(HttpStatusCode.Created, (await create).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await revoke).StatusCode);
        Assert.True(Order(f, "Create API Key") < Order(f, "Revoke API Key"));
    }

    [Fact]
    public async Task DemotingTheOwnerDuringAFullAccessCreate_LandsAfterTheKey()
    {
        var step = new StepGate();
        using var f = new PasskeyFactory(interceptor: step);
        var (admin, _) = f.WithKey();
        var owner = NewUser(f, Role.Admin);
        var (caller, _) = await Key(f, NewUser(f, Role.Admin), "ApiKeyManage", "ServerRead");

        step.HoldUserRead(1); // the endpoint's read of the owner, before full access is resolved
        var create = caller.PostAsJsonAsync("/api/apikeys", new { userId = owner, name = "racing", lifetimeDays = 30 });
        await step.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        var demote = admin.PutAsJsonAsync($"/api/users/{owner}", new { name = "Owner", role = "Editor", isActive = true });
        var demotedFirst = await FinishesWithin(demote, Settle);
        step.Release();

        Assert.False(demotedFirst, "the owner was demoted while a key was being issued to it");
        var created = await create;
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var scopes = JsonNode.Parse(await created.Content.ReadAsStringAsync())!["scopes"]!.AsArray().Select(n => (string)n!);
        Assert.Equal(new[] { "ApiKeyManage", "ServerRead" }, scopes.Order().ToArray());
        Assert.Equal(HttpStatusCode.OK, (await demote).StatusCode);
        Assert.Equal(Role.Editor, f.Db(db => db.Users.Single(u => u.Id == owner).Role));
    }

    [Fact]
    public async Task AUserChangingItsOwnRole_DoesNotUndoAConcurrentDemotion()
    {
        var step = new StepGate();
        using var f = new PasskeyFactory(interceptor: step);
        var (admin, _) = f.WithKey();
        var user = NewUser(f, Role.Admin);
        var (self, _) = await Key(f, user, "ServerRead", "UserWrite");

        // The last-admin count, which runs after the endpoint loads the user and before it saves.
        step.HoldCommand(sql => sql.Contains("COUNT(*)") && sql.Contains("FROM \"Users\""));
        var own = self.PutAsJsonAsync($"/api/users/{user}", new { name = "Self", role = "Editor", isActive = true });
        await step.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        var demote = admin.PutAsJsonAsync($"/api/users/{user}", new { name = "Self", role = "Viewer", isActive = true });
        var demotedFirst = await FinishesWithin(demote, Settle);
        step.Release();

        Assert.False(demotedFirst, "the user was demoted while its own change was under way");
        Assert.Equal(HttpStatusCode.OK, (await own).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await demote).StatusCode);
        Assert.Equal(Role.Viewer, f.Db(db => db.Users.Single(u => u.Id == user).Role));
    }

    [Fact]
    public async Task RevokingTheCallerDuringAPasskeyRegistration_LandsAfterThePasskeyAndItsAuditRow()
    {
        var step = new StepGate();
        using var f = new PasskeyFactory(interceptor: step);
        var (admin, _) = f.WithKey();
        var (caller, callerKey) = await Key(f, NewUser(f, Role.Admin));
        var auth = new SoftAuthenticator();
        var begin = JsonNode.Parse(await (await caller.PostAsync("/api/passkeys/options", null)).Content.ReadAsStringAsync())!;

        // The credential id's uniqueness check, which runs after verification and before the insert.
        step.HoldCommand(sql => sql.Contains("FROM \"Passkeys\"") && sql.Contains("\"CredentialId\" ="));
        var register = caller.PostAsJsonAsync("/api/passkeys", new JsonObject
        {
            ["handle"] = (string)begin["handle"]!, ["name"] = "Laptop", ["response"] = auth.Create(begin["options"]!),
        });
        await step.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        var revoke = admin.PostAsync($"/api/apikeys/{callerKey}/revoke", null);
        var revokedFirst = await FinishesWithin(revoke, Settle);
        step.Release();

        Assert.False(revokedFirst, "the caller's key was revoked while its registration was under way");
        Assert.Equal(HttpStatusCode.Created, (await register).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await revoke).StatusCode);
        Assert.True(Order(f, "Register Passkey") < Order(f, "Revoke API Key"));
    }

    [Fact]
    public async Task AChangeStalledPastTheDeadline_IsStopped_AndTheNextChangeRuns()
    {
        var step = new StepGate();
        using var f = new PasskeyFactory(interceptor: step,
            settings: new Dictionary<string, string?> { ["Security:StateChangeSeconds"] = "1" });
        var (admin, _) = f.WithKey();
        var owner = NewUser(f, Role.Admin);

        step.HoldUserRead(1); // the create's read of the owner, never released
        var create = admin.PostAsJsonAsync("/api/apikeys", new { userId = owner, name = "stalled", lifetimeDays = 30 });
        Assert.True(await FinishesWithin(create, TimeSpan.FromSeconds(15)), "a stalled change held the gate");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await create).StatusCode);
        Assert.Equal(0, f.Db(db => db.ApiKeys.Count(k => k.UserId == owner)));
        var next = admin.PostAsJsonAsync("/api/users", new { name = "", email = "" });
        Assert.True(await FinishesWithin(next, TimeSpan.FromSeconds(10)), "the gate stayed with the stopped change");
        Assert.Equal(HttpStatusCode.BadRequest, (await next).StatusCode);
    }

    [Fact]
    public async Task AChangeStuckPastTheDeadline_LosesTheGateThen_AndChangesNothingAfter()
    {
        var step = new StepGate { IgnoresCancellation = true };
        using var f = new PasskeyFactory(interceptor: step,
            settings: new Dictionary<string, string?> { ["Security:StateChangeSeconds"] = "1" });
        var (admin, _) = f.WithKey();
        var owner = NewUser(f, Role.Admin);

        step.HoldUserRead(1); // the create's read of the owner, held through the deadline
        var create = admin.PostAsJsonAsync("/api/apikeys", new { userId = owner, name = "stuck", lifetimeDays = 30 });
        await step.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        var next = admin.PostAsJsonAsync("/api/users", new { name = "", email = "" });
        Assert.True(await FinishesWithin(next, TimeSpan.FromSeconds(10)), "the gate stayed with a change stuck past its deadline");
        Assert.Equal(HttpStatusCode.BadRequest, (await next).StatusCode);
        Assert.False(create.IsCompleted);

        step.Release();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await create).StatusCode);
        Assert.Equal(0, f.Db(db => db.ApiKeys.Count(k => k.UserId == owner)));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("86401")]
    [InlineData("2147483647")]
    public void ADeadlineOutOfRange_StopsStartup(string seconds)
    {
        using var f = new PasskeyFactory(settings: new Dictionary<string, string?> { ["Security:StateChangeSeconds"] = seconds });
        var e = Assert.ThrowsAny<Exception>(() => f.CreateClient());
        Assert.Contains("Security:StateChangeSeconds", RequestWriteGuardTests.Messages(e));
    }

    [Fact]
    public async Task AnOversizedBody_IsRefusedBeforeAuthentication()
    {
        using var f = new PasskeyFactory();
        var anonymous = f.Anonymous();
        var big = new byte[RequestGate.DefaultBodyLimit + 1];
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge,
            (await anonymous.PostAsync("/api/servers", new ByteArrayContent(big))).StatusCode);

        // The backup import declares a larger limit.
        var (admin, _) = f.WithKey();
        var backup = Encoding.UTF8.GetBytes(new string(' ', 3 * 512 * 1024) + "{}");
        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PostAsync("/api/backup/import/dry-run", new ByteArrayContent(backup))).StatusCode);
    }

    [Fact]
    public async Task TheAppRefusesAWriteFromARequestOutsideTheGate()
    {
        using var f = new PasskeyFactory();
        using var app = f.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddTransient<IStartupFilter, WriteProbe>()));
        var client = app.CreateClient();
        int Users() { using var scope = app.Services.CreateScope(); return scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.Count(); }
        var before = Users();

        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync(WriteProbe.Ungated, null)).StatusCode);
        Assert.Equal(before, Users());
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync(WriteProbe.Gated, null)).StatusCode);
        Assert.Equal(before + 1, Users());
    }

    // Writes a user ahead of the app's own pipeline, with and without the gate's middleware in front.
    private sealed class WriteProbe : IStartupFilter
    {
        public const string Ungated = "/test/ungated-write";
        public const string Gated = "/test/gated-write";

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Map(Ungated, b => b.Run(Write));
            app.Map(Gated, b =>
            {
                b.UseMiddleware<RequestGateMiddleware>();
                b.Run(Write);
            });
            next(app);
        };

        private static async Task Write(HttpContext ctx)
        {
            var db = ctx.RequestServices.GetRequiredService<AppDbContext>();
            db.Users.Add(new User { Name = "probe", Email = $"{Guid.NewGuid():N}@example.com", Role = Role.Viewer });
            try
            {
                await db.SaveChangesAsync();
                ctx.Response.StatusCode = StatusCodes.Status200OK;
            }
            catch (Exception e) when (RequestWriteGuardTests.Messages(e).Contains("outside the request gate"))
            {
                ctx.Response.StatusCode = StatusCodes.Status409Conflict;
            }
        }
    }
}

public class RequestWriteGuardTests : IDisposable
{
    private readonly SqliteConnection _conn = new("Filename=:memory:");
    private readonly HttpContextAccessor _accessor = new();
    private readonly DbContextOptions<AppDbContext> _options;

    public RequestWriteGuardTests()
    {
        _conn.Open();
        _options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_conn)
            .AddInterceptors(new RequestWriteGuard(_accessor)).Options;
        using var db = new AppDbContext(_options);
        db.Database.EnsureCreated();
    }

    public void Dispose() => _conn.Dispose();

    internal static string Messages(Exception e) => e.InnerException is null ? e.Message : e.Message + " " + Messages(e.InnerException);

    private async Task AddUser()
    {
        await using var db = new AppDbContext(_options);
        db.Users.Add(new User { Name = "u", Email = $"{Guid.NewGuid():N}@example.com", Role = Role.Viewer });
        await db.SaveChangesAsync();
    }

    private async Task<int> Users()
    {
        await using var db = new AppDbContext(_options);
        return await db.Users.CountAsync();
    }

    private async Task Refused()
    {
        var e = await Assert.ThrowsAnyAsync<Exception>(AddUser);
        Assert.Contains("outside the request gate", Messages(e));
    }

    private static DefaultHttpContext Request(string method) => new() { Request = { Method = method, Path = "/api/x" } };

    private static DefaultHttpContext WithProblems(DefaultHttpContext ctx)
    {
        ctx.RequestServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
        return ctx;
    }

    private static RequestGateMiddleware Gated(RequestDelegate next, RequestGate gate, int seconds = 120) =>
        new(next, gate, new SecurityOptions { StateChangeSeconds = seconds });

    [Fact]
    public async Task WorkOutsideARequest_Writes()
    {
        await AddUser();
        Assert.Equal(1, await Users());
    }

    [Fact]
    public async Task ARequestOutsideTheGate_ReadsButCannotWrite()
    {
        _accessor.HttpContext = Request("POST");
        Assert.Equal(0, await Users());
        await Refused();
        _accessor.HttpContext = null;
        Assert.Equal(0, await Users());
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public async Task AStateChangingRequest_WritesInsideTheGate_AndReleasesIt(string method)
    {
        var gate = new RequestGate();
        foreach (var _ in new[] { 1, 2 })
        {
            var ctx = Request(method);
            _accessor.HttpContext = ctx;
            var run = Gated(_ => AddUser(), gate).InvokeAsync(ctx);
            Assert.True(await FinishesWithin(run, TimeSpan.FromSeconds(10)), "the gate was not released");
            Assert.False(RequestGate.Holds(ctx));
        }
        _accessor.HttpContext = null;
        Assert.Equal(2, await Users());
    }

    [Fact]
    public async Task AnUploadInProgressDoesNotHoldTheGate()
    {
        var gate = new RequestGate();
        var upload = new HeldStream();
        var uploading = Request("POST");
        uploading.Request.Body = upload;
        var ran = false;
        var first = Gated(_ => { ran = true; return Task.CompletedTask; }, gate).InvokeAsync(uploading);
        await upload.Reached.WaitAsync(TimeSpan.FromSeconds(10));

        var next = Request("POST");
        Assert.True(await FinishesWithin(Gated(_ => Task.CompletedTask, gate).InvokeAsync(next), TimeSpan.FromSeconds(10)),
            "a request waited for another's upload");
        Assert.False(ran);
        upload.Release();
        await first.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(ran);
    }

    [Fact]
    public async Task ADownloadInProgressDoesNotHoldTheGate()
    {
        var gate = new RequestGate();
        var download = new HeldStream();
        var downloading = Request("POST");
        downloading.Features.Set<IHttpResponseBodyFeature>(new StreamResponseBodyFeature(download));
        var first = Gated(ctx => ctx.Response.WriteAsync("done", ctx.RequestAborted), gate).InvokeAsync(downloading);
        await download.Reached.WaitAsync(TimeSpan.FromSeconds(10));

        var next = Request("POST");
        Assert.True(await FinishesWithin(Gated(_ => Task.CompletedTask, gate).InvokeAsync(next), TimeSpan.FromSeconds(10)),
            "a request waited for another's download");
        download.Release();
        await first.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal("done", download.Written());
    }

    [Fact]
    public async Task WorkPastTheDeadlineIsStopped_AndReleasesTheGate()
    {
        var gate = new RequestGate();
        var stalled = Request("POST");
        stalled.RequestServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
        stalled.Response.Headers["X-Before"] = "kept";
        var body = new MemoryStream();
        stalled.Features.Set<IHttpResponseBodyFeature>(new StreamResponseBodyFeature(body));
        var run = Gated(async ctx =>
        {
            ctx.Response.Headers["X-Endpoint"] = "dropped";
            await ctx.Response.WriteAsync("partial", ctx.RequestAborted);
            await Task.Delay(Timeout.Infinite, ctx.RequestAborted);
        }, gate, seconds: 1).InvokeAsync(stalled);

        Assert.True(await FinishesWithin(run, TimeSpan.FromSeconds(10)), "stalled work was not stopped");
        await run;
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, stalled.Response.StatusCode);
        Assert.Equal("kept", stalled.Response.Headers["X-Before"]);
        Assert.False(stalled.Response.Headers.ContainsKey("X-Endpoint"));
        Assert.DoesNotContain("partial", Encoding.UTF8.GetString(body.ToArray()));
        Assert.True(await FinishesWithin(Gated(_ => Task.CompletedTask, gate).InvokeAsync(Request("POST")), TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task WorkStuckPastTheDeadline_LosesTheGateThen_AndItsLaterWriteIsRefused()
    {
        var gate = new RequestGate();
        var stuck = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ctx = WithProblems(Request("POST"));
        _accessor.HttpContext = ctx;
        var run = Gated(async _ =>
        {
            await AddUser();
            reached.TrySetResult();
            await stuck.Task; // does not watch the deadline
            await using var db = new AppDbContext(_options);
            await db.Database.ExecuteSqlRawAsync("DELETE FROM \"Users\"");
        }, gate, seconds: 1).InvokeAsync(ctx);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(await FinishesWithin(Gated(_ => Task.CompletedTask, gate).InvokeAsync(Request("POST")), TimeSpan.FromSeconds(10)),
            "the gate stayed with work stuck past its deadline");
        stuck.TrySetResult();
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, ctx.Response.StatusCode);
        _accessor.HttpContext = null;
        Assert.Equal(1, await Users());
    }

    [Fact]
    public async Task ACommitAfterTheTurnEnds_IsRefused()
    {
        var gate = new RequestGate();
        var stuck = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ctx = WithProblems(Request("POST"));
        _accessor.HttpContext = ctx;
        var run = Gated(async _ =>
        {
            await using var db = new AppDbContext(_options);
            await using var tx = await db.Database.BeginTransactionAsync();
            db.Users.Add(new User { Name = "u", Email = $"{Guid.NewGuid():N}@example.com", Role = Role.Viewer });
            await db.SaveChangesAsync();
            reached.TrySetResult();
            await stuck.Task; // does not watch the deadline
            await tx.CommitAsync();
        }, gate, seconds: 1).InvokeAsync(ctx);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(await FinishesWithin(Gated(_ => Task.CompletedTask, gate).InvokeAsync(Request("POST")), TimeSpan.FromSeconds(10)),
            "the gate stayed with work stuck past its deadline");
        stuck.TrySetResult();
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, ctx.Response.StatusCode);
        _accessor.HttpContext = null;
        Assert.Equal(0, await Users());
    }

    [Fact]
    public async Task AWriteUnderWayAtTheDeadline_KeepsTheGateUntilItFinishes()
    {
        var step = new StepGate { IgnoresCancellation = true };
        step.HoldCommand(sql => sql.Contains("INSERT INTO \"Users\""));
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_conn)
            .AddInterceptors(new RequestWriteGuard(_accessor), step).Options;
        var gate = new RequestGate();
        var ctx = WithProblems(Request("POST"));
        _accessor.HttpContext = ctx;
        var run = Gated(async _ =>
        {
            await using var db = new AppDbContext(options);
            db.Users.Add(new User { Name = "u", Email = $"{Guid.NewGuid():N}@example.com", Role = Role.Viewer });
            await db.SaveChangesAsync();
        }, gate, seconds: 1).InvokeAsync(ctx);
        await step.Reached.WaitAsync(TimeSpan.FromSeconds(10));

        var next = Gated(_ => Task.CompletedTask, gate).InvokeAsync(Request("POST"));
        Assert.False(await FinishesWithin(next, TimeSpan.FromSeconds(3)), "the gate was released while a write was under way");
        step.Release();
        Assert.True(await FinishesWithin(next, TimeSpan.FromSeconds(10)), "the gate stayed after the write finished");
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task AnOversizedBody_IsRefusedWithoutBeingRead()
    {
        var upload = new HeldStream();
        var ctx = WithProblems(Request("POST"));
        ctx.Request.Body = upload;
        ctx.Request.ContentLength = RequestGate.DefaultBodyLimit + 1;
        var ran = false;
        var run = Gated(_ => { ran = true; return Task.CompletedTask; }, new RequestGate()).InvokeAsync(ctx);
        try
        {
            Assert.True(await FinishesWithin(run, TimeSpan.FromSeconds(10)), "the body was read before its size was checked");
            Assert.Equal(StatusCodes.Status413PayloadTooLarge, ctx.Response.StatusCode);
            Assert.False(ran);
        }
        finally
        {
            upload.Release();
        }
    }

    // The guard marks a write finished at ReaderExecuted, which holds while each command carries one statement.
    [Fact]
    public async Task ASaveSendsEachWriteAsItsOwnCommand()
    {
        var seen = new CommandRecorder();
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(_conn).AddInterceptors(seen).Options;
        await using var db = new AppDbContext(options);
        var users = Enumerable.Range(0, 3)
            .Select(i => new User { Name = $"u{i}", Email = $"{Guid.NewGuid():N}@example.com", Role = Role.Viewer }).ToList();
        db.Users.AddRange(users);
        await db.SaveChangesAsync();
        users[0].Name = "renamed";
        db.Users.Remove(users[1]);
        db.Users.Add(new User { Name = "u3", Email = $"{Guid.NewGuid():N}@example.com", Role = Role.Viewer });
        await db.SaveChangesAsync();

        var writes = seen.Commands.Where(c => Statements(c) > 0).ToList();
        Assert.Equal(6, writes.Count);
        Assert.All(writes, c => Assert.Equal(1, Statements(c)));
    }

    private static int Statements(string sql) =>
        Regex.Matches(sql, @"^\s*(INSERT|UPDATE|DELETE)\b", RegexOptions.Multiline | RegexOptions.IgnoreCase).Count;

    private sealed class CommandRecorder : DbCommandInterceptor
    {
        public ConcurrentQueue<string> Commands { get; } = new();

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Commands.Enqueue(command.CommandText);
            return ValueTask.FromResult(result);
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Commands.Enqueue(command.CommandText);
            return ValueTask.FromResult(result);
        }
    }

    // The test server gives every body a Content-Length, so an undeclared one is tested here.
    [Fact]
    public async Task AnOversizedBodyWithoutALength_IsReadOnlyUpToTheCap()
    {
        var ctx = WithProblems(Request("POST"));
        ctx.Request.Body = new MemoryStream(new byte[RequestGate.DefaultBodyLimit + 1]);
        var ran = false;
        await Gated(_ => { ran = true; return Task.CompletedTask; }, new RequestGate()).InvokeAsync(ctx);
        Assert.Equal(StatusCodes.Status413PayloadTooLarge, ctx.Response.StatusCode);
        Assert.False(ran);
    }

    [Fact]
    public async Task AFailedRequestReleasesTheGate()
    {
        var gate = new RequestGate();
        var failing = Request("POST");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Gated(_ => throw new InvalidOperationException("endpoint failed"), gate).InvokeAsync(failing));
        Assert.False(RequestGate.Holds(failing));

        var next = Request("POST");
        _accessor.HttpContext = next;
        var run = Gated(_ => AddUser(), gate).InvokeAsync(next);
        Assert.True(await FinishesWithin(run, TimeSpan.FromSeconds(10)), "the gate stayed with the failed request");
        _accessor.HttpContext = null;
        Assert.Equal(1, await Users());
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public async Task AReadPassesWhileTheGateIsHeld_AndCannotWrite(string method)
    {
        var gate = new RequestGate();
        await gate.WaitAsync(CancellationToken.None);
        var ctx = Request(method);
        _accessor.HttpContext = ctx;
        var run = Gated(_ => Refused(), gate).InvokeAsync(ctx);
        Assert.True(await FinishesWithin(run, TimeSpan.FromSeconds(10)), "a read waited for the gate");
        await run;
    }

    [Fact]
    public async Task AGetMarkedAsChangingState_TakesTheGate()
    {
        var ctx = Request("GET");
        ctx.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(ChangesState.Instance), "marked"));
        Assert.True(RequestGate.Covers(ctx));
        _accessor.HttpContext = ctx;
        await Gated(_ => AddUser(), new RequestGate()).InvokeAsync(ctx);
        _accessor.HttpContext = null;
        Assert.Equal(1, await Users());
    }

    [Fact]
    public async Task AuthenticationWrites_OnlyWithinItsOwnMethod()
    {
        _accessor.HttpContext = Request("GET");
        await AuthenticateAndWrite();
        await Refused();
        _accessor.HttpContext = null;
        Assert.Equal(1, await Users());
    }

    private async Task AuthenticateAndWrite()
    {
        RequestWriteGuard.AllowAuthenticationWrites();
        await AddUser();
    }

    private static async Task<bool> FinishesWithin(Task t, TimeSpan wait) => await Task.WhenAny(t, Task.Delay(wait)) == t;

    // A client that stops mid-transfer: reads return nothing and writes complete only after Release.
    private sealed class HeldStream : Stream
    {
        private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly MemoryStream _written = new();

        public Task Reached => _reached.Task;
        public void Release() => _release.TrySetResult();
        public string Written() => Encoding.UTF8.GetString(_written.ToArray());

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            _reached.TrySetResult();
            await _release.Task.WaitAsync(ct);
            return 0;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            _reached.TrySetResult();
            await _release.Task.WaitAsync(ct);
            _written.Write(buffer.Span);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    }
}

public class CaddyValidateStopTests
{
    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new InvalidOperationException("no HTTP in this test");
    }

    [Fact]
    public async Task AValidateWhoseRequestEnds_StopsAndReportsNoVerdict()
    {
        var dir = Directory.CreateTempSubdirectory("sslrp-hang-");
        try
        {
            // A "caddy" that never answers, through a child process: the stop has to reach the child too.
            string path;
            Func<bool?> child; // null until the child runs, then whether it still runs
            if (OperatingSystem.IsWindows())
            {
                // The child holds its redirected output open while it runs.
                var output = Path.Combine(dir.FullName, "child.txt");
                path = Path.Combine(dir.FullName, "caddy.cmd");
                File.WriteAllText(path, $"@\"{Path.Combine(Environment.SystemDirectory, "PING.EXE")}\" -n 60 127.0.0.1 >\"{output}\"\r\n");
                child = () => Written(output) == 0 ? null : HeldOpen(output);
            }
            else
            {
                var pidFile = Path.Combine(dir.FullName, "child");
                path = Path.Combine(dir.FullName, "caddy");
                File.WriteAllText(path, $"#!/bin/sh\nsleep 60 &\necho $! > '{pidFile}.tmp'\nmv '{pidFile}.tmp' '{pidFile}'\nwait\n");
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                child = () => File.Exists(pidFile) ? Running(int.Parse(File.ReadAllText(pidFile).Trim())) : null;
            }
            using var c = new CaddyProxyController(
                Options.Create(new ProxyOptions { CaddyPath = path, ConfigDirectory = dir.FullName }),
                new NoHttp(), NullLogger<CaddyProxyController>.Instance, TimeProvider.System, new TrafficRecorder(),
                SecretRedactor.None, new CaddyCertificateLog(SecretRedactor.None, TimeProvider.System),
                new RecentRequests(TimeProvider.System));
            var plan = new ProxyPlan([new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.2", Enabled = true }]);

            using var ended = new CancellationTokenSource();
            var started = Stopwatch.StartNew();
            var validate = c.ValidateConfigurationAsync(plan, ended.Token);
            Assert.True(await Until(() => child() == true, TimeSpan.FromSeconds(20)), "the child never started");
            ended.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => validate);
            Assert.True(started.Elapsed < TimeSpan.FromSeconds(30), $"validate returned after {started.Elapsed}");
            Assert.True(await Until(() => child() == false, TimeSpan.FromSeconds(10)), "the child outlived the validate");
        }
        finally
        {
            try { dir.Delete(recursive: true); } catch (IOException) { /* best effort */ }
        }
    }

    private static async Task<bool> Until(Func<bool> condition, TimeSpan limit)
    {
        var clock = Stopwatch.StartNew();
        while (!condition())
        {
            if (clock.Elapsed > limit) return false;
            await Task.Delay(100);
        }
        return true;
    }

    private static long Written(string file)
    {
        try
        {
            using var s = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return s.Length;
        }
        catch (IOException) { return 0; }
    }

    private static bool HeldOpen(string file)
    {
        try
        {
            using var s = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException) { return true; }
    }

    // A zombie has stopped; it waits only for its parent to collect it.
    private static bool Running(int pid)
    {
        try
        {
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            return stat[(stat.LastIndexOf(')') + 2)..][0] != 'Z';
        }
        catch (IOException) { return false; }
    }
}
