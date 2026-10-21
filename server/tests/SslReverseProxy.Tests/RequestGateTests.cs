using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Core.Domain;
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
            var run = new RequestGateMiddleware(_ => AddUser(), gate).InvokeAsync(ctx);
            Assert.True(await FinishesWithin(run, TimeSpan.FromSeconds(10)), "the gate was not released");
            Assert.False(RequestGate.Holds(ctx));
        }
        _accessor.HttpContext = null;
        Assert.Equal(2, await Users());
    }

    [Fact]
    public async Task AFailedRequestReleasesTheGate()
    {
        var gate = new RequestGate();
        var failing = Request("POST");
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new RequestGateMiddleware(_ => throw new InvalidOperationException("endpoint failed"), gate).InvokeAsync(failing));
        Assert.False(RequestGate.Holds(failing));

        var next = Request("POST");
        _accessor.HttpContext = next;
        var run = new RequestGateMiddleware(_ => AddUser(), gate).InvokeAsync(next);
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
        var run = new RequestGateMiddleware(_ => Refused(), gate).InvokeAsync(ctx);
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
        await new RequestGateMiddleware(_ => AddUser(), new RequestGate()).InvokeAsync(ctx);
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
}
