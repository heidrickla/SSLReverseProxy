using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SslReverseProxy.Api.Health;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

public class ApiKeyScopeTests : IDisposable
{
    private readonly PasskeyFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    private static async Task<JsonNode> Json(HttpResponseMessage r) =>
        JsonNode.Parse(await r.Content.ReadAsStringAsync())!;

    private HttpClient Client(string token)
    {
        var c = _factory.Anonymous();
        c.DefaultRequestHeaders.Add("X-Api-Key", token);
        return c;
    }

    private Guid NewUser(Role role) => _factory.Db(db =>
    {
        var u = new User { Name = $"{role} {Guid.NewGuid():N}", Email = $"{Guid.NewGuid():N}@example.com", Role = role };
        db.Users.Add(u);
        db.SaveChanges();
        return u.Id;
    });

    private async Task<JsonNode> Issue(HttpClient caller, Guid owner, object? scopes, int days = 30)
    {
        var r = await caller.PostAsJsonAsync("/api/apikeys", new { userId = owner, name = "scoped", lifetimeDays = days, scopes });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return await Json(r);
    }

    private async Task<HttpClient> Scoped(Guid owner, params string[] scopes)
    {
        var (admin, _) = _factory.WithKey();
        return Client((string)(await Issue(admin, owner, scopes))["token"]!);
    }

    [Fact]
    public async Task AReadOnlyKey_ReadsAndIsRefusedEveryWrite()
    {
        var (_, adminId) = _factory.WithKey();
        var key = await Scoped(adminId, "ServerRead", "CertRead");

        Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/servers")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/certificates")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsJsonAsync("/api/servers", new { name = "x", host = "10.0.0.9", os = "linux" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsync("/api/proxy/reload", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.GetAsync("/api/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.GetAsync("/api/apikeys")).StatusCode);
    }

    [Fact]
    public async Task TheHomeAssistantPreset_ReloadsAndRenewsButCannotStartStopOrEditCertificates()
    {
        var (admin, adminId) = _factory.WithKey();
        var options = await Json(await admin.GetAsync("/api/apikeys/options"));
        var preset = options["presets"]!.AsArray().Single(p => (string)p!["id"]! == "home-assistant")!;
        var scopes = preset["scopes"]!.AsArray().Select(s => (string)s!).ToArray();
        Assert.Equal(["ServerRead", "CertRead", "ProxyReload", "CertRenew"], scopes);
        var key = Client((string)(await Issue(admin, adminId, scopes))["token"]!);

        Assert.NotEqual(HttpStatusCode.Forbidden, (await key.PostAsync("/api/proxy/reload", null)).StatusCode);
        Assert.NotEqual(HttpStatusCode.Forbidden, (await key.PostAsync($"/api/certificates/{Guid.NewGuid()}/renew", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsync("/api/proxy/start", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsync("/api/proxy/stop", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsJsonAsync("/api/certificates", new { domain = "x.example.com", challenge = "Http" })).StatusCode);
    }

    [Fact]
    public async Task DemotingTheOwner_NarrowsTheKeyAtOnce()
    {
        var owner = NewUser(Role.Admin);
        var key = await Scoped(owner, "ServerRead", "ServerWrite");
        Assert.Equal(HttpStatusCode.Created,
            (await key.PostAsJsonAsync("/api/servers", new { name = "before", host = "10.0.0.10", os = "linux" })).StatusCode);

        _factory.Db(db => db.Users.Where(u => u.Id == owner).ExecuteUpdate(s => s.SetProperty(u => u.Role, Role.Viewer)));

        Assert.Equal(HttpStatusCode.Forbidden,
            (await key.PostAsJsonAsync("/api/servers", new { name = "after", host = "10.0.0.11", os = "linux" })).StatusCode);
        var who = await Json(await key.GetAsync("/api/whoami"));
        Assert.Equal(["ServerRead"], who["permissions"]!.AsArray().Select(p => (string)p!));
    }

    [Fact]
    public async Task WhoAmI_ReportsTheKeysEffectivePermissionsAndExpiry()
    {
        var (_, adminId) = _factory.WithKey();
        var key = await Scoped(adminId, "CertRead", "ServerRead");
        var who = await Json(await key.GetAsync("/api/whoami"));
        Assert.Equal(["ServerRead", "CertRead"], who["permissions"]!.AsArray().Select(p => (string)p!));
        Assert.Equal(["ServerRead", "CertRead"], who["key"]!["scopes"]!.AsArray().Select(p => (string)p!));
        var expires = DateTimeOffset.Parse((string)who["key"]!["expiresAt"]!);
        Assert.Equal(_factory.Clock.GetUtcNow().AddDays(30), expires, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task AKeyWithoutStoredScopes_FollowsItsOwnersRole()
    {
        var (admin, _) = _factory.WithKey();
        var who = await Json(await admin.GetAsync("/api/whoami"));
        Assert.Equal(Enum.GetValues<Permission>().Length, who["permissions"]!.AsArray().Count);
        Assert.Null(who["key"]!["scopes"]);
        Assert.True((bool)who["wholeRole"]!);
    }

    [Fact]
    public async Task FullAccess_IsFixedWhenIssued_SoAPromotionDoesNotWidenIt()
    {
        var (admin, _) = _factory.WithKey();
        var viewer = NewUser(Role.Viewer);
        var issued = await Json(await admin.PostAsJsonAsync("/api/apikeys", new { userId = viewer, name = "full", lifetimeDays = 30 }));
        var viewerNames = Permissions.For(Role.Viewer).Order().Select(p => p.ToString()).ToArray();
        Assert.Equal(viewerNames, issued["scopes"]!.AsArray().Select(p => (string)p!));

        _factory.Db(db => db.Users.Where(u => u.Id == viewer).ExecuteUpdate(s => s.SetProperty(u => u.Role, Role.Editor)));

        var key = Client((string)issued["token"]!);
        var who = await Json(await key.GetAsync("/api/whoami"));
        Assert.Equal(viewerNames, who["permissions"]!.AsArray().Select(p => (string)p!));
        Assert.False((bool)who["wholeRole"]!);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await key.PostAsJsonAsync("/api/servers", new { name = "promoted", host = "10.0.0.12", os = "linux" })).StatusCode);
    }

    [Fact]
    public async Task RotatingAKeyThatFollowsItsRole_FixesTheNewKeysScopes()
    {
        var (admin, _) = _factory.WithKey();
        var (legacy, _) = _factory.WithKey();
        var id = (string)(await Json(await legacy.GetAsync("/api/whoami")))["key"]!["id"]!;

        var r = await admin.PostAsJsonAsync($"/api/apikeys/{id}/rotate", new { lifetimeDays = 30 });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(Enum.GetValues<Permission>().Length, (await Json(r))["scopes"]!.AsArray().Count);
    }

    [Fact]
    public async Task IssuingScopesTheOwnersRoleLacks_IsRefused()
    {
        var (admin, _) = _factory.WithKey();
        var viewer = NewUser(Role.Viewer);
        var r = await admin.PostAsJsonAsync("/api/apikeys",
            new { userId = viewer, name = "too wide", lifetimeDays = 30, scopes = new[] { "ServerRead", "RuleWrite" } });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("RuleWrite", await r.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("Nonsense")]
    [InlineData("0")]
    [InlineData(" ServerRead")]
    [InlineData("ServerRead,RuleWrite")]
    [InlineData("serverread")]
    public async Task AScopeThatIsNotAPermissionName_IsRefused(string name)
    {
        var (admin, adminId) = _factory.WithKey();
        var r = await admin.PostAsJsonAsync("/api/apikeys", new { userId = adminId, name = "bad", lifetimeDays = 30, scopes = new[] { name } });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task AnEmptyScopeList_IsRefused()
    {
        var (admin, adminId) = _factory.WithKey();
        var r = await admin.PostAsJsonAsync("/api/apikeys", new { userId = adminId, name = "empty", lifetimeDays = 30, scopes = Array.Empty<string>() });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task AScopedKeyManager_IssuesOnlyWhatItHolds()
    {
        var (_, adminId) = _factory.WithKey();
        var manager = await Scoped(adminId, "ApiKeyManage", "ServerRead");

        var narrower = await manager.PostAsJsonAsync("/api/apikeys",
            new { userId = adminId, name = "narrower", lifetimeDays = 7, scopes = new[] { "ServerRead" } });
        Assert.Equal(HttpStatusCode.Created, narrower.StatusCode);

        var wider = await manager.PostAsJsonAsync("/api/apikeys",
            new { userId = adminId, name = "wider", lifetimeDays = 7, scopes = new[] { "ServerRead", "UserWrite" } });
        Assert.Equal(HttpStatusCode.Forbidden, wider.StatusCode);
        Assert.Contains("UserWrite", await wider.Content.ReadAsStringAsync());

        var full = await manager.PostAsJsonAsync("/api/apikeys", new { userId = adminId, name = "full", lifetimeDays = 7 });
        Assert.Equal(HttpStatusCode.Created, full.StatusCode);
        Assert.Equal(["ServerRead", "ApiKeyManage"], (await Json(full))["scopes"]!.AsArray().Select(p => (string)p!));
    }

    [Fact]
    public async Task FullAccess_FromACallerHoldingNoneOfTheOwnersRole_IsRefused()
    {
        var (_, adminId) = _factory.WithKey();
        var manager = await Scoped(adminId, "ApiKeyManage");
        var viewer = NewUser(Role.Viewer);
        var r = await manager.PostAsJsonAsync("/api/apikeys", new { userId = viewer, name = "full", lifetimeDays = 7 });
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task AScopedKeyManager_CannotRotateAFullKeyIntoItsOwnHands()
    {
        var (admin, adminId) = _factory.WithKey();
        var fullKey = await Json(await admin.PostAsJsonAsync("/api/apikeys", new { userId = adminId, name = "full", lifetimeDays = 30 }));
        var manager = await Scoped(adminId, "ApiKeyManage");

        var r = await manager.PostAsync($"/api/apikeys/{(string)fullKey["id"]!}/rotate", null);
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Client((string)fullKey["token"]!).GetAsync("/api/whoami")).StatusCode);
    }

    [Fact]
    public async Task AKeyNarrowerThanItsOwnersRole_CannotAddOrListPasskeys()
    {
        var (admin, adminId) = _factory.WithKey();
        var key = await Scoped(adminId, "ServerRead", "ApiKeyManage", "UserWrite");
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsync("/api/passkeys/options", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await key.GetAsync("/api/passkeys")).StatusCode);

        var (followsRole, _) = _factory.WithKey();
        Assert.Equal(HttpStatusCode.OK, (await followsRole.PostAsync("/api/passkeys/options", null)).StatusCode);

        // Full access holds the whole role until a promotion leaves it behind.
        var viewer = NewUser(Role.Viewer);
        var full = Client((string)(await Json(await admin.PostAsJsonAsync("/api/apikeys",
            new { userId = viewer, name = "full", lifetimeDays = 30 })))["token"]!);
        Assert.Equal(HttpStatusCode.OK, (await full.GetAsync("/api/passkeys")).StatusCode);
        _factory.Db(db => db.Users.Where(u => u.Id == viewer).ExecuteUpdate(s => s.SetProperty(u => u.Role, Role.Editor)));
        Assert.Equal(HttpStatusCode.Forbidden, (await full.GetAsync("/api/passkeys")).StatusCode);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(0, null)]
    [InlineData(366, null)]
    [InlineData(2, null)]
    [InlineData(45, null)]
    [InlineData(30, 10.0)]
    [InlineData(null, -1.0)]
    [InlineData(null, 365.1)]
    public async Task ALifetimeOffTheListOrPastAYear_IsRefused(int? days, double? expiresInDays)
    {
        var (admin, adminId) = _factory.WithKey();
        DateTimeOffset? at = expiresInDays is { } d ? _factory.Clock.GetUtcNow().AddDays(d) : null;
        var r = await admin.PostAsJsonAsync("/api/apikeys", new { userId = adminId, name = "life", lifetimeDays = days, expiresAt = at });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task ACustomExpiryDate_IsKept()
    {
        var (admin, adminId) = _factory.WithKey();
        var at = _factory.Clock.GetUtcNow().AddDays(45).AddHours(3);
        var r = await admin.PostAsJsonAsync("/api/apikeys", new { userId = adminId, name = "dated", expiresAt = at, scopes = new[] { "ServerRead" } });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        Assert.Equal(at, DateTimeOffset.Parse((string)(await Json(r))["expiresAt"]!), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task RotateWithoutABody_KeepsScopesAndLifetimeAndRevokesTheOldKey()
    {
        var (admin, adminId) = _factory.WithKey();
        var old = await Issue(admin, adminId, new[] { "ServerRead", "CertRead" }, days: 7);
        _factory.Clock.Advance(TimeSpan.FromDays(2));

        var r = await admin.PostAsync($"/api/apikeys/{(string)old["id"]!}/rotate", null);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var rotated = await Json(r);
        Assert.Equal(["ServerRead", "CertRead"], rotated["scopes"]!.AsArray().Select(p => (string)p!));
        Assert.Equal(_factory.Clock.GetUtcNow().AddDays(7), DateTimeOffset.Parse((string)rotated["expiresAt"]!), TimeSpan.FromSeconds(5));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Client((string)old["token"]!).GetAsync("/api/whoami")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Client((string)rotated["token"]!).GetAsync("/api/whoami")).StatusCode);
    }

    private void Publish(string message) =>
        _factory.Services.GetRequiredService<IEventStream>().Publish(new ProxyEvent("test", message, _factory.Clock.GetUtcNow(), null));

    // The next data line, or null when the stream ends first.
    internal static async Task<string?> NextEvent(StreamReader reader, CancellationToken ct)
    {
        while (await reader.ReadLineAsync(ct) is { } line)
            if (line.StartsWith("data: ", StringComparison.Ordinal)) return line;
        return null;
    }

    [Theory]
    [InlineData("revoke")]
    [InlineData("deactivate")]
    [InlineData("lose-read")]
    public async Task AnEventStream_EndsBeforeTheNextEvent_OnceItsKeyNoLongerHolds(string change)
    {
        var (admin, _) = _factory.WithKey();
        var owner = NewUser(Role.Editor);
        var issued = await Issue(admin, owner, new[] { "ServerRead" });
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var stream = await Client((string)issued["token"]!).GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, stream.StatusCode);
        using var reader = new StreamReader(await stream.Content.ReadAsStreamAsync(timeout.Token));

        Publish("before");
        Assert.Contains("before", await NextEvent(reader, timeout.Token));

        switch (change)
        {
            case "revoke":
                Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/apikeys/{(string)issued["id"]!}/revoke", null)).StatusCode);
                break;
            case "deactivate":
                _factory.Db(db => db.Users.Where(u => u.Id == owner).ExecuteUpdate(s => s.SetProperty(u => u.IsActive, false)));
                break;
            default:
                _factory.Db(db => db.Users.Where(u => u.Id == owner).ExecuteUpdate(s => s.SetProperty(u => u.Role, Role.Viewer)));
                _factory.Db(db => db.ApiKeys.Where(k => k.Id == Guid.Parse((string)issued["id"]!))
                    .ExecuteUpdate(s => s.SetProperty(k => k.Scopes, "ServerWrite")));
                break;
        }
        Publish("after");
        Assert.Null(await NextEvent(reader, timeout.Token));
    }

    [Fact]
    public async Task AnEventStream_EndsWhenItsKeyExpires()
    {
        var (admin, adminId) = _factory.WithKey();
        var issued = await Issue(admin, adminId, new[] { "ServerRead" }, days: 1);
        _factory.Clock.Advance(TimeSpan.FromDays(1) - TimeSpan.FromSeconds(2));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var stream = await Client((string)issued["token"]!).GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, stream.StatusCode);
        using var reader = new StreamReader(await stream.Content.ReadAsStreamAsync(timeout.Token));
        Assert.Null(await NextEvent(reader, timeout.Token));
    }

    [Fact]
    public async Task RotateWithoutABody_KeepsALifetimeOffTheList()
    {
        var (admin, adminId) = _factory.WithKey();
        var old = await Json(await admin.PostAsJsonAsync("/api/apikeys",
            new { userId = adminId, name = "dated", expiresAt = _factory.Clock.GetUtcNow().AddDays(45), scopes = new[] { "ServerRead" } }));
        var r = await admin.PostAsync($"/api/apikeys/{(string)old["id"]!}/rotate", null);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(_factory.Clock.GetUtcNow().AddDays(45), DateTimeOffset.Parse((string)(await Json(r))["expiresAt"]!), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task RotateWithABody_IssuesTheNewScopesAndLifetime()
    {
        var (admin, adminId) = _factory.WithKey();
        var old = await Issue(admin, adminId, new[] { "ServerRead" });
        var r = await admin.PostAsJsonAsync($"/api/apikeys/{(string)old["id"]!}/rotate",
            new { lifetimeDays = 90, scopes = new[] { "ServerRead", "ProxyReload" } });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var rotated = await Json(r);
        Assert.Equal(["ServerRead", "ProxyReload"], rotated["scopes"]!.AsArray().Select(p => (string)p!));
        Assert.Equal(_factory.Clock.GetUtcNow().AddDays(90), DateTimeOffset.Parse((string)rotated["expiresAt"]!), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ARevokedKey_CannotBeRotated()
    {
        var (admin, adminId) = _factory.WithKey();
        var old = await Issue(admin, adminId, new[] { "ServerRead" });
        await admin.PostAsync($"/api/apikeys/{(string)old["id"]!}/revoke", null);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync($"/api/apikeys/{(string)old["id"]!}/rotate", null)).StatusCode);
    }

    [Fact]
    public async Task ConcurrentRotations_OfOneKey_IssueOneNewKey()
    {
        var (admin, adminId) = _factory.WithKey();
        for (var round = 0; round < 5; round++)
        {
            var r = await admin.PostAsJsonAsync("/api/apikeys",
                new { userId = adminId, name = $"race {round}", lifetimeDays = 30, scopes = new[] { "ServerRead" } });
            var id = (string)(await Json(r))["id"]!;
            var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
                admin.PostAsync($"/api/apikeys/{id}/rotate", null)));
            Assert.Single(results, x => x.StatusCode == HttpStatusCode.OK);
            Assert.Equal(2, _factory.Db(db => db.ApiKeys.Count(k => k.Name == $"race {round}")));
        }
    }

    [Fact]
    public async Task TheKeyList_ShowsOwnerScopesAndLastUse()
    {
        var (admin, adminId) = _factory.WithKey();
        var issued = await Issue(admin, adminId, new[] { "ServerRead" });
        await Client((string)issued["token"]!).GetAsync("/api/whoami");
        var row = (await Json(await admin.GetAsync("/api/apikeys"))).AsArray().Single(k => (string)k!["id"]! == (string)issued["id"]!)!;
        Assert.Equal(adminId.ToString(), (string)row["userId"]!);
        Assert.False(string.IsNullOrEmpty((string)row["userName"]!));
        Assert.Equal(["ServerRead"], row["scopes"]!.AsArray().Select(p => (string)p!));
        Assert.NotNull(row["lastUsedAt"]);
        Assert.Null(row["token"]);
    }

    [Fact]
    public async Task TheKeyList_CarriesEachOwnersCurrentRole()
    {
        var (admin, _) = _factory.WithKey();
        var viewer = NewUser(Role.Viewer);
        var issued = await Issue(admin, viewer, new[] { "ServerRead" });
        async Task<string> OwnerRole() => (string)(await Json(await admin.GetAsync("/api/apikeys"))).AsArray()
            .Single(k => (string)k!["id"]! == (string)issued["id"]!)!["userRole"]!;

        Assert.Equal("Viewer", await OwnerRole());
        _factory.Db(db => db.Users.Where(u => u.Id == viewer).ExecuteUpdate(s => s.SetProperty(u => u.Role, Role.Editor)));
        Assert.Equal("Editor", await OwnerRole());
    }
}

public class ApiKeyScopeUnitTests
{
    [Fact]
    public void StoredScopes_DropNamesTheCodeNoLongerHas()
    {
        Assert.Equal([Permission.ServerRead], ApiKeyScopes.Parse("ServerRead,Retired,7,"));
        Assert.Empty(ApiKeyScopes.Parse("")!);
        Assert.Null(ApiKeyScopes.Parse(null));
    }

    [Fact]
    public void Effective_IsTheRoleNarrowedToTheScopes()
    {
        Assert.Equal([Permission.ServerRead],
            Permissions.Effective(Role.Viewer, new HashSet<Permission> { Permission.ServerRead, Permission.RuleWrite }));
        Assert.Empty(Permissions.Effective(Role.Admin, new HashSet<Permission>()));
        Assert.Equal(Permissions.For(Role.Editor).Count, Permissions.Effective(Role.Editor, null).Count);
    }

    [Fact]
    public void ThePresets_FitTheRolesTheyAreFor()
    {
        foreach (var preset in ApiKeyScopes.Presets.Where(p => p.Scopes is not null))
            Assert.All(preset.Scopes!, p => Assert.True(Permissions.Has(Role.Editor, p), $"{preset.Id}: {p}"));
    }

    private static ApiKey Key(DateTimeOffset now, TimeSpan left) =>
        new() { Name = "ha", Prefix = "abcd1234", CreatedAt = now.AddDays(-30), ExpiresAt = now + left };

    [Fact]
    public void ExpiryAlerts_WarnOnceAtSevenDaysAndOnceAtOne()
    {
        var now = DateTimeOffset.UtcNow;
        var key = Key(now, TimeSpan.FromDays(10));
        Assert.Null(ApiKeyAlerts.Evaluate(key, "Lewis", now));

        now = now.AddDays(3.5);
        var week = ApiKeyAlerts.Evaluate(key, "Lewis", now);
        Assert.Equal((AlertTypes.ApiKeyExpiring, AlertSeverity.Warning), (week!.Type, week.Severity));
        Assert.Equal(7, key.ExpiryAlertedDays);
        Assert.Null(ApiKeyAlerts.Evaluate(key, "Lewis", now.AddDays(1)));

        now = now.AddDays(6);
        var day = ApiKeyAlerts.Evaluate(key, "Lewis", now);
        Assert.Equal(AlertSeverity.Critical, day!.Severity);
        Assert.Equal(1, key.ExpiryAlertedDays);
        Assert.Null(ApiKeyAlerts.Evaluate(key, "Lewis", now.AddHours(2)));
    }

    [Fact]
    public void ExpiryAlerts_SkipToTheOneDayWarningWhenTheWeekOneWasMissed()
    {
        var now = DateTimeOffset.UtcNow;
        var key = Key(now, TimeSpan.FromHours(20));
        Assert.Equal(AlertSeverity.Critical, ApiKeyAlerts.Evaluate(key, "Lewis", now)!.Severity);
        Assert.Null(ApiKeyAlerts.Evaluate(key, "Lewis", now));
    }

    [Fact]
    public void ExpiryAlerts_IgnoreRevokedExpiredAndNonExpiringKeys()
    {
        var now = DateTimeOffset.UtcNow;
        var revoked = Key(now, TimeSpan.FromDays(2));
        revoked.RevokedAt = now;
        Assert.Null(ApiKeyAlerts.Evaluate(revoked, "Lewis", now));
        Assert.Null(ApiKeyAlerts.Evaluate(Key(now, TimeSpan.FromMinutes(-1)), "Lewis", now));
        Assert.Null(ApiKeyAlerts.Evaluate(new ApiKey { Name = "forever" }, "Lewis", now));
    }

    [Fact]
    public void AnExpiryAlert_NamesTheKeyAndNotItsSecret()
    {
        var now = DateTimeOffset.UtcNow;
        var alert = ApiKeyAlerts.Evaluate(Key(now, TimeSpan.FromDays(3)), "Lewis", now)!;
        Assert.Contains("ha", alert.Message);
        Assert.Contains("Lewis", alert.Message);
        Assert.Contains("3 days", alert.Message);
    }
}

public class ApiKeyExpiryMonitorTests : IDisposable
{
    private readonly PasskeyFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    [Fact]
    public async Task ACheck_StoresTheWarningAndRaisesItOnce()
    {
        var owner = _factory.Db(db => db.Users.First(u => u.Role == Role.Admin));
        var svc = _factory.Services.CreateScope().ServiceProvider.GetRequiredService<IApiKeyService>();
        var issued = await svc.CreateAsync(owner.Id, "soon", _factory.Clock.GetUtcNow().AddDays(5), [Permission.ServerRead]);
        await svc.CreateAsync(owner.Id, "later", _factory.Clock.GetUtcNow().AddDays(60), [Permission.ServerRead]);
        var alerts = new RecordingAlerts();
        var monitor = new ApiKeyExpiryMonitor(_factory.Services.GetRequiredService<IServiceScopeFactory>(), alerts,
            _factory.Clock, NullLogger<ApiKeyExpiryMonitor>.Instance);

        await monitor.CheckAsync(CancellationToken.None);
        await monitor.CheckAsync(CancellationToken.None);

        var alert = Assert.Single(alerts.Raised);
        Assert.Equal("soon", alert.Subject);
        Assert.Equal(7, _factory.Db(db => db.ApiKeys.Single(k => k.Id == issued.Record.Id).ExpiryAlertedDays));
    }
}
