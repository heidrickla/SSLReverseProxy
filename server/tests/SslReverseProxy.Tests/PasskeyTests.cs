using System.Formats.Cbor;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Endpoints;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>
/// A WebAuthn authenticator in software: a P-256 key, "none" attestation and ES256 assertions, so the server's
/// ceremonies run against real signatures without a browser.
/// </summary>
internal sealed class SoftAuthenticator
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);
    public byte[]? UserHandle { get; set; }
    public uint Counter { get; set; }
    public string RpId { get; set; } = PasskeyFactory.RpId;
    public string Origin { get; set; } = PasskeyFactory.Origin;
    public bool UserVerified { get; set; } = true;

    private static string B64(byte[] b) => WebEncoders.Base64UrlEncode(b);

    public JsonObject Create(JsonNode options)
    {
        UserHandle = WebEncoders.Base64UrlDecode((string)options["user"]!["id"]!);
        var clientData = ClientData("webauthn.create", (string)options["challenge"]!);
        var cbor = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cbor.WriteStartMap(3);
        cbor.WriteTextString("fmt");
        cbor.WriteTextString("none");
        cbor.WriteTextString("attStmt");
        cbor.WriteStartMap(0);
        cbor.WriteEndMap();
        cbor.WriteTextString("authData");
        cbor.WriteByteString(AuthData(attested: true));
        cbor.WriteEndMap();
        return new JsonObject
        {
            ["id"] = B64(CredentialId),
            ["rawId"] = B64(CredentialId),
            ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["attestationObject"] = B64(cbor.Encode()),
                ["clientDataJSON"] = B64(clientData),
                ["transports"] = new JsonArray("internal"),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    public JsonObject Get(JsonNode options, byte[]? userHandle = null)
    {
        Counter++;
        var clientData = ClientData("webauthn.get", (string)options["challenge"]!);
        var authData = AuthData(attested: false);
        var signature = _key.SignData([.. authData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        return new JsonObject
        {
            ["id"] = B64(CredentialId),
            ["rawId"] = B64(CredentialId),
            ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["authenticatorData"] = B64(authData),
                ["clientDataJSON"] = B64(clientData),
                ["signature"] = B64(signature),
                ["userHandle"] = B64(userHandle ?? UserHandle!),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    private byte[] ClientData(string type, string challenge) => Encoding.UTF8.GetBytes(new JsonObject
    {
        ["type"] = type,
        ["challenge"] = challenge,
        ["origin"] = Origin,
        ["crossOrigin"] = false,
    }.ToJsonString());

    private byte[] AuthData(bool attested)
    {
        var flags = (byte)(0x01 | (UserVerified ? 0x04 : 0) | (attested ? 0x40 : 0));
        var data = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(RpId))) { flags };
        data.AddRange([(byte)(Counter >> 24), (byte)(Counter >> 16), (byte)(Counter >> 8), (byte)Counter]);
        if (!attested) return [.. data];

        data.AddRange(new byte[16]); // AAGUID
        data.AddRange([(byte)(CredentialId.Length >> 8), (byte)CredentialId.Length]);
        data.AddRange(CredentialId);
        var p = _key.ExportParameters(false);
        var cose = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);   // kty: EC2
        cose.WriteInt32(3); cose.WriteInt32(-7);  // alg: ES256
        cose.WriteInt32(-1); cose.WriteInt32(1);  // crv: P-256
        cose.WriteInt32(-2); cose.WriteByteString(p.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(p.Q.Y!);
        cose.WriteEndMap();
        data.AddRange(cose.Encode());
        return [.. data];
    }
}

internal sealed class PasskeyFactory(bool enabled = true, int signInsPerMinute = 1000) : WebApplicationFactory<Program>
{
    public const string RpId = "localhost";
    public const string Origin = "http://localhost:4173";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-passkeys-{Guid.NewGuid():N}.db");
    public ManualClock Clock { get; } = new(DateTimeOffset.UtcNow);

    public HttpClient Anonymous() => CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });

    public (HttpClient Client, Guid UserId) WithKey(Role role = Role.Admin)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = role == Role.Admin ? db.Users.First(u => u.Role == Role.Admin) : null;
        if (user is null)
        {
            user = new User { Name = $"{role} {Guid.NewGuid():N}", Email = $"{Guid.NewGuid():N}@example.com", Role = role };
            db.Users.Add(user);
            db.SaveChanges();
        }
        var key = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
            .CreateAsync(user.Id, "passkey-tests", null).GetAwaiter().GetResult().PlaintextToken;
        var client = Anonymous();
        client.DefaultRequestHeaders.Add("X-Api-Key", key);
        return (client, user.Id);
    }

    public T Db<T>(Func<AppDbContext, T> f)
    {
        using var scope = Services.CreateScope();
        return f(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        builder.ConfigureTestServices(s =>
        {
            s.RemoveAll<IHostedService>();
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(Clock);
        });

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureHostConfiguration(cfg =>
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                ["Security:RequestsPerMinute"] = "100000",
                ["Passkeys:RelyingPartyId"] = enabled ? RpId : "",
                ["Passkeys:Origins:0"] = Origin,
                ["Passkeys:SignInsPerMinute"] = signInsPerMinute.ToString(),
            }));
        return base.CreateHost(builder);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }
}

public class PasskeyTests : IDisposable
{
    private readonly PasskeyFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    private sealed record Session(string Cookie, string Csrf, string SetCookie);

    private static async Task<JsonNode> Json(HttpResponseMessage r) =>
        JsonNode.Parse(await r.Content.ReadAsStringAsync())!;

    private async Task<(SoftAuthenticator Auth, Guid UserId, HttpClient Keyed)> Register(Role role = Role.Admin, string name = "Laptop")
    {
        var (client, userId) = _factory.WithKey(role);
        var auth = new SoftAuthenticator();
        var begin = await Json(await client.PostAsync("/api/passkeys/options", null));
        var r = await client.PostAsJsonAsync("/api/passkeys", new JsonObject
        {
            ["handle"] = (string)begin["handle"]!, ["name"] = name, ["response"] = auth.Create(begin["options"]!),
        });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (auth, userId, client);
    }

    private async Task<HttpResponseMessage> TrySignIn(SoftAuthenticator auth, Func<JsonNode, JsonObject>? answer = null)
    {
        var client = _factory.Anonymous();
        var begin = await Json(await client.PostAsync("/api/auth/passkey/options", null));
        return await client.PostAsJsonAsync("/api/auth/passkey", new JsonObject
        {
            ["handle"] = (string)begin["handle"]!, ["response"] = (answer ?? (o => auth.Get(o)))(begin["options"]!),
        });
    }

    private async Task<Session> SignIn(SoftAuthenticator auth)
    {
        var r = await TrySignIn(auth);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var setCookie = r.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith(SessionTokens.CookieName + "="));
        var cookie = setCookie.Split(';')[0];
        return new Session(cookie, (string)(await Json(r))["csrfToken"]!, setCookie);
    }

    private HttpRequestMessage Req(HttpMethod method, string path, Session s, bool csrf = true, string? origin = PasskeyFactory.Origin)
    {
        var m = new HttpRequestMessage(method, path);
        m.Headers.Add("Cookie", s.Cookie);
        if (csrf) m.Headers.Add(SessionTokens.CsrfHeader, s.Csrf);
        if (origin is not null) m.Headers.Add("Origin", origin);
        return m;
    }

    private Task<HttpResponseMessage> Send(HttpRequestMessage m) => _factory.Anonymous().SendAsync(m);

    [Fact]
    public async Task Register_ThenSignIn_StartsAHardenedCookieSession()
    {
        var (auth, userId, keyed) = await Register();
        var listed = (await keyed.GetFromJsonAsync<JsonArray>("/api/passkeys"))!;
        Assert.Equal("Laptop", (string?)Assert.Single(listed)!["name"]);

        var s = await SignIn(auth);
        Assert.Contains("httponly", s.SetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", s.SetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", s.SetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", s.SetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", s.SetCookie, StringComparison.OrdinalIgnoreCase);

        var who = await Json(await Send(Req(HttpMethod.Get, "/api/whoami", s, csrf: false, origin: null)));
        Assert.Equal(userId.ToString(), (string?)who["userId"]);

        // Only the secret's hash is stored.
        var secret = s.Cookie.Split('.')[^1];
        var row = _factory.Db(db => db.Sessions.Single());
        Assert.Equal(SessionTokens.Hash(secret), row.SecretHash);
        Assert.Equal(1u, _factory.Db(db => db.Passkeys.Single()).SignCount);
        Assert.True(_factory.Db(db => db.AuditEntries.Any(a => a.Action == "Passkey Sign-In" && a.Success)));
    }

    [Fact]
    public async Task UnsafeRequests_NeedTheCsrfTokenAndAnAllowedOrigin()
    {
        var (auth, _, _) = await Register();
        var s = await SignIn(auth);

        Assert.Equal(HttpStatusCode.Forbidden, (await Send(Req(HttpMethod.Post, "/api/proxy/validate", s, csrf: false))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(Req(HttpMethod.Post, "/api/proxy/validate", s, origin: null))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await Send(Req(HttpMethod.Post, "/api/proxy/validate", s, origin: "https://evil.example"))).StatusCode);
        var wrong = Req(HttpMethod.Post, "/api/proxy/validate", s, csrf: false);
        wrong.Headers.Add(SessionTokens.CsrfHeader, s.Csrf[..^2] + "AA");
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(wrong)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Send(Req(HttpMethod.Post, "/api/proxy/validate", s))).StatusCode);

        var session = await Json(await Send(Req(HttpMethod.Get, "/api/auth/session", s, csrf: false, origin: null)));
        Assert.Equal(s.Csrf, (string?)session["csrfToken"]);
    }

    [Fact]
    public async Task AForgedSecret_ForALiveSession_IsRefused()
    {
        var (auth, _, _) = await Register();
        var s = await SignIn(auth);
        var parts = s.Cookie.Split('.');
        var forged = s with { Cookie = $"{parts[0]}.{parts[1]}.{new string('A', parts[2].Length)}" };
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Req(HttpMethod.Get, "/api/whoami", forged))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Send(Req(HttpMethod.Get, "/api/whoami", s))).StatusCode);
    }

    [Fact]
    public async Task ACookieAndAnApiKeyTogether_AreRefused()
    {
        var (auth, _, _) = await Register();
        var s = await SignIn(auth);
        var (keyed, _) = _factory.WithKey();
        var m = new HttpRequestMessage(HttpMethod.Get, "/api/whoami");
        m.Headers.Add("Cookie", s.Cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, (await keyed.SendAsync(m)).StatusCode);
    }

    [Fact]
    public async Task Ceremonies_AreSingleUse_AndExpire()
    {
        var (auth, _, _) = await Register();
        var client = _factory.Anonymous();
        var begin = await Json(await client.PostAsync("/api/auth/passkey/options", null));
        var body = new JsonObject { ["handle"] = (string)begin["handle"]!, ["response"] = auth.Get(begin["options"]!) };
        // A second answer to the same challenge, signed with a higher counter: only the spent handle refuses it.
        var second = new JsonObject { ["handle"] = (string)begin["handle"]!, ["response"] = auth.Get(begin["options"]!) };
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/passkey", body.DeepClone())).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/passkey", second)).StatusCode);

        // The same signed answer under a fresh ceremony fails on the challenge.
        var again = await Json(await client.PostAsync("/api/auth/passkey/options", null));
        body["handle"] = (string)again["handle"]!;
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/passkey", body)).StatusCode);

        var late = await Json(await client.PostAsync("/api/auth/passkey/options", null));
        _factory.Clock.Advance(PasskeyChallenges.Lifetime + TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/passkey", new JsonObject
        {
            ["handle"] = (string)late["handle"]!, ["response"] = auth.Get(late["options"]!),
        })).StatusCode);
    }

    [Theory]
    [InlineData("origin")]
    [InlineData("rpid")]
    [InlineData("uv")]
    [InlineData("counter")]
    [InlineData("userhandle")]
    [InlineData("unknown")]
    public async Task ForgedOrWeakAssertions_AreRefused(string fault)
    {
        var (auth, _, _) = await Register();
        await SignIn(auth); // counter now 1 on both sides
        switch (fault)
        {
            case "origin": auth.Origin = "https://evil.example"; break;
            case "rpid": auth.RpId = "evil.example"; break;
            case "uv": auth.UserVerified = false; break;
            case "counter": auth.Counter = 0; break; // the next assertion carries 1 again
        }
        var other = new SoftAuthenticator();
        var r = fault switch
        {
            "userhandle" => await TrySignIn(auth, o => auth.Get(o, Guid.NewGuid().ToByteArray())),
            "unknown" => await TrySignIn(other, o => { other.UserHandle = auth.UserHandle; return other.Get(o); }),
            _ => await TrySignIn(auth),
        };
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.False(r.Headers.Contains("Set-Cookie"));
        Assert.True(_factory.Db(db => db.AuditEntries.Any(a => a.Action == "Passkey Sign-In" && !a.Success)));
    }

    [Fact]
    public async Task SignOut_AndExpiry_EndTheSession()
    {
        var (auth, _, _) = await Register();
        var s = await SignIn(auth);
        var logout = await Send(Req(HttpMethod.Post, "/api/auth/logout", s));
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        Assert.Contains(logout.Headers.GetValues("Set-Cookie"), c => c.StartsWith(SessionTokens.CookieName + "=;"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Req(HttpMethod.Get, "/api/whoami", s))).StatusCode);

        var s2 = await SignIn(auth);
        _factory.Clock.Advance(TimeSpan.FromHours(12) + TimeSpan.FromSeconds(1));
        var expired = await Send(Req(HttpMethod.Get, "/api/whoami", s2));
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        Assert.Contains(expired.Headers.GetValues("Set-Cookie"), c => c.StartsWith(SessionTokens.CookieName + "=;"));
    }

    [Fact]
    public async Task RoleChange_Deactivation_AndPasskeyDeletion_EndSessions()
    {
        var (auth, userId, keyed) = await Register(Role.Editor);
        var s = await SignIn(auth);
        Assert.Equal(HttpStatusCode.OK, (await Send(Req(HttpMethod.Get, "/api/whoami", s))).StatusCode);
        _factory.Db(db => db.Users.Where(u => u.Id == userId).ExecuteUpdate(u => u.SetProperty(x => x.Role, Role.Viewer)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Req(HttpMethod.Get, "/api/whoami", s))).StatusCode);

        // Signed in again as a Viewer, the session lasts until the user is deactivated.
        var s2 = await SignIn(auth);
        _factory.Db(db => db.Users.Where(u => u.Id == userId).ExecuteUpdate(u => u.SetProperty(x => x.IsActive, false)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Req(HttpMethod.Get, "/api/whoami", s2))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TrySignIn(auth)).StatusCode);

        _factory.Db(db => db.Users.Where(u => u.Id == userId).ExecuteUpdate(u => u.SetProperty(x => x.IsActive, true)));
        var s3 = await SignIn(auth);
        var id = (string)(await keyed.GetFromJsonAsync<JsonArray>("/api/passkeys"))![0]!["id"]!;
        Assert.Equal(HttpStatusCode.NoContent, (await keyed.DeleteAsync($"/api/passkeys/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(Req(HttpMethod.Get, "/api/whoami", s3))).StatusCode);
        Assert.Equal(0, _factory.Db(db => db.Sessions.Count(x => x.UserId == userId)));
    }

    [Fact]
    public async Task Registration_IsBoundToItsUser_AndRefusesDuplicates()
    {
        var (auth, _, admin) = await Register();
        var (editor, _) = _factory.WithKey(Role.Editor);

        var begin = await Json(await admin.PostAsync("/api/passkeys/options", null));
        var stolen = await editor.PostAsJsonAsync("/api/passkeys", new JsonObject
        {
            ["handle"] = (string)begin["handle"]!, ["response"] = new SoftAuthenticator().Create(begin["options"]!),
        });
        Assert.Equal(HttpStatusCode.BadRequest, stolen.StatusCode);

        var again = await Json(await admin.PostAsync("/api/passkeys/options", null));
        Assert.Equal(Convert.ToBase64String(auth.CredentialId).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            (string?)again["options"]!["excludeCredentials"]![0]!["id"]);
        var duplicate = await admin.PostAsJsonAsync("/api/passkeys", new JsonObject
        {
            ["handle"] = (string)again["handle"]!, ["response"] = auth.Create(again["options"]!),
        });
        Assert.NotEqual(HttpStatusCode.Created, duplicate.StatusCode);
        Assert.Equal(1, _factory.Db(db => db.Passkeys.Count()));

        // Another user's passkey cannot be deleted.
        var id = _factory.Db(db => db.Passkeys.Single().Id);
        Assert.Equal(HttpStatusCode.NotFound, (await editor.DeleteAsync($"/api/passkeys/{id}")).StatusCode);
    }

    [Fact]
    public async Task TheTenPasskeyLimit_HoldsAtCompletion()
    {
        var (keyed, userId) = _factory.WithKey(Role.Editor);
        async Task<HttpResponseMessage> Complete(JsonNode begin) => await keyed.PostAsJsonAsync("/api/passkeys", new JsonObject
        {
            ["handle"] = (string)begin["handle"]!, ["response"] = new SoftAuthenticator().Create(begin["options"]!),
        });
        for (var i = 0; i < PasskeyEndpoints.MaxPerUser - 1; i++)
            Assert.Equal(HttpStatusCode.Created, (await Complete(await Json(await keyed.PostAsync("/api/passkeys/options", null)))).StatusCode);

        // Two ceremonies started at nine passkeys: the second to finish would make eleven.
        var first = await Json(await keyed.PostAsync("/api/passkeys/options", null));
        var second = await Json(await keyed.PostAsync("/api/passkeys/options", null));
        Assert.Equal(HttpStatusCode.Created, (await Complete(first)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await Complete(second)).StatusCode);
        Assert.Equal(PasskeyEndpoints.MaxPerUser, _factory.Db(db => db.Passkeys.Count(p => p.UserId == userId)));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"handle\":\"x\",\"response\":\"not an object\"}")]
    [InlineData("[]")]
    public async Task MalformedSignIns_GetTheSameAuditedRefusal(string body)
    {
        var r = await _factory.Anonymous().PostAsync("/api/auth/passkey", new StringContent(body, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal("Passkey sign-in failed.", (string?)(await Json(r))["message"]);
        Assert.True(_factory.Db(db => db.AuditEntries.Any(a => a.Action == "Passkey Sign-In" && !a.Success && a.Details == "malformed request")));
    }

    [Fact]
    public async Task Options_RequireUserVerification_AndDiscoverableKeys()
    {
        var (keyed, _) = _factory.WithKey();
        var create = (await Json(await keyed.PostAsync("/api/passkeys/options", null)))["options"]!;
        Assert.Equal("required", (string?)create["authenticatorSelection"]!["residentKey"]);
        Assert.Equal("required", (string?)create["authenticatorSelection"]!["userVerification"]);
        Assert.Equal(PasskeyFactory.RpId, (string?)create["rp"]!["id"]);
        var get = (await Json(await _factory.Anonymous().PostAsync("/api/auth/passkey/options", null)))["options"]!;
        Assert.Equal("required", (string?)get["userVerification"]);
        Assert.Empty(get["allowCredentials"]?.AsArray() ?? []);
        Assert.True((bool)(await Json(await _factory.Anonymous().GetAsync("/api/auth/methods")))["passkeys"]!);
    }
}

public class PasskeyConfigTests
{
    [Fact]
    public async Task WithoutARelyingParty_PasskeysAreOff_AndCookiesIgnored()
    {
        using var factory = new PasskeyFactory(enabled: false);
        var client = factory.Anonymous();
        Assert.False((bool)JsonNode.Parse(await client.GetStringAsync("/api/auth/methods"))!["passkeys"]!);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/api/auth/passkey/options", null)).StatusCode);
        var m = new HttpRequestMessage(HttpMethod.Get, "/api/whoami");
        m.Headers.Add("Cookie", $"{SessionTokens.CookieName}=sps.{Guid.NewGuid():N}.{new string('a', 43)}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(m)).StatusCode);
    }

    [Fact]
    public async Task SignIns_AreRateLimitedPerClient()
    {
        using var factory = new PasskeyFactory(signInsPerMinute: 2);
        var client = factory.Anonymous();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
            codes.Add((await client.PostAsJsonAsync("/api/auth/passkey", new { handle = "x", response = new { } })).StatusCode);
        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests], codes);
    }

    [Fact]
    public void BlankOrigins_DoNotCount()
    {
        // docker-compose passes an unset variable as an empty string.
        var blank = new PasskeyOptions { RelyingPartyId = "proxy.example.com", Origins = [""] };
        Assert.False(blank.Enabled);
        Assert.False(blank.AllowsOrigin(""));

        var set = new PasskeyOptions { RelyingPartyId = "proxy.example.com", Origins = ["", " https://proxy.example.com/ "] };
        Assert.True(set.Enabled);
        Assert.True(set.AllowsOrigin("https://proxy.example.com"));
        Assert.False(set.AllowsOrigin(""));
        Assert.False(set.AllowsOrigin(null));
        Assert.False(set.AllowsOrigin("https://proxy.example.com/"));
        Assert.False(set.AllowsOrigin("http://proxy.example.com"));
    }

    [Fact]
    public void Tokens_RoundTrip_AndRejectOtherShapes()
    {
        var id = Guid.NewGuid();
        var (token, hash) = SessionTokens.Create(id);
        Assert.True(SessionTokens.TryParse(token, out var parsed, out var secret));
        Assert.Equal(id, parsed);
        Assert.True(SessionTokens.Matches(secret, hash));
        Assert.False(SessionTokens.Matches(secret + "x", hash));
        Assert.True(SessionTokens.CsrfMatches(secret, SessionTokens.CsrfToken(secret)));
        Assert.False(SessionTokens.CsrfMatches(secret, null));
        Assert.False(SessionTokens.TryParse($"srp.{id:N}.{secret}", out _, out _));
        Assert.False(SessionTokens.TryParse($"sps.{id}.{secret}", out _, out _));
        Assert.False(SessionTokens.TryParse("sps..", out _, out _));
    }
}
