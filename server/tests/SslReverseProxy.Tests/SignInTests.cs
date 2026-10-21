using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using Xunit;

namespace SslReverseProxy.Tests;

public class SignInBuilderTests
{
    internal static ProxyRule Rule(string provider, Action<ProxyRule>? tweak = null, string domain = "a.example.com")
    {
        var r = new ProxyRule
        {
            Domain = domain, UpstreamUrl = "http://10.0.0.5", Enabled = true, EnableTls = false,
            SignInProvider = provider,
            SignInVerifierUrl = SignInProviders.UsesVerifier(provider) ? "http://idp.internal:9091" : null,
            CloudflareTeamDomain = provider == SignInProviders.CloudflareAccess ? AccessTeam.Team : null,
            CloudflareAudience = provider == SignInProviders.CloudflareAccess ? AccessTeam.Audience : null,
        };
        tweak?.Invoke(r);
        return r;
    }

    internal static JsonArray Routes(JsonNode cfg) => (JsonArray)cfg["apps"]!["http"]!["servers"]![CaddyConfigBuilder.HttpServer]!["routes"]!;

    private static JsonNode RuleRoute(JsonNode cfg, ProxyRule rule) =>
        Routes(cfg).Single(r => r!["handle"]!.AsArray().Any(h => (string?)h!["handler"] == "log_append" && (string?)h["value"] == rule.Id.ToString()))!;

    internal static JsonObject SignInHandler(JsonNode cfg, ProxyRule rule) =>
        RuleRoute(cfg, rule)["handle"]!.AsArray().Select(h => h!.AsObject()).Single(h => h["rewrite"]?["method"] is not null);

    /// <summary>Every provider's identity headers as a JSON array.</summary>
    internal static string AllIdentity => new JsonArray([.. SignInProviders.IdentityHeaders.Select(h => (JsonNode)h)]).ToJsonString();

    private static string Copy(string header) => """
        {"handle":[{"handler":"headers","request":{"delete":["HDR"]}}]},
        {"handle":[{"handler":"headers","request":{"set":{"HDR":["{http.reverse_proxy.header.HDR}"]}}}],
         "match":[{"not":[{"vars":{"{http.reverse_proxy.header.HDR}":[""]}}]}]}
        """.Replace("HDR", header, StringComparison.Ordinal);

    [Fact]
    public void ForwardAuth_IsCaddysExpansion_AfterBasicAuth_AndBeforeTheStrip()
    {
        var rule = Rule(SignInProviders.Authelia, r =>
        {
            r.BasicAuthUsername = "ops";
            r.BasicAuthPasswordHash = "$2a$11$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0";
            r.PathPrefix = "/app";
            r.StripPathPrefix = true;
        });
        var cfg = CaddyConfigBuilder.Build([rule], new ProxyOptions());

        var copies = string.Join(",", new[] { "Remote-Email", "Remote-Groups", "Remote-Name", "Remote-User" }.Select(Copy));
        var expected = JsonNode.Parse("""
            {
              "handler":"reverse_proxy",
              "upstreams":[{"dial":"idp.internal:9091"}],
              "handle_response":[{"match":{"status_code":[2]},"routes":[
                {"handle":[{"handler":"vars"}]},
                {"handle":[{"handler":"headers","request":{"delete":ALL}}]},
                COPIES
              ]}],
              "headers":{"request":{"set":{"X-Forwarded-Method":["{http.request.method}"],"X-Forwarded-Uri":["{http.request.uri}"]},"delete":ALL}},
              "rewrite":{"method":"GET","uri":"/api/authz/forward-auth"}
            }
            """.Replace("COPIES", copies, StringComparison.Ordinal).Replace("ALL", AllIdentity, StringComparison.Ordinal));
        var handler = SignInHandler(cfg, rule);
        Assert.True(JsonNode.DeepEquals(expected, handler), handler.ToJsonString());

        var order = RuleRoute(cfg, rule)["handle"]!.AsArray().ToList();
        var basic = order.FindIndex(h => (string?)h!["handler"] == "authentication");
        var signIn = order.IndexOf(handler);
        var strip = order.FindIndex(h => h!["strip_path_prefix"] is not null);
        Assert.True(basic >= 0 && basic < signIn && signIn < strip, string.Join(", ", order.Select(h => (string?)h!["handler"])));
    }

    [Fact]
    public void OAuth2Proxy_SendsA401ToItsSignIn_AndItsPathsGoFirst()
    {
        var rule = Rule(SignInProviders.OAuth2Proxy);
        var other = Rule(SignInProviders.OAuth2Proxy, domain: "b.example.com");
        var cfg = CaddyConfigBuilder.Build([rule, other], new ProxyOptions());

        var responses = SignInHandler(cfg, rule)["handle_response"]!.AsArray();
        Assert.Equal(2, responses.Count);
        var expected = JsonNode.Parse("""
            {"match":{"status_code":[401]},"routes":[{"handle":[{"handler":"static_response",
              "headers":{"Location":["/oauth2/sign_in?rd={http.request.scheme}://{http.request.host}{http.request.uri}"]},"status_code":302}]}]}
            """);
        Assert.True(JsonNode.DeepEquals(expected, responses[1]), responses[1]!.ToJsonString());
        Assert.Equal("/oauth2/auth", (string?)SignInHandler(cfg, rule)["rewrite"]!["uri"]);

        var routes = Routes(cfg);
        var callback = JsonNode.Parse("""
            {"match":[{"host":["a.example.com"],"path":["/oauth2/*"]}],
             "handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"idp.internal:9091"}],
               "headers":{"request":{"set":{"X-Forwarded-Uri":["{http.request.uri}"],"X-Real-Ip":["{http.request.remote.host}"]},"delete":ALL}}}],
             "terminal":true}
            """.Replace("ALL", AllIdentity, StringComparison.Ordinal));
        Assert.True(JsonNode.DeepEquals(callback, routes[0]), routes[0]!.ToJsonString());
        Assert.Equal("b.example.com", (string?)routes[1]!["match"]![0]!["host"]![0]);
        Assert.Equal("/oauth2/*", (string?)routes[1]!["match"]![0]!["path"]![0]);
        Assert.Equal(4, routes.Count);
    }

    [Fact]
    public void Authentik_ProxiesItsOutpost_AndAnswersA401Itself()
    {
        var rule = Rule(SignInProviders.Authentik, r => r.SignInVerifierUrl = "https://authentik.internal:9443");
        var cfg = CaddyConfigBuilder.Build([rule], new ProxyOptions());
        var handler = SignInHandler(cfg, rule);
        Assert.Equal("/outpost.goauthentik.io/auth/caddy", (string?)handler["rewrite"]!["uri"]);
        Assert.Single(handler["handle_response"]!.AsArray());
        Assert.Equal(12, (handler["handle_response"]![0]!["routes"]!.AsArray().Count - 2) / 2);
        Assert.Equal("authentik.internal:9443", (string?)handler["upstreams"]![0]!["dial"]);
        var tls = JsonNode.Parse("""{"protocol":"http","tls":{}}""");
        Assert.True(JsonNode.DeepEquals(tls, handler["transport"]));

        var callback = Routes(cfg)[0]!;
        Assert.Equal("/outpost.goauthentik.io/*", (string?)callback["match"]![0]!["path"]![0]);
        Assert.True(JsonNode.DeepEquals(tls, callback["handle"]![0]!["transport"]));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse($"{{\"request\":{{\"delete\":{AllIdentity}}}}}"), callback["handle"]![0]!["headers"]),
            callback["handle"]![0]!["headers"]!.ToJsonString());
    }

    [Fact]
    public void CloudflareAccess_AsksThisService_ByItsOwnName_ForTheRule()
    {
        var rule = Rule(SignInProviders.CloudflareAccess);
        var cfg = CaddyConfigBuilder.Build([rule], new ProxyOptions { ControlPlaneUrl = "http://127.0.0.1:5195" });
        var handler = SignInHandler(cfg, rule);
        Assert.Equal("127.0.0.1:5195", (string?)handler["upstreams"]![0]!["dial"]);
        Assert.Equal("/api/sign-in/cloudflare/" + rule.Id, (string?)handler["rewrite"]!["uri"]);
        Assert.Equal("127.0.0.1:5195", (string?)handler["headers"]!["request"]!["set"]!["Host"]![0]);
        var routes = handler["handle_response"]![0]!["routes"]!.AsArray();
        Assert.Equal(4, routes.Count);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(AllIdentity), routes[1]!["handle"]![0]!["request"]!["delete"]), routes[1]!.ToJsonString());
        Assert.Equal(SignInProviders.CloudflareEmailHeader, (string?)routes[2]!["handle"]![0]!["request"]!["delete"]![0]);
        Assert.Single(Routes(cfg));
    }

    [Fact]
    public void TheIdentityHeaders_AreEveryProvidersCopyHeaders()
    {
        var copied = SignInProviders.Profiles.Values.SelectMany(p => p.CopyHeaders).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.True(copied.SetEquals(SignInProviders.IdentityHeaders), string.Join(", ", SignInProviders.IdentityHeaders));
    }

    [Fact]
    public void ARuleWithoutSignIn_GetsNoForwardAuth()
    {
        var rule = Rule(SignInProviders.Authelia, r => r.SignInProvider = null);
        var cfg = CaddyConfigBuilder.Build([rule], new ProxyOptions());
        Assert.DoesNotContain(RuleRoute(cfg, rule)["handle"]!.AsArray(), h => h!["rewrite"] is not null);
        Assert.Single(Routes(cfg));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("no-verifier")]
    [InlineData("no-audience")]
    [InlineData("bad-control-plane")]
    public void AnIncompleteSignIn_DoesNotBuild(string flaw)
    {
        var rule = flaw switch
        {
            "unknown" => Rule(SignInProviders.Authelia, r => r.SignInProvider = "okta"),
            "no-verifier" => Rule(SignInProviders.Authelia, r => r.SignInVerifierUrl = null),
            "no-audience" => Rule(SignInProviders.CloudflareAccess, r => r.CloudflareAudience = null),
            _ => Rule(SignInProviders.CloudflareAccess),
        };
        var options = new ProxyOptions { ControlPlaneUrl = flaw == "bad-control-plane" ? "127.0.0.1:8080" : "http://127.0.0.1:8080" };
        Assert.Throws<InvalidOperationException>(() => CaddyConfigBuilder.Build([rule], options));
    }
}

public class SignInConflictTests
{
    private static ProxyRule R(string provider, string? verifier = null, string? prefix = null, string domain = "a.example.com") =>
        SignInBuilderTests.Rule(provider, r =>
        {
            if (verifier is not null) r.SignInVerifierUrl = verifier;
            r.PathPrefix = prefix;
        }, domain);

    [Fact]
    public void AHost_HasOneSignInCallback()
    {
        var a = R(SignInProviders.OAuth2Proxy, prefix: "/a");
        Assert.Empty(RoutePath.Conflicts([a, R(SignInProviders.OAuth2Proxy, prefix: "/b")]));
        Assert.Empty(RoutePath.Conflicts([a, R(SignInProviders.Authelia, "http://other:9091", "/b"), R(SignInProviders.CloudflareAccess, prefix: "/c")]));
        Assert.Empty(RoutePath.Conflicts([a, R(SignInProviders.Authentik, "http://other:9000", domain: "b.example.com")]));

        var otherVerifier = R(SignInProviders.OAuth2Proxy, "http://other:4180", "/b");
        Assert.Contains("one sign-in callback", Assert.Single(RoutePath.Conflicts([a, otherVerifier])));
        Assert.Contains("one sign-in callback", RoutePath.ConflictWith(otherVerifier, [a]));
        var authentik = R(SignInProviders.Authentik, prefix: "/b");
        Assert.Contains("one sign-in callback", RoutePath.ConflictWith(authentik, [a]));

        otherVerifier.Enabled = false;
        Assert.Empty(RoutePath.Conflicts([a, otherVerifier]));
        Assert.Null(RoutePath.ConflictWith(otherVerifier, [a]));
    }

    [Theory]
    [InlineData("/oauth2", true)]
    [InlineData("/OAuth2/start", true)]
    [InlineData("/oauth2x", false)]
    [InlineData("/app", false)]
    public void ARoute_UnderTheCallbackPath_IsRefused(string prefix, bool refused)
    {
        var signIn = R(SignInProviders.OAuth2Proxy);
        var other = new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.6", Enabled = true, EnableTls = false, PathPrefix = prefix };
        Assert.Equal(refused, RoutePath.Conflicts([signIn, other]).Any());
        Assert.Equal(refused, RoutePath.ConflictWith(other, [signIn]) is not null);
        Assert.Equal(refused, RoutePath.ConflictWith(signIn, [other]) is not null);
    }
}

/// <summary>A Cloudflare Access team for tests: an RSA signing key, its JWKS, and tokens signed with it.</summary>
internal sealed class AccessTeam : IDisposable
{
    public const string Team = "home.cloudflareaccess.com";
    public static readonly string Audience = string.Concat(Enumerable.Repeat("0123456789abcdef", 4));

    private readonly RSA _rsa = RSA.Create(2048);
    public string Kid { get; }

    public AccessTeam(string kid = "k1") => Kid = kid;

    public JsonObject Jwk()
    {
        var p = _rsa.ExportParameters(false);
        return new JsonObject
        {
            ["kid"] = Kid, ["kty"] = "RSA", ["alg"] = "RS256", ["use"] = "sig",
            ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent),
        };
    }

    public static string Jwks(params AccessTeam[] teams) =>
        new JsonObject { ["keys"] = new JsonArray([.. teams.Select(t => (JsonNode)t.Jwk())]) }.ToJsonString();

    public string Token(
        string? audience = null, string? issuer = null, DateTime? expires = null, string? email = "ops@example.com",
        string? kid = "", SecurityKey? signWith = null, string algorithm = SecurityAlgorithms.RsaSha256)
    {
        var exp = expires ?? DateTime.UtcNow.AddMinutes(10);
        var claims = new Dictionary<string, object> { ["type"] = "app" };
        if (email is not null) claims["email"] = email;
        var key = signWith ?? new RsaSecurityKey(_rsa) { KeyId = kid == "" ? Kid : kid };
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? "https://" + Team,
            Audience = audience ?? Audience,
            IssuedAt = exp.AddMinutes(-20),
            NotBefore = exp.AddMinutes(-20),
            Expires = exp,
            Claims = claims,
            SigningCredentials = new SigningCredentials(key, algorithm),
        });
    }

    public void Dispose() => _rsa.Dispose();
}

internal sealed class KeysHandler : HttpMessageHandler
{
    private readonly List<Uri> _requests = [];
    public Func<HttpResponseMessage> Respond { get; set; } = () => new HttpResponseMessage(HttpStatusCode.NotFound);

    public IReadOnlyList<Uri> Requests { get { lock (_requests) return [.. _requests]; } }

    public void Serve(string json) => Respond = () => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        lock (_requests) _requests.Add(request.RequestUri!);
        return Task.FromResult(Respond());
    }
}

internal sealed class StubHttpFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
}

public sealed class CloudflareAccessVerifierTests : IDisposable
{
    private readonly AccessTeam _team = new();
    private readonly KeysHandler _keys = new();
    private readonly ManualClock _clock = new(new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero));
    private readonly CloudflareAccessVerifier _verifier;

    public CloudflareAccessVerifierTests()
    {
        _keys.Serve(AccessTeam.Jwks(_team));
        _verifier = new CloudflareAccessVerifier(new StubHttpFactory(_keys), Options.Create(new ProxyOptions()), _clock,
            NullLogger<CloudflareAccessVerifier>.Instance);
    }

    public void Dispose() => _team.Dispose();

    private Task<CloudflareAccessResult> Verify(string? token, string audience = "") =>
        _verifier.VerifyAsync(AccessTeam.Team, audience == "" ? AccessTeam.Audience : audience, token, CancellationToken.None);

    [Fact]
    public async Task AToken_FromTheTeam_ForTheApplication_GivesItsEmail()
    {
        var result = await Verify(_team.Token());
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("ops@example.com", result.Email);
        Assert.Equal(new Uri("https://home.cloudflareaccess.com/cdn-cgi/access/certs"), Assert.Single(_keys.Requests));

        var service = await Verify(_team.Token(email: null));
        Assert.True(service.Ok, service.Reason);
        Assert.Null(service.Email);
    }

    public static TheoryData<string> Forgeries() => ["audience", "issuer", "expired", "other key", "tampered", "no key id", "unknown key id", "hs256", "none", "no token", "garbage", "oversize"];

    [Theory]
    [MemberData(nameof(Forgeries))]
    public async Task ATokenThatIsNotTheTeamsForTheApplication_IsRefused(string forgery)
    {
        using var other = new AccessTeam();
        var token = forgery switch
        {
            "audience" => _team.Token(audience: string.Concat(Enumerable.Repeat("fedcba9876543210", 4))),
            "issuer" => _team.Token(issuer: "https://other.cloudflareaccess.com"),
            "expired" => _team.Token(expires: DateTime.UtcNow.AddMinutes(-2)),
            "other key" => other.Token(),
            "tampered" => Tamper(_team.Token()),
            "no key id" => _team.Token(kid: null),
            "unknown key id" => _team.Token(kid: "k9"),
            "hs256" => _team.Token(signWith: new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)) { KeyId = "k1" }, algorithm: SecurityAlgorithms.HmacSha256),
            "none" => Unsigned(),
            "no token" => "",
            "garbage" => "not.a.token",
            _ => _team.Token(email: new string('x', CloudflareAccessVerifier.MaxTokenBytes)),
        };
        var result = await Verify(token);
        Assert.False(result.Ok, forgery);
        Assert.Null(result.Email);
    }

    private static string Tamper(string token)
    {
        var parts = token.Split('.');
        var payload = JsonNode.Parse(Base64UrlEncoder.Decode(parts[1]))!;
        payload["email"] = "admin@example.com";
        return $"{parts[0]}.{Base64UrlEncoder.Encode(payload.ToJsonString())}.{parts[2]}";
    }

    private string Unsigned()
    {
        var parts = _team.Token().Split('.');
        return $"{Base64UrlEncoder.Encode("""{"alg":"none","kid":"k1","typ":"JWT"}""")}.{parts[1]}.";
    }

    [Fact]
    public async Task Keys_AreKeptAnHour_AndAnUnknownKeyId_FetchesAgain_AtMostEvery30Seconds()
    {
        Assert.True((await Verify(_team.Token())).Ok);
        Assert.True((await Verify(_team.Token())).Ok);
        Assert.Single(_keys.Requests);

        using var rotated = new AccessTeam("k2");
        _keys.Serve(AccessTeam.Jwks(_team, rotated));
        Assert.False((await Verify(rotated.Token())).Ok);
        Assert.Single(_keys.Requests);

        _clock.Advance(CloudflareAccessVerifier.RefetchAfter);
        Assert.True((await Verify(rotated.Token())).Ok);
        Assert.Equal(2, _keys.Requests.Count);
        Assert.False((await Verify(_team.Token(kid: "k9"))).Ok);
        Assert.Equal(2, _keys.Requests.Count);

        _clock.Advance(CloudflareAccessVerifier.KeysFor);
        Assert.True((await Verify(_team.Token())).Ok);
        Assert.Equal(3, _keys.Requests.Count);
    }

    [Fact]
    public async Task WhenTheKeysCannotBeRead_TheLastOnesServeADay_ThenEveryTokenIsRefused()
    {
        Assert.True((await Verify(_team.Token())).Ok);
        _keys.Respond = () => new HttpResponseMessage(HttpStatusCode.BadGateway);

        _clock.Advance(TimeSpan.FromHours(2));
        Assert.True((await Verify(_team.Token())).Ok);
        Assert.Equal(2, _keys.Requests.Count);

        _clock.Advance(CloudflareAccessVerifier.MaxKeyAge);
        Assert.False((await Verify(_team.Token())).Ok);
    }

    [Fact]
    public async Task OversizeKeys_AreNotRead()
    {
        var padded = AccessTeam.Jwks(_team).Insert(1, $"\"pad\":\"{new string('x', CloudflareAccessVerifier.MaxKeysBytes)}\",");
        _keys.Serve(padded);
        Assert.False((await Verify(_team.Token())).Ok);

        _keys.Serve(AccessTeam.Jwks(_team));
        _clock.Advance(CloudflareAccessVerifier.RefetchAfter);
        Assert.True((await Verify(_team.Token())).Ok);
    }

    [Fact]
    public async Task TheCertsAddress_ComesFromTheTemplate()
    {
        var verifier = new CloudflareAccessVerifier(new StubHttpFactory(_keys),
            Options.Create(new ProxyOptions { CloudflareAccessCertsUrl = "http://127.0.0.1:9/{team}/certs" }), _clock,
            NullLogger<CloudflareAccessVerifier>.Instance);
        Assert.True((await verifier.VerifyAsync(AccessTeam.Team, AccessTeam.Audience, _team.Token(), CancellationToken.None)).Ok);
        Assert.Equal(new Uri("http://127.0.0.1:9/home.cloudflareaccess.com/certs"), Assert.Single(_keys.Requests));
    }
}

internal sealed class SignInFactory(bool requireMutualTls = false, bool passkeys = false) : WebApplicationFactory<Program>
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-signin-{Guid.NewGuid():N}.db");

    public KeysHandler Keys { get; } = new();

    public HttpClient Authed()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var admin = db.Users.First(u => u.Role == Role.Admin);
        var key = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
            .CreateAsync(admin.Id, "sign-in-tests", null).GetAwaiter().GetResult().PlaintextToken;
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", key);
        return client;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        builder.ConfigureTestServices(s =>
        {
            s.RemoveAll<IHostedService>();
            s.RemoveAll<IProxyController>();
            s.AddSingleton<IProxyController>(new FakeProxy());
            s.AddHttpClient(CloudflareAccessVerifier.ClientName).ConfigurePrimaryHttpMessageHandler(() => Keys);
        });

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureHostConfiguration(cfg =>
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                ["Security:RequireMutualTls"] = requireMutualTls ? "true" : "false",
                ["Passkeys:RelyingPartyId"] = passkeys ? "localhost" : null,
                ["Passkeys:Origins:0"] = passkeys ? "http://localhost" : null,
            }));
        return base.CreateHost(builder);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }
}

public sealed class SignInEndpointTests : IDisposable
{
    private readonly SignInFactory _factory = new();
    private readonly AccessTeam _team = new();
    private readonly HttpClient _admin;

    public SignInEndpointTests()
    {
        _admin = _factory.Authed();
        _factory.Keys.Serve(AccessTeam.Jwks(_team));
    }

    public void Dispose()
    {
        _team.Dispose();
        _factory.Dispose();
    }

    internal static async Task<string> NewServer(HttpClient admin)
    {
        var server = await admin.PostAsJsonAsync("/api/servers", new { name = $"S {Guid.NewGuid():N}", host = "192.0.2.20", os = "linux" });
        return (string)JsonNode.Parse(await server.Content.ReadAsStringAsync())!["id"]!;
    }

    internal static object Cloudflare => new { provider = "cloudflare-access", teamDomain = AccessTeam.Team, audience = AccessTeam.Audience };

    private static async Task<HttpResponseMessage> PostRule(HttpClient admin, string server, string domain, object? signIn, string? pathPrefix = null) =>
        await admin.PostAsJsonAsync($"/api/servers/{server}/rules", new
        {
            domain, upstreamUrl = "http://10.0.0.5", enableTls = false, enabled = true, signIn,
            routing = new { pathPrefix },
        });

    internal static async Task<JsonObject> AddRule(HttpClient admin, string server, string domain, object? signIn, string? pathPrefix = null)
    {
        var r = await PostRule(admin, server, domain, signIn, pathPrefix);
        Assert.True(r.StatusCode == HttpStatusCode.Created, await r.Content.ReadAsStringAsync());
        return JsonNode.Parse(await r.Content.ReadAsStringAsync())!.AsObject();
    }

    private static async Task<JsonObject> Errors(HttpResponseMessage r)
    {
        Assert.True(r.StatusCode == HttpStatusCode.BadRequest, await r.Content.ReadAsStringAsync());
        return JsonNode.Parse(await r.Content.ReadAsStringAsync())!["errors"]!.AsObject();
    }

    private HttpRequestMessage Check(string ruleId, params string[] tokens)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"/api/sign-in/cloudflare/{ruleId}");
        if (tokens.Length > 0) req.Headers.TryAddWithoutValidation(SignInProviders.CloudflareTokenHeader, tokens);
        return req;
    }

    [Theory]
    [InlineData("""{"provider":"okta"}""", "signIn.provider")]
    [InlineData("""{"provider":"authelia"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"authelia","verifierUrl":"http://authelia:9091/api"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"authelia","verifierUrl":"http://authelia:9091/?x=1"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"authelia","verifierUrl":"http://authelia:9091#f"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"authelia","verifierUrl":"http://u:p@authelia:9091"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"authentik","verifierUrl":"ftp://authentik"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"oauth2-proxy","verifierUrl":"http://169.254.169.254"}""", "signIn.verifierUrl")]
    [InlineData("""{"provider":"authelia","verifierUrl":"http://authelia:9091","teamDomain":"home.cloudflareaccess.com"}""", "signIn.teamDomain")]
    [InlineData("""{"provider":"cloudflare-access","teamDomain":"home.example.com","audience":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}""", "signIn.teamDomain")]
    [InlineData("""{"provider":"cloudflare-access","teamDomain":"home.cloudflareaccess.com","audience":"0123"}""", "signIn.audience")]
    [InlineData("""{"provider":"cloudflare-access","teamDomain":"home.cloudflareaccess.com","audience":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","verifierUrl":"http://x"}""", "signIn.verifierUrl")]
    public async Task ASignInThatCannotWork_IsRefused(string signIn, string field)
    {
        var server = await NewServer(_admin);
        var errors = await Errors(await PostRule(_admin, server, "v.example.com", JsonNode.Parse(signIn)));
        Assert.True(errors.ContainsKey(field), errors.ToJsonString());
    }

    [Fact]
    public async Task SignIn_IsKeptWhenLeftOut_AndClearedByABlockWithoutAProvider()
    {
        var server = await NewServer(_admin);
        var rule = await AddRule(_admin, server, "k.example.com", new { provider = "Authelia", verifierUrl = " http://authelia:9091/ " });
        var expected = JsonNode.Parse("""{"provider":"authelia","verifierUrl":"http://authelia:9091","teamDomain":null,"audience":null}""");
        Assert.True(JsonNode.DeepEquals(expected, rule["signIn"]), rule["signIn"]?.ToJsonString());

        async Task<JsonObject> Put(object? signIn)
        {
            var req = new HttpRequestMessage(HttpMethod.Put, $"/api/servers/{server}/rules/{rule!["id"]}")
            {
                Content = JsonContent.Create(new { domain = "k.example.com", upstreamUrl = "http://10.0.0.6", enableTls = false, enabled = true, signIn }),
            };
            req.Headers.TryAddWithoutValidation("If-Match", $"\"{(int)rule["version"]!}\"");
            var r = await _admin.SendAsync(req);
            Assert.True(r.IsSuccessStatusCode, await r.Content.ReadAsStringAsync());
            return rule = JsonNode.Parse(await r.Content.ReadAsStringAsync())!.AsObject();
        }

        Assert.Equal("authelia", (string?)(await Put(null))["signIn"]!["provider"]);
        Assert.Equal("cloudflare-access", (string?)(await Put(Cloudflare))["signIn"]!["provider"]);
        Assert.Null((await Put(Cloudflare))["signIn"]!["verifierUrl"]);
        Assert.Null((await Put(new { verifierUrl = "http://authelia:9091" }))["signIn"]);
    }

    [Fact]
    public async Task RulesOnAHost_ThatNeedTwoCallbacks_AreRefused()
    {
        var server = await NewServer(_admin);
        await AddRule(_admin, server, "c.example.com", new { provider = "oauth2-proxy", verifierUrl = "http://oauth2:4180" });
        var errors = await Errors(await PostRule(_admin, server, "c.example.com", new { provider = "oauth2-proxy", verifierUrl = "http://other:4180" }, "/b"));
        Assert.Contains("one sign-in callback", (string?)errors["domain"]![0]);
        errors = await Errors(await PostRule(_admin, server, "c.example.com", null, "/oauth2/x"));
        Assert.Contains("/oauth2", (string?)errors["domain"]![0]);
        await AddRule(_admin, server, "c.example.com", new { provider = "oauth2-proxy", verifierUrl = "http://oauth2:4180/" }, "/b");
    }

    [Fact]
    public async Task ABackup_CarriesSignIn_AndAnImportChangesIt()
    {
        var server = await NewServer(_admin);
        var rule = await AddRule(_admin, server, "b.example.com", Cloudflare);
        var document = JsonNode.Parse(await _admin.GetStringAsync("/api/backup"))!;
        var exported = document["servers"]!.AsArray().SelectMany(s => s!["rules"]!.AsArray()).Single(r => (string?)r!["id"] == (string?)rule["id"])!;
        var expected = JsonNode.Parse($$"""{"provider":"cloudflare-access","verifierUrl":null,"teamDomain":"{{AccessTeam.Team}}","audience":"{{AccessTeam.Audience}}"}""");
        Assert.True(JsonNode.DeepEquals(expected, exported["signIn"]), exported["signIn"]?.ToJsonString());

        exported["signIn"] = JsonNode.Parse("""{"provider":"authelia","verifierUrl":"http://authelia:9091"}""");
        var dry = JsonNode.Parse(await (await _admin.PostAsJsonAsync("/api/backup/import/dry-run", new { document, mode = "merge" })).Content.ReadAsStringAsync())!;
        var fields = dry["changes"]!.AsArray().Single()!["fields"]!.AsArray().Select(f => (string?)f!["field"]).ToList();
        Assert.Contains("signIn.provider", fields);
        Assert.Contains("signIn.verifierUrl", fields);

        exported["signIn"] = JsonNode.Parse("""{"provider":"authelia"}""");
        dry = JsonNode.Parse(await (await _admin.PostAsJsonAsync("/api/backup/import/dry-run", new { document, mode = "merge" })).Content.ReadAsStringAsync())!;
        Assert.Contains(dry["problems"]!.AsObject(), p => p.Key.EndsWith(".signIn.verifierUrl", StringComparison.Ordinal));

        exported["signIn"] = null;
        dry = JsonNode.Parse(await (await _admin.PostAsJsonAsync("/api/backup/import/dry-run", new { document, mode = "merge" })).Content.ReadAsStringAsync())!;
        var import = await _admin.PostAsJsonAsync("/api/backup/import", new { document, mode = "merge", revision = (string?)dry["revision"] });
        Assert.True(import.IsSuccessStatusCode, await import.Content.ReadAsStringAsync());
        var rules = JsonNode.Parse(await _admin.GetStringAsync($"/api/servers/{server}/rules"))!.AsArray();
        Assert.Null(rules.Single()!["signIn"]);
    }

    [Fact]
    public async Task TheCloudflareCheck_AnswersForItsRule_WithTheEmail()
    {
        var server = await NewServer(_admin);
        var rule = (string)(await AddRule(_admin, server, "cf.example.com", Cloudflare))["id"]!;
        var authelia = (string)(await AddRule(_admin, server, "au.example.com", new { provider = "authelia", verifierUrl = "http://authelia:9091" }))["id"]!;
        var anon = _factory.CreateClient();

        var ok = await anon.SendAsync(Check(rule, _team.Token()));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal("ops@example.com", Assert.Single(ok.Headers.GetValues(SignInProviders.CloudflareEmailHeader)));

        var service = await anon.SendAsync(Check(rule, _team.Token(email: null)));
        Assert.Equal(HttpStatusCode.OK, service.StatusCode);
        Assert.False(service.Headers.Contains(SignInProviders.CloudflareEmailHeader));
        var odd = await anon.SendAsync(Check(rule, _team.Token(email: "a@example.comé")));
        Assert.Equal(HttpStatusCode.OK, odd.StatusCode);
        Assert.False(odd.Headers.Contains(SignInProviders.CloudflareEmailHeader));

        foreach (var refused in new[]
        {
            Check(rule), Check(rule, _team.Token(audience: new string('f', 64))), Check(rule, _team.Token(), _team.Token()),
            Check(authelia, _team.Token()), Check(Guid.NewGuid().ToString(), _team.Token()),
        })
        {
            var r = await anon.SendAsync(refused);
            Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
            Assert.Equal("Sign-in required.", await r.Content.ReadAsStringAsync());
            Assert.False(r.Headers.Contains(SignInProviders.CloudflareEmailHeader));
        }
    }

    [Fact]
    public async Task TheCloudflareCheck_PassesOverTheProxiedRequestsCredentials_AndIsNotRateLimited()
    {
        var server = await NewServer(_admin);
        var rule = (string)(await AddRule(_admin, server, "cf.example.com", Cloudflare))["id"]!;
        var anon = _factory.CreateClient();

        // The same credentials are refused by the control plane's own endpoints.
        var control = new HttpRequestMessage(HttpMethod.Get, "/api/servers");
        control.Headers.TryAddWithoutValidation("X-Api-Key", "sslrp_not-a-key");
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.SendAsync(control)).StatusCode);

        var req = Check(rule, _team.Token());
        req.Headers.TryAddWithoutValidation("X-Api-Key", "sslrp_not-a-key");
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer upstream-app-token");
        Assert.Equal(HttpStatusCode.OK, (await anon.SendAsync(req)).StatusCode);

        var token = _team.Token();
        for (var i = 0; i < 120; i++)
            Assert.Equal(HttpStatusCode.OK, (await anon.SendAsync(Check(rule, token))).StatusCode);
    }

    private async Task<string> SeedCloudflareRule(SignInFactory factory)
    {
        factory.Keys.Serve(AccessTeam.Jwks(_team));
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var s = new ProxyServer { Name = "S", Host = "192.0.2.20", Os = "linux" };
        db.Servers.Add(s);
        var r = SignInBuilderTests.Rule(SignInProviders.CloudflareAccess, x => x.ServerId = s.Id);
        db.Rules.Add(r);
        await db.SaveChangesAsync();
        return r.Id.ToString();
    }

    [Fact]
    public async Task UnderMutualTls_TheCloudflareCheck_NeedsNoClientCertificate()
    {
        using var factory = new SignInFactory(requireMutualTls: true);
        var rule = await SeedCloudflareRule(factory);
        var anon = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Forbidden, (await anon.GetAsync("/api/servers")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.SendAsync(Check(rule, _team.Token()))).StatusCode);
    }

    [Fact]
    public async Task TheCloudflareCheck_LeavesTheProxiedRequestsSessionCookieAlone()
    {
        using var factory = new SignInFactory(passkeys: true);
        var rule = await SeedCloudflareRule(factory);
        var anon = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        var cookie = $"{SslReverseProxy.Api.Auth.SessionTokens.CookieName}=sps.not-a-session";

        // The control plane's own endpoints clear a cookie that does not sign in.
        var control = new HttpRequestMessage(HttpMethod.Get, "/api/servers");
        control.Headers.TryAddWithoutValidation("Cookie", cookie);
        var refused = await anon.SendAsync(control);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.True(refused.Headers.Contains("Set-Cookie"));

        var req = Check(rule, _team.Token());
        req.Headers.TryAddWithoutValidation("Cookie", cookie);
        var ok = await anon.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.False(ok.Headers.Contains("Set-Cookie"));
    }
}
