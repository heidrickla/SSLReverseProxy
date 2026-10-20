using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Health;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class CertificateNameTests
{
    [Theory]
    [InlineData(" App.Example.COM. ", "app.example.com")]
    [InlineData("*.Example.com", "*.example.com")]
    public void Normalize_TrimsLowersAndDropsTheRootDot(string input, string expected) =>
        Assert.Equal(expected, CertificateNames.Normalize(input));

    [Theory]
    [InlineData("app.example.com", true)]
    [InlineData("localhost", true)]
    [InlineData("*.example.com", true)]
    [InlineData("*.com", false)]
    [InlineData("a*.example.com", false)]
    [InlineData("*.*.example.com", false)]
    [InlineData("10.0.0.5", false)]
    [InlineData("bad name.example.com", false)]
    [InlineData("", false)]
    public void Problem_AcceptsHostnamesAndWildcardsOnly(string input, bool ok) =>
        Assert.Equal(ok, CertificateNames.Problem(input) is null);

    [Fact]
    public void ProbeHost_AsksForAWildcardWithALabelInFront()
    {
        Assert.Equal("sslrp-check.example.com", CertificateNames.ProbeHost("*.example.com"));
        Assert.Equal("a.example.com", CertificateNames.ProbeHost("a.example.com"));
    }
}

public class CloudflareTokenTests
{
    [Theory]
    [InlineData(null, "is not set")]
    [InlineData("  ", "is not set")]
    [InlineData("abc", "format")]
    [InlineData("has space aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "format")]
    [InlineData("{env.X}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "format")]
    public void Problem_NamesTheSettingNeverTheValue(string? token, string expected)
    {
        var problem = CloudflareToken.Problem(new ProxyOptions { CloudflareApiToken = token });
        Assert.NotNull(problem);
        Assert.Contains(expected, problem);
        if (!string.IsNullOrWhiteSpace(token)) Assert.DoesNotContain(token.Trim(), problem);
    }

    [Theory]
    [InlineData("0123456789abcdefghij0123456789abcdefghij")]
    [InlineData("cfut_0123456789abcdefghij0123456789abcdefghij")]
    [InlineData("cfat_0123456789abcdefghij0123456789abcdefghij")]
    public void Usable_AcceptsTheShapesCloudflareIssues(string token) =>
        Assert.True(CloudflareToken.Usable(new ProxyOptions { CloudflareApiToken = token }));
}

public class CertificateConfigTests
{
    internal const string Token = "cfut_0123456789abcdefghij0123456789abcdefghij";

    private static ProxyRule Rule(string domain) =>
        new() { Domain = domain, UpstreamUrl = "http://10.0.0.5", Enabled = true, EnableTls = true };

    private static CertificatePlan Manual(string domain, CertificateChallenge challenge = CertificateChallenge.Http, bool renew = false) =>
        new(domain, challenge, Automate: true, RenewPending: renew);

    private static JsonObject Build(ProxyOptions options, params CertificatePlan[] certs) =>
        CaddyConfigBuilder.Build(new ProxyPlan([], certs), options);

    private static JsonObject Tls(JsonObject cfg) => cfg["apps"]!["tls"]!.AsObject();

    private static string[] Automated(JsonObject cfg) =>
        Tls(cfg)["certificates"]?["automate"]?.AsArray().Select(n => (string)n!).ToArray() ?? [];

    [Fact]
    public void RenewInterval_IsInEveryConfig()
    {
        var cfg = CaddyConfigBuilder.Build([], new ProxyOptions { RenewCheckSeconds = 30 });
        Assert.Equal("30s", (string?)Tls(cfg)["automation"]!["renew_interval"]);
    }

    [Fact]
    public void ManualName_IsAutomated_AndGetsAnHttpsListener()
    {
        var cfg = Build(new ProxyOptions(), Manual("m.example.com"));
        Assert.Equal(["m.example.com"], Automated(cfg));
        Assert.NotNull(cfg["apps"]!["http"]!["servers"]![CaddyConfigBuilder.HttpsServer]!["tls_connection_policies"]);
    }

    [Fact]
    public void RuleRow_IsNotAutomated()
    {
        var cfg = CaddyConfigBuilder.Build(new ProxyPlan([Rule("a.example.com")],
            [new CertificatePlan("a.example.com", CertificateChallenge.Http, Automate: false, RenewPending: false)]), new ProxyOptions());
        Assert.Empty(Automated(cfg));
    }

    [Fact]
    public void Wildcard_NeedsTheDnsChallengeOrTheInternalCa()
    {
        Assert.Empty(Automated(Build(new ProxyOptions(), Manual("*.example.com"))));
        Assert.Empty(Automated(Build(new ProxyOptions(), Manual("*.example.com", CertificateChallenge.DnsCloudflare))));
        Assert.Equal(["*.example.com"], Automated(Build(new ProxyOptions { CloudflareApiToken = Token },
            Manual("*.example.com", CertificateChallenge.DnsCloudflare))));
        Assert.Equal(["*.example.com"], Automated(Build(new ProxyOptions { CertificateIssuer = "internal" }, Manual("*.example.com"))));
    }

    [Fact]
    public void DnsPolicy_ReadsTheTokenFromCaddysEnvironment()
    {
        var cfg = Build(new ProxyOptions { CloudflareApiToken = Token, DnsChallengeResolvers = "1.1.1.1:53, 1.0.0.1:53", AcmeContactEmail = "ops@example.com" },
            Manual("*.example.com", CertificateChallenge.DnsCloudflare));
        var json = cfg.ToJsonString();
        Assert.DoesNotContain(Token, json);

        var policies = Tls(cfg)["automation"]!["policies"]!.AsArray();
        Assert.Equal(2, policies.Count);
        Assert.Equal("*.example.com", (string?)policies[0]!["subjects"]![0]);
        var issuer = policies[0]!["issuers"]![0]!;
        Assert.Equal("acme", (string?)issuer["module"]);
        Assert.Equal("ops@example.com", (string?)issuer["email"]);
        var dns = issuer["challenges"]!["dns"]!;
        Assert.Equal("cloudflare", (string?)dns["provider"]!["name"]);
        Assert.Equal("{env." + CaddyEnvironment.CloudflareTokenVariable + "}", (string?)dns["provider"]!["api_token"]);
        Assert.Equal(["1.1.1.1:53", "1.0.0.1:53"], dns["resolvers"]!.AsArray().Select(n => (string)n!));
        // The catch-all comes last, so certmagic matches the subject policy first.
        Assert.Null(policies[1]!["subjects"]);
    }

    [Fact]
    public void MalformedToken_LeavesDnsNamesOutOfTheConfig()
    {
        const string bad = "not a token value 0123456789";
        var json = Build(new ProxyOptions { CloudflareApiToken = bad }, Manual("d.example.com", CertificateChallenge.DnsCloudflare)).ToJsonString();
        Assert.DoesNotContain("cloudflare", json);
        Assert.DoesNotContain("d.example.com", json);
        Assert.DoesNotContain(bad, json);
    }

    [Fact]
    public void PendingRenewal_GetsAOneNamePolicyThatIsDueAtOnce()
    {
        var plan = new ProxyPlan([Rule("a.example.com")],
            [new CertificatePlan("a.example.com", CertificateChallenge.Http, Automate: false, RenewPending: true)]);
        var policies = Tls(CaddyConfigBuilder.Build(plan, new ProxyOptions { CertificateIssuer = "internal" }))["automation"]!["policies"]!.AsArray();
        Assert.Equal("a.example.com", (string?)policies[0]!["subjects"]![0]);
        Assert.Equal(CaddyConfigBuilder.ForcedRenewalRatio, (double)policies[0]!["renewal_window_ratio"]!);
        Assert.Equal("internal", (string?)policies[0]!["issuers"]![0]!["module"]);
        Assert.Null(policies[1]!["subjects"]);

        var kept = CaddyConfigBuilder.Build(plan.WithoutPendingRenewals(), new ProxyOptions()).ToJsonString();
        Assert.DoesNotContain("renewal_window_ratio", kept);
    }

    [Fact]
    public void SnapshotPlan_DropsOnlyThePendingMark()
    {
        var plan = new ProxyPlan([], [Manual("m.example.com", renew: true)]);
        var kept = plan.WithoutPendingRenewals();
        Assert.Equal([Manual("m.example.com")], kept.Certificates);
        Assert.True(plan.Certificates.Single().RenewPending);
    }
}

public class CaddyCertificateLogTests
{
    private const string Secret = "cfut_0123456789abcdefghij0123456789abcdefghij";
    private readonly CaddyCertificateLog _log = new(new SecretRedactor([Secret]), TimeProvider.System);

    private static string Line(string level, string logger, string msg, string identifier, string? error = null)
    {
        var o = new JsonObject { ["level"] = level, ["ts"] = 1.5, ["logger"] = logger, ["msg"] = msg, ["identifier"] = identifier };
        if (error is not null) o["error"] = error;
        return o.ToJsonString();
    }

    [Fact]
    public void Failure_IsRecordedRedactedAndCut()
    {
        _log.Observe(Line("error", "tls.obtain", "could not get certificate from issuer", "A.Example.com",
            $"token {Secret} refused " + new string('x', 900)));
        var outcome = _log.Latest("a.example.com");
        Assert.NotNull(outcome?.Error);
        Assert.DoesNotContain(Secret, outcome!.Error);
        Assert.Contains(SecretRedactor.Mask, outcome.Error);
        Assert.True(outcome.Error!.Length <= CaddyCertificateLog.MaxErrorLength + 1);
    }

    [Theory]
    [InlineData("tls.obtain", "certificate obtained successfully")]
    [InlineData("tls.renew", "certificate renewed successfully")]
    public void Success_ClearsAFailure(string logger, string msg)
    {
        _log.Observe(Line("error", "tls.obtain", "could not get certificate from issuer", "a.example.com", "boom"));
        _log.Observe(Line("info", logger, msg, "a.example.com"));
        Assert.Null(_log.Latest("a.example.com")!.Error);
    }

    [Fact]
    public void UnlockErrorsAndOtherLines_AreIgnored()
    {
        _log.Observe(Line("info", "tls.renew", "certificate renewed successfully", "a.example.com"));
        _log.Observe(Line("error", "tls.renew", "unable to unlock", "a.example.com", "remove lock: access denied"));
        _log.Observe(Line("error", "http.log", "could not get certificate from issuer", "a.example.com", "x"));
        _log.Observe("{\"logger\":\"tls.obtain\", not json");
        _log.Observe("plain text");
        Assert.Null(_log.Latest("a.example.com")!.Error);
        Assert.Null(_log.Latest("b.example.com"));
    }
}

public class CertificateProbeTests
{
    private static X509Certificate2 SelfSigned(params string[] names)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={names[0]}", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in names) san.AddDnsName(n);
        req.CertificateExtensions.Add(san.Build());
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public void Describe_ReadsTheLeafAndWhetherItCoversTheName()
    {
        using var cert = SelfSigned("a.example.com");
        var d = TlsCertificateProbe.Describe(cert, "a.example.com");
        Assert.True(d.MatchesName);
        Assert.Equal(cert.SerialNumber, d.Serial);
        Assert.Equal("ECDSA 256", d.Algorithm);
        Assert.Equal("a.example.com", d.Issuer);
        Assert.Equal(cert.NotAfter.ToUniversalTime(), d.NotAfter.UtcDateTime);
        Assert.False(TlsCertificateProbe.Describe(cert, "b.example.com").MatchesName);
    }

    [Fact]
    public void Describe_MatchesAWildcardThroughItsProbeName()
    {
        using var cert = SelfSigned("*.example.com");
        Assert.True(TlsCertificateProbe.Describe(cert, CertificateNames.ProbeHost("*.example.com")).MatchesName);
        Assert.False(TlsCertificateProbe.Describe(cert, "example.com").MatchesName);
    }

    [Fact]
    public async Task ReadAsync_ReturnsNullWhenNothingListens()
    {
        var port = FreePort();
        var probe = new TlsCertificateProbe(Options.Create(new ProxyOptions { HttpsPort = port }));
        Assert.Null(await probe.ReadAsync("a.example.com", CancellationToken.None));
    }

    private static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}

/// <summary>The certificate monitor and endpoints, with the proxy and the TLS probe replaced by fakes.</summary>
public class CertificateMonitorTests : IDisposable
{
    private readonly CertificateFactory _factory = new(CertificateConfigTests.Token);

    public void Dispose() => _factory.Dispose();

    private async Task<T> WithDb<T>(Func<AppDbContext, Task<T>> f)
    {
        using var scope = _factory.Services.CreateScope();
        return await f(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    private Task Check() => _factory.Services.GetRequiredService<CertificateMonitor>().CheckAllAsync(CancellationToken.None);

    private async Task<Guid> AddRule(string domain, bool enabled = true)
    {
        return await WithDb(async db =>
        {
            var server = new ProxyServer { Name = $"s-{Guid.NewGuid():N}", Host = "192.0.2.9", Os = "linux" };
            var rule = new ProxyRule { Domain = domain, UpstreamUrl = "http://10.0.0.5", EnableTls = true, Enabled = enabled };
            server.Rules.Add(rule);
            db.Servers.Add(server);
            await db.SaveChangesAsync();
            return rule.Id;
        });
    }

    private Task<Certificate?> Row(string domain) =>
        WithDb(db => db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.Domain == domain));

    private ServedCertificate Serve(string domain, string serial, int daysLeft = 60)
    {
        var now = _factory.Clock.GetUtcNow();
        // A 90-day certificate, as Let's Encrypt issues.
        var served = new ServedCertificate(serial, now.AddDays(daysLeft - 90), now.AddDays(daysLeft), "Test CA", "ECDSA 256", true);
        _factory.Probe.Served[domain] = served;
        return served;
    }

    [Fact]
    public async Task Sync_FollowsTheEnabledTlsRules()
    {
        var ruleId = await AddRule("A.Example.com");
        await AddRule("off.example.com", enabled: false);
        await Check();

        var row = await Row("a.example.com");
        Assert.Equal(CertificateSource.Rule, row!.Source);
        Assert.Null(await Row("off.example.com"));

        await WithDb(async db => await db.Rules.Where(r => r.Id == ruleId).ExecuteDeleteAsync());
        await Check();
        Assert.Null(await Row("a.example.com"));
    }

    [Fact]
    public async Task ServedCertificate_SetsTheRowFromWhatClientsGet()
    {
        await AddRule("a.example.com");
        await AddRule("b.example.com");
        var served = Serve("a.example.com", "0A1B", daysLeft: 60);
        Serve("b.example.com", "0C2D", daysLeft: 10);
        await Check();

        var a = await Row("a.example.com");
        Assert.Equal(CertificateStatus.Valid, a!.Status);
        Assert.Equal(("0A1B", "Test CA", "ECDSA 256"), (a.SerialNumber, a.Issuer, a.Algorithm));
        Assert.Equal(served.NotAfter, a.ExpiresAt);
        Assert.Equal(_factory.Clock.GetUtcNow(), a.CheckedAt);
        Assert.Equal(CertificateStatus.Expiring, (await Row("b.example.com"))!.Status);
        Assert.Contains(_factory.Events.Published, e => e.Type == "certificate.status" && e.Message == "a.example.com is valid");
    }

    [Fact]
    public async Task NoCertificate_IsIssuingUntilCaddyLogsAFailure()
    {
        await AddRule("a.example.com");
        // Caddy answers with some other certificate.
        _factory.Probe.Served["a.example.com"] = Serve("other.example.com", "FF") with { MatchesName = false };
        await Check();
        Assert.Equal(CertificateStatus.Issuing, (await Row("a.example.com"))!.Status);

        _factory.Log.Observe(new JsonObject
        {
            ["level"] = "error", ["logger"] = "tls.obtain", ["msg"] = "could not get certificate from issuer",
            ["identifier"] = "a.example.com", ["error"] = $"HTTP 403 for token {CertificateConfigTests.Token}",
        }.ToJsonString());
        await Check();
        var row = await Row("a.example.com");
        Assert.Equal(CertificateStatus.Failed, row!.Status);
        Assert.Contains("HTTP 403", row.LastError);
        Assert.DoesNotContain(CertificateConfigTests.Token, row.LastError);
    }

    [Fact]
    public async Task StoppedProxy_LeavesTheLastReading()
    {
        await AddRule("a.example.com");
        Serve("a.example.com", "0A");
        _factory.Proxy.State = ProxyState.Stopped;
        await Check();
        var row = await Row("a.example.com");
        Assert.Null(row!.CheckedAt);
        Assert.Null(row.SerialNumber);
    }

    [Fact]
    public async Task UnusableDnsChallenge_IsReportedOnTheRow()
    {
        using var noToken = new CertificateFactory(cloudflareToken: null);
        using (var scope = noToken.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Certificates.Add(new Certificate { Domain = "*.example.com", Source = CertificateSource.Manual, Challenge = CertificateChallenge.DnsCloudflare });
            await db.SaveChangesAsync();
        }
        await noToken.Services.GetRequiredService<CertificateMonitor>().CheckAllAsync(CancellationToken.None);
        using (var scope = noToken.Services.CreateScope())
        {
            var row = await scope.ServiceProvider.GetRequiredService<AppDbContext>().Certificates.SingleAsync();
            Assert.Equal(CertificateStatus.Failed, row.Status);
            Assert.Equal("Proxy:CloudflareApiToken is not set.", row.LastError);
        }
    }

    [Fact]
    public async Task ForcedRenewal_EndsOnANewSerial_AndDropsTheMark()
    {
        var client = _factory.Authed();
        await AddRule("a.example.com");
        Serve("a.example.com", "0A");
        await Check();
        var id = (await Row("a.example.com"))!.Id;

        var res = await client.PostAsync($"/api/certificates/{id}/renew", null);
        Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
        var row = await Row("a.example.com");
        Assert.Equal("0A", row!.RenewFromSerial);
        Assert.True(_factory.Proxy.Applied.Last().Certificates.Single(c => c.Domain == "a.example.com").RenewPending);

        // Caddy has not renewed yet: the mark stays.
        await Check();
        Assert.NotNull((await Row("a.example.com"))!.RenewFromSerial);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsync($"/api/certificates/{id}/renew", null)).StatusCode);

        Serve("a.example.com", "0B");
        var applied = _factory.Proxy.Applied.Count;
        await Check();
        row = await Row("a.example.com");
        Assert.Null(row!.RenewFromSerial);
        Assert.Equal("0B", row.SerialNumber);
        Assert.Equal(applied + 1, _factory.Proxy.Applied.Count);
        Assert.False(_factory.Proxy.Applied.Last().Certificates.Single(c => c.Domain == "a.example.com").RenewPending);
        Assert.Contains(_factory.Events.Published, e => e.Type == "certificate.renewed");

        // The next forced renewal waits Proxy:RenewMinimumAgeMinutes after the last request.
        var again = await client.PostAsync($"/api/certificates/{id}/renew", null);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Contains("may be requested", await again.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ForcedRenewal_TimesOutWithAnError()
    {
        var client = _factory.Authed();
        await AddRule("a.example.com");
        Serve("a.example.com", "0A");
        await Check();
        var id = (await Row("a.example.com"))!.Id;
        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsync($"/api/certificates/{id}/renew", null)).StatusCode);

        _factory.Clock.Advance(TimeSpan.FromMinutes(11));
        Serve("a.example.com", "0A");
        await Check();
        var row = await Row("a.example.com");
        Assert.Null(row!.RenewFromSerial);
        Assert.Contains("No new certificate was served within 10 minutes", row.LastError);
        Assert.Equal(CertificateStatus.Valid, row.Status);
        Assert.False(_factory.Proxy.Applied.Last().Certificates.Single().RenewPending);
        Assert.Contains(_factory.Events.Published, e => e.Type == "certificate.renew_failed");
    }

    [Fact]
    public async Task Renew_IsRefusedWhenThereIsNothingToRenew()
    {
        var client = _factory.Authed();
        var id = await WithDb(async db =>
        {
            var c = new Certificate { Domain = "m.example.com", Source = CertificateSource.Manual };
            db.Certificates.Add(c);
            await db.SaveChangesAsync();
            return c.Id;
        });

        var none = await client.PostAsync($"/api/certificates/{id}/renew", null);
        Assert.Equal(HttpStatusCode.Conflict, none.StatusCode);
        Assert.Contains("nothing to renew", await none.Content.ReadAsStringAsync());

        Serve("m.example.com", "0A");
        _factory.Proxy.State = ProxyState.Stopped;
        var stopped = await client.PostAsync($"/api/certificates/{id}/renew", null);
        Assert.Equal(HttpStatusCode.Conflict, stopped.StatusCode);
        Assert.Contains("stopped", await stopped.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync($"/api/certificates/{Guid.NewGuid()}/renew", null)).StatusCode);
    }

    [Fact]
    public async Task Create_ValidatesAndNormalisesTheName()
    {
        var client = _factory.Authed();
        async Task<HttpResponseMessage> Create(string domain, string? challenge = null) =>
            await client.PostAsJsonAsync("/api/certificates", new { domain, challenge });

        Assert.Equal(HttpStatusCode.BadRequest, (await Create("bad name")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Create("*.com", "DnsCloudflare")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Create("x.example.com", "5")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Create("x.example.com", "Smtp")).StatusCode);
        var wildcardHttp = await Create("*.example.com", "Http");
        Assert.Equal(HttpStatusCode.BadRequest, wildcardHttp.StatusCode);
        Assert.Contains("DnsCloudflare", await wildcardHttp.Content.ReadAsStringAsync());

        var created = await Create("Site.Example.COM.");
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await created.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal("site.example.com", (string?)body!["domain"]);
        Assert.Equal("Manual", (string?)body["source"]);
        Assert.Equal("Http", (string?)body["challenge"]);
        Assert.True(_factory.Proxy.Applied.Last().Certificates.Single(c => c.Domain == "site.example.com").Automate);

        Assert.Equal(HttpStatusCode.Conflict, (await Create("site.example.com")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await Create("*.example.com", "dnscloudflare")).StatusCode);
    }

    [Fact]
    public async Task Create_RefusesTheDnsChallengeWithoutAToken()
    {
        using var noToken = new CertificateFactory(cloudflareToken: null);
        var res = await noToken.Authed().PostAsJsonAsync("/api/certificates", new { domain = "*.example.com", challenge = "DnsCloudflare" });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Contains("Proxy:CloudflareApiToken is not set.", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenges_SayWhatIsAvailable_WithoutTheToken()
    {
        var text = await _factory.Authed().GetStringAsync("/api/certificates/challenges");
        Assert.DoesNotContain(CertificateConfigTests.Token, text);
        var list = JsonNode.Parse(text)!.AsArray();
        Assert.Equal(["Http:true:false", "DnsCloudflare:true:true"],
            list.Select(n => $"{n!["name"]}:{n["available"]}:{n["wildcard"]}"));
    }

    [Fact]
    public async Task Update_ChangesTheChallenge_AndDeleteSparesRuleRows()
    {
        var client = _factory.Authed();
        await AddRule("a.example.com");
        await Check();
        var id = (await Row("a.example.com"))!.Id;

        var put = await client.PutAsJsonAsync($"/api/certificates/{id}", new { challenge = "DnsCloudflare" });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        Assert.Equal(CertificateChallenge.DnsCloudflare, (await Row("a.example.com"))!.Challenge);

        var del = await client.DeleteAsync($"/api/certificates/{id}");
        Assert.Equal(HttpStatusCode.Conflict, del.StatusCode);
        Assert.NotNull(await Row("a.example.com"));

        var manual = await (await client.PostAsJsonAsync("/api/certificates", new { domain = "m.example.com" })).Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/certificates/{manual!["id"]}")).StatusCode);
        Assert.Null(await Row("m.example.com"));
    }

    [Fact]
    public async Task List_DerivesStatusFromTheDates()
    {
        await WithDb(async db =>
        {
            db.Certificates.Add(new Certificate
            {
                Domain = "old.example.com", Status = CertificateStatus.Valid,
                ExpiresAt = _factory.Clock.GetUtcNow().AddDays(-1),
            });
            db.Certificates.Add(new Certificate { Domain = "new.example.com" });
            return await db.SaveChangesAsync();
        });
        var list = (await _factory.Authed().GetFromJsonAsync<JsonArray>("/api/certificates"))!;
        Assert.Equal(["new.example.com:Unknown", "old.example.com:Expired"],
            list.Select(n => $"{n!["domain"]}:{n["status"]}"));
    }
}

internal sealed class CertificateFactory(string? cloudflareToken) : WebApplicationFactory<Program>
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-certs-{Guid.NewGuid():N}.db");

    public FakeProxy Proxy { get; } = new();
    public FakeProbe Probe { get; } = new();
    public ManualClock Clock { get; } = new(new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero));
    public RecordingEvents Events { get; } = new();
    public CaddyCertificateLog Log => Services.GetRequiredService<CaddyCertificateLog>();

    public HttpClient Authed()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var admin = db.Users.First(u => u.Role == Role.Admin);
        var key = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
            .CreateAsync(admin.Id, "certificate-tests", null).GetAwaiter().GetResult().PlaintextToken;
        var client = CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", key);
        return client;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        builder.ConfigureTestServices(s =>
        {
            // The tests run each monitor cycle themselves.
            s.RemoveAll<IHostedService>();
            s.RemoveAll<IProxyController>();
            s.AddSingleton<IProxyController>(Proxy);
            s.RemoveAll<ICertificateProbe>();
            s.AddSingleton<ICertificateProbe>(Probe);
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(Clock);
            s.RemoveAll<IEventStream>();
            s.AddSingleton<IEventStream>(Events);
        });

    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureHostConfiguration(cfg =>
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                ["Proxy:CloudflareApiToken"] = cloudflareToken,
            }));
        return base.CreateHost(builder);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
    }
}

internal sealed class FakeProxy : IProxyController
{
    public volatile ProxyState State = ProxyState.Running;
    public ConcurrentQueue<ProxyPlan> AppliedQueue { get; } = new();
    public List<ProxyPlan> Applied => AppliedQueue.ToList();

    private ProxyStatus Status() => new(State, "fake", null, null, 0, null);

    public Task<ProxyStatus> GetStatusAsync(CancellationToken ct = default) => Task.FromResult(Status());
    public Task<ProxyStatus> StartAsync(CancellationToken ct = default) => Task.FromResult(Status());
    public Task<ProxyStatus> StopAsync(CancellationToken ct = default) => Task.FromResult(Status());

    public Task<ProxyStatus> ApplyConfigurationAsync(ProxyPlan plan, CancellationToken ct = default)
    {
        AppliedQueue.Enqueue(plan);
        return Task.FromResult(Status());
    }

    public string BuildConfigJson(ProxyPlan plan) => CaddyConfigBuilder.Build(plan, new ProxyOptions()).ToJsonString();
    public Task<ProxyValidationResult> ValidateConfigurationAsync(ProxyPlan plan, CancellationToken ct = default) =>
        Task.FromResult(new ProxyValidationResult(true, [], false));
    public Task<ProxyStatus> ApplyRawConfigAsync(string configJson, CancellationToken ct = default) => Task.FromResult(Status());
    public Task<MetricsSnapshot> GetMetricsAsync(CancellationToken ct = default) =>
        Task.FromResult(new MetricsSnapshot(DateTimeOffset.UtcNow, false, 0, 0, new Dictionary<string, double>(), null));
    public Task CaptureTrafficAsync(CancellationToken ct = default) => Task.CompletedTask;
}

internal sealed class FakeProbe : ICertificateProbe
{
    public ConcurrentDictionary<string, ServedCertificate> Served { get; } = new(StringComparer.Ordinal);

    public Task<ServedCertificate?> ReadAsync(string domain, CancellationToken ct) =>
        Task.FromResult(Served.TryGetValue(domain, out var c) ? c : null);
}

internal sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    private long _ticks = start.UtcTicks;
    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);
    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

internal sealed class RecordingEvents : IEventStream
{
    private readonly ConcurrentQueue<ProxyEvent> _published = new();
    public IReadOnlyList<ProxyEvent> Published => _published.ToList();
    public void Publish(ProxyEvent evt) => _published.Enqueue(evt);
    public async IAsyncEnumerable<ProxyEvent> Subscribe([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await Task.Delay(Timeout.Infinite, ct);
        yield break;
    }
}

/// <summary>The certificate section through a real <c>caddy validate</c>, which provisions the Cloudflare DNS module.</summary>
public class CertificateCaddyValidationTests
{
    private sealed class NoHttp : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new Xunit.Sdk.XunitException("No HTTP expected.");
    }

    private static readonly ProxyPlan Plan = new(
        [new ProxyRule { Domain = "a.example.com", UpstreamUrl = "http://10.0.0.5", Enabled = true, EnableTls = true }],
        [
            new CertificatePlan("a.example.com", CertificateChallenge.Http, Automate: false, RenewPending: true),
            new CertificatePlan("*.example.com", CertificateChallenge.DnsCloudflare, Automate: true, RenewPending: false),
            new CertificatePlan("m.example.org", CertificateChallenge.Http, Automate: true, RenewPending: false),
        ]);

    private static string? CaddyWithCloudflare()
    {
        var caddy = CaddyBinaryValidationTests.FindCaddy();
        if (caddy is null)
        {
            Assert.False(CaddyBinaryValidationTests.Required, "SSLRP_REQUIRE_CADDY=1 but no caddy binary.");
            return null;
        }
        var psi = CaddyEnvironment.StartInfo(new ProxyOptions { CaddyPath = caddy }, "list-modules");
        using var p = System.Diagnostics.Process.Start(psi)!;
        var err = p.StandardError.ReadToEndAsync();
        var modules = p.StandardOutput.ReadToEnd() + err.GetAwaiter().GetResult();
        p.WaitForExit(30_000);
        var has = modules.Split('\n').Any(l => l.Trim() == "dns.providers.cloudflare");
        Assert.True(has || !CaddyBinaryValidationTests.Required, $"{caddy} lacks dns.providers.cloudflare.");
        return has ? caddy : null;
    }

    private static ProxyOptions Options(string caddy, string? token) => new()
    {
        CaddyPath = caddy,
        CloudflareApiToken = token,
        AcmeContactEmail = "ops@example.com",
        DnsChallengeResolvers = "1.1.1.1:53",
        ConfigDirectory = Path.Combine(Path.GetTempPath(), $"sslrp-certval-{Guid.NewGuid():N}"),
    };

    private static CaddyProxyController Controller(ProxyOptions options) => new(
        Microsoft.Extensions.Options.Options.Create(options), new NoHttp(), NullLogger<CaddyProxyController>.Instance,
        TimeProvider.System, new TrafficRecorder(), new SecretRedactor([options.CloudflareApiToken]),
        new CaddyCertificateLog(SecretRedactor.None, TimeProvider.System));

    [Fact]
    public async Task DnsWildcardAndForcedRenewal_AreAcceptedByCaddy()
    {
        if (CaddyWithCloudflare() is not { } caddy) return;
        var options = Options(caddy, CertificateConfigTests.Token);
        using var c = Controller(options);
        Assert.Contains("cloudflare", c.BuildConfigJson(Plan));
        try
        {
            var result = await c.ValidateConfigurationAsync(Plan);

            Assert.True(result.Valid, string.Join("; ", result.Issues));
            Assert.True(result.EngineValidated);
        }
        finally
        {
            if (Directory.Exists(options.ConfigDirectory)) Directory.Delete(options.ConfigDirectory, recursive: true);
        }
    }

    /// <summary>Positive control: the same config with no token in Caddy's environment is refused, so the module did check it.</summary>
    [Fact]
    public async Task DnsConfig_WithoutTheTokenInCaddysEnvironment_IsRefused()
    {
        if (CaddyWithCloudflare() is not { } caddy) return;
        var json = CaddyConfigBuilder.Build(Plan, Options(caddy, CertificateConfigTests.Token)).ToJsonString();
        var path = Path.Combine(Path.GetTempPath(), $"sslrp-certval-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, json);
        try
        {
            var psi = CaddyEnvironment.StartInfo(Options(caddy, token: null), "validate", "--config", path);
            using var p = System.Diagnostics.Process.Start(psi)!;
            var err = p.StandardError.ReadToEndAsync();
            var output = p.StandardOutput.ReadToEnd() + await err;
            await p.WaitForExitAsync();
            Assert.NotEqual(0, p.ExitCode);
            Assert.Contains("cloudflare", output, StringComparison.OrdinalIgnoreCase);
        }
        finally { File.Delete(path); }
    }
}
