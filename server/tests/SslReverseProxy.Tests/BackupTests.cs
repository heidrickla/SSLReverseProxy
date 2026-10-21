using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

public class BackupTests : IDisposable
{
    private const string CloudflareToken = "cfut_backupTestsTokenNotARealOne0123456789";
    private readonly CertificateFactory _factory = new(CloudflareToken);
    private readonly HttpClient _admin;

    public BackupTests() => _admin = _factory.Authed();

    public void Dispose() => _factory.Dispose();

    private async Task<string> AddServer(HttpClient c, string name, string host = "192.0.2.10")
    {
        var r = await c.PostAsJsonAsync("/api/servers", new { name, host, os = "linux" });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (string)JsonNode.Parse(await r.Content.ReadAsStringAsync())!["id"]!;
    }

    private static async Task<string> AddRule(HttpClient c, string serverId, object rule)
    {
        var r = await c.PostAsJsonAsync($"/api/servers/{serverId}/rules", rule);
        Assert.True(r.StatusCode == HttpStatusCode.Created, await r.Content.ReadAsStringAsync());
        return (string)JsonNode.Parse(await r.Content.ReadAsStringAsync())!["id"]!;
    }

    private async Task Seed(HttpClient c)
    {
        var web = await AddServer(c, "Web");
        await AddRule(c, web, new
        {
            domain = "app.example.com", upstreamUrl = "http://10.0.0.5", enableTls = true, enabled = true,
            basicAuthUsername = "ops", basicAuthPassword = "a-long-password",
            hardening = new { dialTimeoutSeconds = 5, hstsMaxAgeDays = 30, frameOptions = "DENY", skipAccessLog = true },
        });
        await AddRule(c, web, new
        {
            domain = "app.example.com", upstreamUrl = "http://10.0.0.6", enableTls = true, enabled = true,
            routing = new { pathPrefix = "/api", stripPathPrefix = true },
        });
        var docs = await AddServer(c, "Docs", "docs-host.example.com");
        await AddRule(c, docs, new { domain = "docs.example.com", upstreamUrl = "http://10.0.0.7", enableTls = false, enabled = false });
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsJsonAsync("/api/certificates", new { domain = "*.example.org", challenge = "DnsCloudflare" })).StatusCode);
    }

    private static async Task<JsonObject> Export(HttpClient c) =>
        JsonNode.Parse(await c.GetStringAsync("/api/backup"))!.AsObject();

    private static object Body(JsonNode document, string mode = "merge", string? revision = null) =>
        new { document, mode, revision };

    private static async Task<JsonObject> DryRun(HttpClient c, JsonNode document, string mode = "merge")
    {
        var r = await c.PostAsJsonAsync("/api/backup/import/dry-run", Body(document, mode));
        Assert.True(r.StatusCode == HttpStatusCode.OK, await r.Content.ReadAsStringAsync());
        return JsonNode.Parse(await r.Content.ReadAsStringAsync())!.AsObject();
    }

    private static async Task<HttpResponseMessage> Import(HttpClient c, JsonNode document, string mode = "merge")
    {
        var dry = await DryRun(c, document, mode);
        return await c.PostAsJsonAsync("/api/backup/import", Body(document, mode, (string)dry["revision"]!));
    }

    private static JsonObject Problems(JsonObject dry) => dry["problems"]!.AsObject();

    private static JsonObject WithoutTime(JsonObject doc)
    {
        var copy = doc.DeepClone().AsObject();
        copy.Remove("exportedAt");
        return copy;
    }

    private T Db<T>(Func<AppDbContext, T> f)
    {
        using var scope = _factory.Services.CreateScope();
        return f(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    [Fact]
    public async Task AnExport_RestoresIntoAnEmptyInstance_AsTheSameRows()
    {
        await Seed(_admin);
        var original = await Export(_admin);
        Assert.Equal(1, (int)original["formatVersion"]!);
        var hash = Db(db => db.Rules.Single(r => r.BasicAuthUsername == "ops").BasicAuthPasswordHash);
        Assert.Contains(hash!, original.ToJsonString());
        Assert.DoesNotContain("a-long-password", original.ToJsonString());
        Assert.DoesNotContain(CloudflareToken, original.ToJsonString());

        using var other = new CertificateFactory(CloudflareToken);
        var target = other.Authed();
        var dry = await DryRun(target, original);
        Assert.Empty(Problems(dry));
        Assert.Equal(["certificate:add", "rule:add", "rule:add", "rule:add", "server:add", "server:add"],
            dry["changes"]!.AsArray().Select(c => $"{c!["kind"]}:{c["action"]}").Order(StringComparer.Ordinal).ToArray());

        var applied = await target.PostAsJsonAsync("/api/backup/import", Body(original, "merge", (string)dry["revision"]!));
        Assert.True(applied.StatusCode == HttpStatusCode.OK, await applied.Content.ReadAsStringAsync());
        var result = JsonNode.Parse(await applied.Content.ReadAsStringAsync())!;
        Assert.Equal((6, 0, 0), ((int)result["added"]!, (int)result["updated"]!, (int)result["removed"]!));
        Assert.True((bool)result["reloadNeeded"]!);

        var restored = await Export(target);
        Assert.True(JsonNode.DeepEquals(WithoutTime(original), WithoutTime(restored)), restored.ToJsonString());

        // A second import of the same file changes nothing.
        var again = await DryRun(target, original);
        Assert.Empty(again["changes"]!.AsArray());
        Assert.Equal(6, (int)again["unchanged"]!);
    }

    [Fact]
    public async Task TheExport_IsADownload_AndIsAudited()
    {
        await Seed(_admin);
        var r = await _admin.GetAsync("/api/backup");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("attachment", r.Content.Headers.ContentDisposition!.DispositionType);
        Assert.StartsWith("sslrp-backup-", r.Content.Headers.ContentDisposition.FileName);
        Assert.True(Db(db => db.AuditEntries.Any(a => a.Action == "Export Backup")));
    }

    [Fact]
    public async Task ADryRun_KeepsNothing()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        doc["servers"]![0]!["rules"]![0]!["upstreamUrl"] = "http://10.0.0.99";
        var before = Db(db => (db.Servers.Count(), db.Rules.Count(), db.Certificates.Count(), db.Rules.Count(r => r.UpstreamUrl == "http://10.0.0.99")));
        var dry = await DryRun(_admin, doc, "replace");
        Assert.NotEmpty(dry["changes"]!.AsArray());
        Assert.Equal(before, Db(db => (db.Servers.Count(), db.Rules.Count(), db.Certificates.Count(), db.Rules.Count(r => r.UpstreamUrl == "http://10.0.0.99"))));
    }

    [Fact]
    public async Task AMerge_ChangesTheFieldsNamed_AndKeepsRowsTheFileDoesNotName()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        var web = doc["servers"]!.AsArray().First(s => (string)s!["name"]! == "Web")!;
        var rule = web["rules"]!.AsArray().First(r => r!["routing"]!["pathPrefix"] is null)!;
        rule["upstreamUrl"] = "http://10.0.0.9";
        doc["servers"] = new JsonArray(web.DeepClone());
        doc["certificates"] = new JsonArray();

        var dry = await DryRun(_admin, doc);
        var change = Assert.Single(dry["changes"]!.AsArray())!;
        Assert.Equal(("rule", "update", "app.example.com on Web"), ((string)change["kind"]!, (string)change["action"]!, (string)change["name"]!));
        var field = Assert.Single(change["fields"]!.AsArray())!;
        Assert.Equal(("upstreamUrl", "\"http://10.0.0.5\"", "\"http://10.0.0.9\""), ((string)field["field"]!, (string)field["before"]!, (string)field["after"]!));

        Assert.Equal(HttpStatusCode.OK, (await _admin.PostAsJsonAsync("/api/backup/import", Body(doc, "merge", (string)dry["revision"]!))).StatusCode);
        Assert.Equal((2, 3), Db(db => (db.Servers.Count(), db.Rules.Count())));
        Assert.Equal(1, Db(db => db.Rules.Single(r => r.UpstreamUrl == "http://10.0.0.9").Version));
    }

    [Fact]
    public async Task AReplace_RemovesWhatTheFileDoesNotName_ButKeepsRuleCertificateRows()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        await AddServer(_admin, "Extra");
        Assert.Equal(HttpStatusCode.Created, (await _admin.PostAsJsonAsync("/api/certificates", new { domain = "extra.example.net" })).StatusCode);
        Db(db =>
        {
            db.Certificates.Add(new Certificate { Domain = "app.example.com", Source = CertificateSource.Rule });
            return db.SaveChanges();
        });

        var dry = await DryRun(_admin, doc, "replace");
        var removed = dry["changes"]!.AsArray().Where(c => (string)c!["action"]! == "remove").Select(c => $"{c!["kind"]} {c["name"]}").Order().ToList();
        Assert.Equal(["certificate extra.example.net", "server Extra"], removed);

        Assert.Equal(HttpStatusCode.OK, (await _admin.PostAsJsonAsync("/api/backup/import", Body(doc, "replace", (string)dry["revision"]!))).StatusCode);
        Assert.False(Db(db => db.Servers.Any(s => s.Name == "Extra")));
        Assert.False(Db(db => db.Certificates.Any(c => c.Domain == "extra.example.net")));
        Assert.True(Db(db => db.Certificates.Any(c => c.Domain == "app.example.com" && c.Source == CertificateSource.Rule)));
    }

    [Fact]
    public async Task AReplace_MovesARuleOffARemovedServer_WithoutLosingIt()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        var servers = doc["servers"]!.AsArray();
        var docs = servers.First(s => (string)s!["name"]! == "Docs")!;
        var web = servers.First(s => (string)s!["name"]! == "Web")!;
        var moved = docs["rules"]![0]!.DeepClone();
        web["rules"]!.AsArray().Add(moved);
        servers.Remove(docs);

        var r = await Import(_admin, doc, "replace");
        Assert.True(r.StatusCode == HttpStatusCode.OK, await r.Content.ReadAsStringAsync());
        Assert.False(Db(db => db.Servers.Any(s => s.Name == "Docs")));
        var rule = Db(db => db.Rules.Include(x => x.Server).Single(x => x.Domain == "docs.example.com"));
        Assert.Equal(((string)moved["id"]!, "Web"), (rule.Id.ToString(), rule.Server!.Name));
    }

    [Fact]
    public async Task ARuleWithANewId_MatchesTheRowOnTheSameHostAndPath()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        var rule = doc["servers"]!.AsArray().First(s => (string)s!["name"]! == "Web")!["rules"]!.AsArray()
            .First(x => (string?)x!["routing"]!["pathPrefix"] == "/api")!;
        var id = (string)rule["id"]!;
        rule["id"] = Guid.NewGuid().ToString();
        rule["upstreamUrl"] = "http://10.0.0.8";

        var r = await Import(_admin, doc);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal(3, Db(db => db.Rules.Count()));
        Assert.Equal("http://10.0.0.8", Db(db => db.Rules.Single(x => x.Id == Guid.Parse(id)).UpstreamUrl));
    }

    [Fact]
    public async Task AServerNameThatMatchesTwoRows_IsRefused()
    {
        await AddServer(_admin, "Twin");
        await AddServer(_admin, "Twin");
        var doc = JsonNode.Parse($$"""{"formatVersion":1,"exportedAt":"2026-10-21T00:00:00Z","servers":[{"id":"{{Guid.NewGuid()}}","name":"Twin","host":"192.0.2.10","os":"linux","rules":[]}],"certificates":[]}""")!;
        var dry = await DryRun(_admin, doc);
        Assert.Contains("More than one server", Problems(dry)["servers[0].name"]![0]!.ToString());
        Assert.Null(dry["preview"]);
    }

    [Fact]
    public async Task EveryRuleCheck_RunsOnTheFile_AgainstTheSetTheImportLeaves()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        var web = doc["servers"]!.AsArray().First(s => (string)s!["name"]! == "Web")!["rules"]!.AsArray();
        var plain = web[0]!.DeepClone();
        plain["id"] = Guid.NewGuid().ToString();
        plain["routing"] = new JsonObject { ["pathPrefix"] = "/other", ["stripPathPrefix"] = false };
        plain["enableTls"] = false;
        plain["basicAuthUsername"] = null;
        plain["basicAuthPasswordHash"] = null;
        web.Add(plain);
        var metadata = web[0]!.DeepClone();
        metadata["id"] = Guid.NewGuid().ToString();
        metadata["domain"] = "meta.example.com";
        metadata["upstreamUrl"] = "http://169.254.169.254";
        web.Add(metadata);
        var braced = web[0]!.DeepClone();
        braced["id"] = Guid.NewGuid().ToString();
        braced["domain"] = "braced.example.com";
        braced["hardening"]!["healthCheckPath"] = "/x{env.HOME}";
        web.Add(braced);

        var problems = Problems(await DryRun(_admin, doc));
        Assert.Contains("disagree on TLS", problems["servers[1].rules[2].domain"]![0]!.ToString());
        Assert.Contains("metadata", problems["servers[1].rules[3].upstreamUrl"]![0]!.ToString());
        Assert.Contains("'{' or '}'", problems["servers[1].rules[4].healthCheckPath"]![0]!.ToString());
    }

    [Fact]
    public async Task TwoRowsOfTheFileOnOneRoute_AreRefused()
    {
        var id = Guid.NewGuid();
        var rule = (Guid rid) => new JsonObject
        {
            ["id"] = rid.ToString(), ["domain"] = "dup.example.com", ["upstreamUrl"] = "http://10.0.0.5", ["enableTls"] = true, ["enabled"] = true,
        };
        var doc = new JsonObject
        {
            ["formatVersion"] = 1, ["exportedAt"] = "2026-10-21T00:00:00Z", ["certificates"] = new JsonArray(),
            ["servers"] = new JsonArray(new JsonObject
            {
                ["id"] = id.ToString(), ["name"] = "S", ["host"] = "192.0.2.10", ["os"] = "linux",
                ["rules"] = new JsonArray(rule(Guid.NewGuid()), rule(Guid.NewGuid())),
            }),
        };
        var problems = Problems(await DryRun(_admin, doc));
        Assert.Contains("Duplicate domain", problems["servers[0].rules[0].domain"]![0]!.ToString());
        Assert.Contains("Duplicate domain", problems["servers[0].rules[1].domain"]![0]!.ToString());
    }

    [Fact]
    public async Task BasicAuth_NeedsAUsernameAndABcryptHashTogether_AndAHashChangeShowsNoValue()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        var rules = doc["servers"]!.AsArray().First(s => (string)s!["name"]! == "Web")!["rules"]!.AsArray();
        var guarded = rules.First(r => (string?)r!["basicAuthUsername"] == "ops")!;
        var oldHash = (string)guarded["basicAuthPasswordHash"]!;
        var newHash = BCrypt.Net.BCrypt.HashPassword("another-password");
        guarded["basicAuthPasswordHash"] = newHash;

        var dry = await DryRun(_admin, doc);
        var field = dry["changes"]!.AsArray().SelectMany(c => c!["fields"]!.AsArray()).Single(f => (string)f!["field"]! == "basicAuthPasswordHash")!;
        Assert.Equal(("[masked]", "[masked]"), ((string)field["before"]!, (string)field["after"]!));
        Assert.DoesNotContain(oldHash, dry.ToJsonString());
        Assert.DoesNotContain(newHash, dry.ToJsonString());

        guarded["basicAuthPasswordHash"] = "not-a-hash";
        Assert.Equal("Not a bcrypt hash.", (string)Problems(await DryRun(_admin, doc))["servers[1].rules[0].basicAuthPasswordHash"]![0]!);
        guarded["basicAuthPasswordHash"] = null;
        Assert.Contains("needs its password hash", (string)Problems(await DryRun(_admin, doc))["servers[1].rules[0].basicAuthPasswordHash"]![0]!);
        guarded["basicAuthUsername"] = null;
        guarded["basicAuthPasswordHash"] = newHash;
        Assert.Contains("needs a Basic Auth username", (string)Problems(await DryRun(_admin, doc))["servers[1].rules[0].basicAuthUsername"]![0]!);
    }

    [Fact]
    public async Task AnImport_AfterTheRowsChanged_IsRefused_AndChangesNothing()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        doc["servers"]![0]!["host"] = "192.0.2.77";
        var dry = await DryRun(_admin, doc);
        await AddServer(_admin, "Late");

        var r = await _admin.PostAsJsonAsync("/api/backup/import", Body(doc, "merge", (string)dry["revision"]!));
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.False(Db(db => db.Servers.Any(s => s.Host == "192.0.2.77")));

        // A revision from another mode does not carry over either.
        var replace = await _admin.PostAsJsonAsync("/api/backup/import", Body(doc, "replace", (string)(await DryRun(_admin, doc))["revision"]!));
        Assert.Equal(HttpStatusCode.Conflict, replace.StatusCode);
    }

    [Fact]
    public async Task AnImportWithProblems_IsRefused_EvenWithAFreshRevision()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        doc["servers"]![0]!["rules"]![0]!["upstreamUrl"] = "http://169.254.169.254";
        var dry = await DryRun(_admin, doc);
        Assert.NotEmpty(Problems(dry));
        var r = await _admin.PostAsJsonAsync("/api/backup/import", Body(doc, "merge", (string)dry["revision"]!));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.False(Db(db => db.Rules.Any(x => x.UpstreamUrl == "http://169.254.169.254")));
    }

    [Fact]
    public async Task AnImportWithoutARevision_IsRefused()
    {
        var doc = await Export(_admin);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PostAsJsonAsync("/api/backup/import", Body(doc))).StatusCode);
    }

    [Fact]
    public async Task AnotherFormatVersion_IsRefused()
    {
        var doc = await Export(_admin);
        doc["formatVersion"] = 2;
        Assert.Contains("format 2", (string)Problems(await DryRun(_admin, doc))["formatVersion"]![0]!);
    }

    [Fact]
    public async Task ABodyOverTheCap_IsRefusedUnread()
    {
        var padding = new string('x', 2 * 1024 * 1024);
        var big = new StringContent($$$"""{"document":{"formatVersion":1,"servers":[],"certificates":[],"pad":"{{{padding}}}"}}""", Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await _admin.PostAsync("/api/backup/import/dry-run", big)).StatusCode);
    }

    [Theory]
    [InlineData("document", "servers", "rules")]
    [InlineData("Document", "Servers", "Rules")]
    public async Task TooManyRows_AreRefusedBeforeBinding_WhateverTheCase(string document, string servers, string rules)
    {
        var many = string.Join(",", Enumerable.Repeat("{}", 5001));
        var body = new StringContent($$$"""{"{{{document}}}":{"formatVersion":1,"certificates":[],"{{{servers}}}":[{"{{{rules}}}":[{{{many}}}]}]}}""", Encoding.UTF8, "application/json");
        var r = await _admin.PostAsync("/api/backup/import/dry-run", body);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("At most 5000 rules", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task CertificateRows_AreCheckedAndPushedWhileCaddyRuns_RulesWaitForAReload()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        var certs = doc["certificates"]!.AsArray();
        certs.Add(new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["domain"] = "nohost.example.com", ["source"] = "Rule", ["challenge"] = "Http" });
        certs[0]!["domain"] = "renamed.example.org";
        var problems = Problems(await DryRun(_admin, doc));
        Assert.Contains("belongs to *.example.org", (string)problems["certificates[0].id"]![0]!);
        Assert.Contains("No TLS rule", (string)problems["certificates[1].source"]![0]!);

        // Rules only: nothing is pushed.
        doc = await Export(_admin);
        doc["servers"]![0]!["rules"]![0]!["upstreamUrl"] = "http://10.0.0.42";
        var pushed = _factory.Proxy.Applied.Count;
        var rulesOnly = JsonNode.Parse(await (await Import(_admin, doc)).Content.ReadAsStringAsync())!;
        Assert.True((bool)rulesOnly["reloadNeeded"]!);
        Assert.Null(rulesOnly["proxy"]);
        Assert.Equal(pushed, _factory.Proxy.Applied.Count);

        // A certificate row: pushed as a certificate write is.
        doc = await Export(_admin);
        doc["certificates"]!.AsArray().Add(new JsonObject { ["id"] = Guid.NewGuid().ToString(), ["domain"] = "new.example.net", ["source"] = "Manual", ["challenge"] = "Http" });
        var withCert = JsonNode.Parse(await (await Import(_admin, doc)).Content.ReadAsStringAsync())!;
        Assert.False((bool)withCert["reloadNeeded"]!);
        Assert.Equal("Running", (string)withCert["proxy"]!["state"]!);
        Assert.Equal(pushed + 1, _factory.Proxy.Applied.Count);
    }

    [Fact]
    public async Task TheDryRun_PreviewsWhatAReloadAfterTheImportWouldPush()
    {
        await Seed(_admin);
        await _admin.PostAsync("/api/proxy/reload", null);
        var doc = await Export(_admin);
        doc["servers"]!.AsArray().First(s => (string)s!["name"]! == "Docs")!["rules"]![0]!["enabled"] = true;
        var preview = (await DryRun(_admin, doc))["preview"]!;
        Assert.True((bool)preview["runningAvailable"]!);
        var change = Assert.Single(preview["changes"]!.AsArray())!;
        Assert.Equal(("docs.example.com (http)", "added"), ((string)change["group"]!, (string)change["kind"]!));
    }

    [Fact]
    public async Task EveryBackupCall_NeedsBackupManage()
    {
        await Seed(_admin);
        var doc = await Export(_admin);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var editor = new User { Name = "Editor", Email = "editor@example.com", Role = Role.Editor };
        db.Users.Add(editor);
        db.SaveChanges();
        var admin = db.Users.First(u => u.Role == Role.Admin);
        var keys = scope.ServiceProvider.GetRequiredService<IApiKeyService>();
        foreach (var (owner, scopes) in new[] { (editor.Id, (Permission[]?)null), (admin.Id, Enum.GetValues<Permission>().Where(p => p != Permission.BackupManage).ToArray()) })
        {
            var token = (await keys.CreateAsync(owner, "no-backup", _factory.Clock.GetUtcNow().AddDays(30), scopes)).PlaintextToken;
            var c = _factory.CreateClient();
            c.DefaultRequestHeaders.Add("X-Api-Key", token);
            Assert.Equal(HttpStatusCode.Forbidden, (await c.GetAsync("/api/backup")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await c.PostAsJsonAsync("/api/backup/import/dry-run", Body(doc))).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await c.PostAsJsonAsync("/api/backup/import", Body(doc, "merge", "x"))).StatusCode);
        }
    }
}
