using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

public class NewEndpointsIntegrationTests : IClassFixture<NewEndpointsIntegrationTests.AuthedFactory>
{
    private readonly AuthedFactory _factory;
    public NewEndpointsIntegrationTests(AuthedFactory factory) => _factory = factory;

    private HttpClient Authed()
    {
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Add("X-Api-Key", _factory.AdminKey);
        return c;
    }

    [Fact]
    public async Task Ready_IsAnonymous()
    {
        var resp = await _factory.CreateClient().GetAsync("/api/ready");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Theory]
    [InlineData("/api/proxy/metrics")]
    [InlineData("/api/proxy/config")]
    [InlineData("/api/proxy/snapshots")]
    [InlineData("/api/events")]
    public async Task NewProtectedRoutes_RequireAuth(string path)
    {
        var resp = await _factory.CreateClient().GetAsync(path);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ConfigPreview_ReturnsJson()
    {
        var resp = await Authed().GetAsync("/api/proxy/config");
        resp.EnsureSuccessStatusCode();
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("apps", body);
        Assert.Contains("127.0.0.1:2019", body); // admin pinned to loopback
    }

    [Fact]
    public async Task Validate_EmptyRuleSet_IsValid()
    {
        var resp = await Authed().PostAsync("/api/proxy/validate", null);
        resp.EnsureSuccessStatusCode();
        var dto = await resp.Content.ReadFromJsonAsync<ValidateResult>();
        Assert.True(dto!.valid);
    }

    [Fact]
    public async Task Metrics_ReportsUnavailable_WhenProxyStopped()
    {
        var dto = await Authed().GetFromJsonAsync<MetricsResult>("/api/proxy/metrics");
        Assert.False(dto!.available);
    }

    [Fact]
    public async Task RuleToggle_FlipsEnabled()
    {
        var client = Authed();
        var server = await (await client.PostAsJsonAsync("/api/servers",
            new { name = "t", host = "10.0.0.5", os = "linux" })).Content.ReadFromJsonAsync<IdName>();
        var rule = await (await client.PostAsJsonAsync($"/api/servers/{server!.id}/rules",
            new { domain = "t.example.com", upstreamUrl = "http://10.0.0.20:8080", enableTls = true, enabled = true })).Content.ReadFromJsonAsync<RuleResult>();

        var toggled = await client.PatchAsJsonAsync($"/api/servers/{server.id}/rules/{rule!.id}/enabled", new { enabled = false });
        toggled.EnsureSuccessStatusCode();
        var updated = await toggled.Content.ReadFromJsonAsync<RuleResult>();
        Assert.False(updated!.enabled);
    }

    [Fact]
    public async Task RuleHealth_ReturnsUnreachable_ForDeadUpstream()
    {
        var client = Authed();
        var server = await (await client.PostAsJsonAsync("/api/servers",
            new { name = "h", host = "10.0.0.6", os = "linux" })).Content.ReadFromJsonAsync<IdName>();
        var rule = await (await client.PostAsJsonAsync($"/api/servers/{server!.id}/rules",
            new { domain = "h.example.com", upstreamUrl = "http://10.255.255.1:9", enableTls = true, enabled = true })).Content.ReadFromJsonAsync<RuleResult>();

        var health = await client.GetFromJsonAsync<HealthResult>($"/api/servers/{server.id}/rules/{rule!.id}/health");
        Assert.False(health!.reachable);
    }

    [Fact]
    public async Task InvalidCidr_IsRejected()
    {
        var client = Authed();
        var server = await (await client.PostAsJsonAsync("/api/servers",
            new { name = "c", host = "10.0.0.7", os = "linux" })).Content.ReadFromJsonAsync<IdName>();
        var resp = await client.PostAsJsonAsync($"/api/servers/{server!.id}/rules",
            new { domain = "c.example.com", upstreamUrl = "http://10.0.0.20:8080", enableTls = true, enabled = true, deniedCidrs = "not-an-ip" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    private async Task<Guid> NewServerAsync(HttpClient client, string host)
    {
        var server = await (await client.PostAsJsonAsync("/api/servers",
            new { name = host, host, os = "linux" })).Content.ReadFromJsonAsync<IdName>();
        return server!.id;
    }

    [Fact]
    public async Task AdditionalUpstreams_AreSubjectToTheSameSsrfPolicy()
    {
        // The primary upstream is validated; an unvalidated second field would
        // be a way straight round it.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.30");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "lb.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
            hardening = new { additionalUpstreams = "http://169.254.169.254/latest/meta-data/" },
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task MixedUpstreamSchemes_AreRejected()
    {
        // One transport serves every upstream in the handler, so a rule cannot
        // be half TLS. Accepting it would mean cleartext to a TLS port.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.31");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "mixed.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
            hardening = new { additionalUpstreams = "https://10.0.0.21:8443" },
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task ChangingOnlyTheUpstreamScheme_CannotStrandMismatchedExtraUpstreams()
    {
        // The gap: `hardening` omitted means "leave those settings alone", so
        // the stored additional upstreams survive. Validate only what the
        // request carries and the primary's scheme can drift away from them,
        // leaving a rule with one https and one http upstream — which the
        // builder resolves by putting a TLS transport on both.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.35");
        var created = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "drift.example.com",
            upstreamUrl = "https://10.0.0.20:8443",
            enableTls = true,
            enabled = true,
            hardening = new { additionalUpstreams = "https://10.0.0.21:8443" },
        });
        created.EnsureSuccessStatusCode();
        var rule = await created.Content.ReadFromJsonAsync<RuleResult>();

        // Same rule, primary flipped to http, no `hardening` block at all.
        var resp = await client.PutAsJsonAsync($"/api/servers/{serverId}/rules/{rule!.id}", new
        {
            domain = "drift.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task HealthCheckTimeout_IsCheckedAgainstTheDefaultInterval_WhenNoneGiven()
    {
        // Guarding only when both are present let a 300s timeout through
        // against Caddy's 30s default interval.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.36");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "hc.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
            hardening = new { healthCheckPath = "/healthz", healthCheckTimeoutSeconds = 300 },
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task UpstreamTlsSettings_AreRejectedOnAPlaintextUpstream()
    {
        // Accepting them silently would let someone believe a name mismatch had
        // been handled on a route where no TLS is spoken at all.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.37");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "plain.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
            hardening = new { upstreamTlsServerName = "backend.internal" },
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task SkipVerify_AndATrustedCa_CannotBothBeSet()
    {
        // They express opposite intentions, and Caddy resolves the conflict by
        // verifying nothing.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.38");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "conflict.example.com",
            upstreamUrl = "https://10.0.0.20:8443",
            enableTls = true,
            enabled = true,
            hardening = new
            {
                upstreamTlsInsecureSkipVerify = true,
                upstreamTlsTrustedCaFile = "/etc/ssl/ca.pem",
            },
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task UpstreamTlsServerName_RoundTrips()
    {
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.39");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "tls.example.com",
            upstreamUrl = "https://10.0.0.20:8443",
            enableTls = true,
            enabled = true,
            hardening = new { upstreamTlsServerName = "backend.internal" },
        });
        resp.EnsureSuccessStatusCode();

        var config = await (await client.GetAsync("/api/proxy/config")).Content.ReadAsStringAsync();
        Assert.Contains("\"server_name\": \"backend.internal\"", config);
    }

    [Theory]
    [InlineData("{\"loadBalancePolicy\":\"magic\"}")]
    [InlineData("{\"frameOptions\":\"ALLOW-FROM https://evil.example\"}")]
    [InlineData("{\"healthCheckPath\":\"healthz\"}")]
    [InlineData("{\"dialTimeoutSeconds\":0}")]
    [InlineData("{\"maxRequestBodyBytes\":-1}")]
    [InlineData("{\"healthCheckExpectStatus\":42}")]
    [InlineData("{\"healthCheckIntervalSeconds\":5,\"healthCheckTimeoutSeconds\":30}")]
    public async Task InvalidHardening_IsRejected(string hardeningJson)
    {
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.32");
        var body = $$"""
            {"domain":"h.example.com","upstreamUrl":"http://10.0.0.20:8080",
             "enableTls":true,"enabled":true,"hardening":{{hardeningJson}}}
            """;
        var resp = await client.PostAsync($"/api/servers/{serverId}/rules",
            new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task OmittedHardening_LeavesTheRuleUsable_WithSafeDefaults()
    {
        // Clients written before these settings existed must keep working.
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.33");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "legacy.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
        });
        resp.EnsureSuccessStatusCode();
        var rule = await resp.Content.ReadFromJsonAsync<RuleWithHardening>();
        Assert.True(rule!.hardening.enableSecurityHeaders);
        Assert.Null(rule.hardening.hstsMaxAgeDays);
        Assert.False(rule.hardening.skipAccessLog);
    }

    [Fact]
    public async Task Hardening_RoundTripsThroughCreateAndRead()
    {
        var client = Authed();
        var serverId = await NewServerAsync(client, "10.0.0.34");
        var resp = await client.PostAsJsonAsync($"/api/servers/{serverId}/rules", new
        {
            domain = "full.example.com",
            upstreamUrl = "http://10.0.0.20:8080",
            enableTls = true,
            enabled = true,
            hardening = new
            {
                additionalUpstreams = "http://10.0.0.21:8080",
                loadBalancePolicy = "round_robin",
                dialTimeoutSeconds = 5,
                maxRequestBodyBytes = 1048576L,
                hstsMaxAgeDays = 365,
                hstsIncludeSubdomains = true,
                frameOptions = "deny",
                healthCheckPath = "/healthz",
                healthCheckIntervalSeconds = 30,
                healthCheckTimeoutSeconds = 5,
                healthCheckExpectStatus = 2,
                skipAccessLog = true,
            },
        });
        resp.EnsureSuccessStatusCode();
        var rule = await resp.Content.ReadFromJsonAsync<RuleWithHardening>();
        Assert.Equal("round_robin", rule!.hardening.loadBalancePolicy);
        Assert.Equal("DENY", rule.hardening.frameOptions); // normalised on the way in
        Assert.Equal(1048576L, rule.hardening.maxRequestBodyBytes);
        Assert.True(rule.hardening.skipAccessLog);
        Assert.True(rule.hardening.hstsIncludeSubdomains);

        // And it reaches the generated Caddy config, not just the database.
        var config = await (await client.GetAsync("/api/proxy/config")).Content.ReadAsStringAsync();
        Assert.Contains("\"uri\": \"/healthz\"", config);
        Assert.Contains("round_robin", config);
        Assert.Contains("max-age=31536000; includeSubDomains", config);
    }

    [Fact]
    public async Task LastAdmin_CannotBeDemoted()
    {
        var client = Authed();
        var admin = await client.GetFromJsonAsync<UserResult[]>("/api/users");
        var theAdmin = admin!.First(u => u.role == "Admin");
        var resp = await client.PutAsJsonAsync($"/api/users/{theAdmin.id}",
            new { name = theAdmin.name, role = "Viewer", isActive = true });
        Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode);
    }

    [Fact]
    public async Task ApiKeyRotate_IssuesNewAndRevokesOld()
    {
        var client = Authed();
        var admin = (await client.GetFromJsonAsync<UserResult[]>("/api/users"))!.First(u => u.role == "Admin");
        var created = await (await client.PostAsJsonAsync("/api/apikeys",
            new { userId = admin.id, name = "rotate-me", lifetimeDays = (int?)null })).Content.ReadFromJsonAsync<IssuedKey>();

        // Old key works.
        var oldClient = _factory.CreateClient();
        oldClient.DefaultRequestHeaders.Add("X-Api-Key", created!.token);
        Assert.Equal(HttpStatusCode.OK, (await oldClient.GetAsync("/api/whoami")).StatusCode);

        // Rotate, then the old key must stop working and the new one must work.
        var rotated = await (await client.PostAsync($"/api/apikeys/{created.id}/rotate", null)).Content.ReadFromJsonAsync<IssuedKey>();
        Assert.Equal(HttpStatusCode.Unauthorized, (await oldClient.GetAsync("/api/whoami")).StatusCode);

        var newClient = _factory.CreateClient();
        newClient.DefaultRequestHeaders.Add("X-Api-Key", rotated!.token);
        Assert.Equal(HttpStatusCode.OK, (await newClient.GetAsync("/api/whoami")).StatusCode);
    }

    [Fact]
    public async Task AuditFilter_ByAction_Works()
    {
        var client = Authed();
        // Generate a distinctive action.
        await client.PostAsJsonAsync("/api/servers", new { name = "audited", host = "10.0.0.8", os = "linux" });
        var filtered = await client.GetFromJsonAsync<AuditResult[]>("/api/audit?action=Create%20Server");
        Assert.NotEmpty(filtered!);
        Assert.All(filtered!, a => Assert.Equal("Create Server", a.action));
    }

    // --- response shapes ---
    private record IdName(Guid id, string name);
    private record RuleResult(Guid id, bool enabled);
    private record HardeningResult(
        string? additionalUpstreams, string? loadBalancePolicy, int? dialTimeoutSeconds,
        long? maxRequestBodyBytes, bool enableSecurityHeaders, int? hstsMaxAgeDays,
        bool hstsIncludeSubdomains, string? frameOptions, string? healthCheckPath, bool skipAccessLog);
    private record RuleWithHardening(Guid id, string domain, HardeningResult hardening);
    private record ValidateResult(bool valid, string[] issues, bool engineValidated);
    private record MetricsResult(bool available, long totalRequests);
    private record HealthResult(bool reachable, int? statusCode);
    private record UserResult(Guid id, string name, string role);
    private record IssuedKey(Guid id, string name, string token);
    private record AuditResult(long id, string action);

    public sealed class AuthedFactory : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-new-{Guid.NewGuid():N}.db");
        public string AdminKey { get; private set; } = "";

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureHostConfiguration(cfg =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                }));
            var host = base.CreateHost(builder);

            using var scope = host.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.Migrate();
            var admin = db.Users.FirstOrDefault(u => u.Role == Role.Admin);
            if (admin is null)
            {
                admin = new User { Name = "Test Admin", Email = "testadmin@localhost", Role = Role.Admin };
                db.Users.Add(admin);
                db.SaveChanges();
            }
            var keys = scope.ServiceProvider.GetRequiredService<IApiKeyService>();
            AdminKey = keys.CreateAsync(admin.Id, "test-suite", null).GetAwaiter().GetResult().PlaintextToken;
            return host;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { }
        }
    }
}
