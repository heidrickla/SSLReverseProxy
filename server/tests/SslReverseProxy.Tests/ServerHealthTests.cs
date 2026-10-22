using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>
/// Server status from the background monitor, and the Development demo seed
/// that gives the browser smoke test one server in each status.
/// </summary>
public class ServerHealthTests
{
    private sealed record ServerResult(Guid Id, string Name, string Status, int UpstreamsUp, int UpstreamsTotal, DateTimeOffset? StatusCheckedAt);

    [Theory]
    [InlineData(0, 0, ServerHealthStatus.Inactive)]
    [InlineData(2, 2, ServerHealthStatus.Active)]
    [InlineData(1, 2, ServerHealthStatus.Error)]
    [InlineData(0, 3, ServerHealthStatus.Error)]
    public void Classify(int up, int total, ServerHealthStatus expected) =>
        Assert.Equal(expected, ServerHealth.Classify(up, total));

    [Fact]
    public async Task DemoSeed_GivesOneServerInEachStatus()
    {
        using var factory = new Factory("Development", seedDemo: true, intervalSeconds: 3600);
        var client = factory.Authed();

        var servers = await WaitForAsync(client, list => list.Count == 3 && list.All(s => s.Status != "Unknown"));

        var web = servers.Single(s => s.Name == "Web Applications");
        Assert.Equal(("Active", 3, 3), (web.Status, web.UpstreamsUp, web.UpstreamsTotal));
        Assert.NotNull(web.StatusCheckedAt);
        var internalServices = servers.Single(s => s.Name == "Internal Services");
        Assert.Equal(("Error", 1, 2), (internalServices.Status, internalServices.UpstreamsUp, internalServices.UpstreamsTotal));
        var windows = servers.Single(s => s.Name == "Windows Services");
        Assert.Equal(("Inactive", 0, 0), (windows.Status, windows.UpstreamsUp, windows.UpstreamsTotal));

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        // The four seeded rows, plus a rule row the certificate monitor adds for each other enabled TLS rule.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        List<Certificate> certs = [];
        while (DateTime.UtcNow < deadline && certs.Count != 6)
        {
            certs = await db.Certificates.AsNoTracking().ToListAsync();
            if (certs.Count != 6) await Task.Delay(100);
        }
        Assert.Equal(
            ["api.example.com:Manual", "app.example.com:Rule", "docs.example.com:Rule", "git.example.com:Rule",
             "portal.example.com:Manual", "wiki.example.com:Rule"],
            certs.Select(c => $"{c.Domain}:{c.Source}").Order(StringComparer.Ordinal));
        Assert.Equal(1, certs.Count(c => c.Status == CertificateStatus.Expiring));
        Assert.Equal(3, await db.Users.CountAsync());
        Assert.Equal(4, await db.AuditEntries.CountAsync());
    }

    [Fact]
    public async Task DemoSeed_IsIgnoredOutsideDevelopment()
    {
        using var factory = new Factory("Production", seedDemo: true, intervalSeconds: 0);
        _ = factory.Server; // starts the host, which runs the bootstrapper

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(0, await db.Servers.CountAsync());
        Assert.Equal(0, await db.Certificates.CountAsync());
        Assert.Equal(1, await db.Users.CountAsync()); // the bootstrap admin only
    }

    [Fact]
    public async Task SuccessfulWrite_ProbesAgainWithoutWaitingForTheInterval()
    {
        // An hour-long interval: only the write-triggered probe can change the status within the test.
        using var factory = new Factory("Development", seedDemo: false, intervalSeconds: 3600);
        var client = factory.Authed();

        var created = await client.PostAsJsonAsync("/api/servers", new { name = "Probe target", host = "192.0.2.50", os = "linux" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<ServerResult>())!.Id;

        await WaitForAsync(client, list => list.Any(s => s.Id == id && s.Status == "Inactive"));

        var rule = await client.PostAsJsonAsync($"/api/servers/{id}/rules", new
        {
            domain = "probe.example.com", upstreamUrl = "http://127.0.0.1:8080", enableTls = false, enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, rule.StatusCode);

        var after = await WaitForAsync(client, list => list.Any(s => s.Id == id && s.Status == "Active"));
        Assert.Equal((1, 1), (after.Single(s => s.Id == id).UpstreamsUp, after.Single(s => s.Id == id).UpstreamsTotal));
    }

    [Fact]
    public async Task StatusChange_ReachesAnEventStreamOpenedBeforeIt()
    {
        using var factory = new Factory("Development", seedDemo: false, intervalSeconds: 3600);
        var client = factory.Authed();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // Headers arrive only once the subscriber is registered, so the write below cannot race it.
        using var stream = await client.GetAsync("/api/events", HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        using var reader = new StreamReader(await stream.Content.ReadAsStreamAsync(timeout.Token));

        var created = await client.PostAsJsonAsync("/api/servers", new { name = "Evented", host = "192.0.2.70", os = "linux" }, timeout.Token);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        while (await reader.ReadLineAsync(timeout.Token) is { } line)
        {
            if (!line.StartsWith("data: ", StringComparison.Ordinal)) continue;
            Assert.Contains("\"type\":\"server.health\"", line);
            Assert.Contains("Evented is inactive", line);
            return;
        }
        Assert.Fail("The event stream closed before a server.health event.");
    }

    [Fact]
    public async Task IntervalZero_TurnsTheMonitorOff()
    {
        using var factory = new Factory("Development", seedDemo: true, intervalSeconds: 0);
        var client = factory.Authed();

        var created = await client.PostAsJsonAsync("/api/servers", new { name = "Unprobed", host = "192.0.2.60", os = "linux" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        await Task.Delay(TimeSpan.FromSeconds(1.5));

        var servers = await client.GetFromJsonAsync<List<ServerResult>>("/api/servers");
        Assert.NotNull(servers);
        Assert.Equal(4, servers.Count);
        Assert.All(servers, s => Assert.Equal("Unknown", s.Status));
    }

    private static async Task<List<ServerResult>> WaitForAsync(HttpClient client, Func<List<ServerResult>, bool> done)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        List<ServerResult> last = [];
        while (DateTime.UtcNow < deadline)
        {
            last = await client.GetFromJsonAsync<List<ServerResult>>("/api/servers") ?? [];
            if (done(last)) return last;
            await Task.Delay(100);
        }
        Assert.Fail("Server statuses did not settle: " + string.Join(", ", last.Select(s => $"{s.Name}={s.Status}")));
        return last;
    }

    /// <summary>Answers for every upstream except the discard port, so statuses do not depend on the network.</summary>
    private sealed class FakeUpstreamChecker : IUpstreamHealthChecker
    {
        public Task<UpstreamHealth> CheckAsync(string upstreamUrl, CancellationToken ct = default) =>
            Task.FromResult(upstreamUrl.EndsWith(":9", StringComparison.Ordinal)
                ? new UpstreamHealth(false, null, 1, "Connection refused")
                : new UpstreamHealth(true, 200, 1, null));
    }

    private sealed class Factory(string environment, bool seedDemo, int intervalSeconds) : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-health-{Guid.NewGuid():N}.db");

        public HttpClient Authed()
        {
            using var scope = Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var admin = db.Users.First(u => u.Role == Role.Admin);
            var key = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
                .CreateAsync(admin.Id, "health-tests", null).GetAwaiter().GetResult().PlaintextToken;
            var client = CreateClient();
            client.DefaultRequestHeaders.Add("X-Api-Key", key);
            return client;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder) =>
            builder.ConfigureTestServices(s =>
            {
                s.RemoveAll<IUpstreamHealthChecker>();
                s.AddScoped<IUpstreamHealthChecker, FakeUpstreamChecker>();
            });

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            builder.ConfigureHostConfiguration(cfg =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                    ["Security:ApiKeyPepper"] = Convert.ToBase64String(new byte[32]),
                    ["Seed:Demo"] = seedDemo ? "true" : "false",
                    ["Seed:DemoUpstreamBase"] = "http://127.0.0.1:5195",
                    ["Proxy:ServerHealthIntervalSeconds"] = intervalSeconds.ToString(),
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
