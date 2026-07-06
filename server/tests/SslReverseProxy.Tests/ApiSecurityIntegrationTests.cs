using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>
/// Spins up the real API in-memory and verifies the security pipeline:
/// anonymous liveness works, but every protected route is denied without a key.
/// </summary>
public class ApiSecurityIntegrationTests : IClassFixture<ApiSecurityIntegrationTests.Factory>
{
    private readonly Factory _factory;
    public ApiSecurityIntegrationTests(Factory factory) => _factory = factory;

    [Fact]
    public async Task Health_IsAnonymous()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Theory]
    [InlineData("/api/proxy/status")]
    [InlineData("/api/servers")]
    [InlineData("/api/users")]
    [InlineData("/api/audit")]
    [InlineData("/api/whoami")]
    public async Task ProtectedRoutes_RequireAuth(string path)
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task ProxyControl_RejectsInvalidKey()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", "srp.bogus.deadbeef");
        var resp = await client.PostAsync("/api/proxy/start", null);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task SecurityHeaders_ArePresent()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/health");
        Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", resp.Headers.GetValues("X-Frame-Options").Single());
    }

    public sealed class Factory : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-test-{Guid.NewGuid():N}.db");

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Development"); // no HTTPS redirect in the test server
            builder.ConfigureHostConfiguration(cfg =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
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
