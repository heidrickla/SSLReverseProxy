using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>
/// The first-run bootstrap-key claim endpoint must answer only in Development,
/// only to loopback clients, and only once — 404 in every other case.
/// </summary>
public class BootstrapKeyEndpointTests
{
    private sealed record ClaimResponse(string ApiKey);

    [Fact]
    public async Task Claim_FromLoopbackInDevelopment_ReturnsKeyExactlyOnce()
    {
        using var factory = new Factory("Development", loopbackClient: true);
        var client = factory.CreateClient();

        var first = await client.GetAsync("/api/bootstrap-key");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var claim = await first.Content.ReadFromJsonAsync<ClaimResponse>();
        Assert.NotNull(claim);
        Assert.StartsWith("srp.", claim.ApiKey);

        // The claimed key must be a working admin credential.
        var authed = factory.CreateClient();
        authed.DefaultRequestHeaders.Add("X-Api-Key", claim.ApiKey);
        var whoami = await authed.GetAsync("/api/whoami");
        Assert.Equal(HttpStatusCode.OK, whoami.StatusCode);

        // A second claim finds the broker empty.
        var second = await client.GetAsync("/api/bootstrap-key");
        Assert.Equal(HttpStatusCode.NotFound, second.StatusCode);
    }

    [Fact]
    public async Task Claim_FromNonLoopback_IsNotFound()
    {
        // TestServer connections carry no remote IP, which must be treated as
        // untrusted exactly like a non-loopback address.
        using var factory = new Factory("Development", loopbackClient: false);
        var resp = await factory.CreateClient().GetAsync("/api/bootstrap-key");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Claim_OutsideDevelopment_IsNotFound_EvenFromLoopback()
    {
        using var factory = new Factory("Production", loopbackClient: true);
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), // skip the prod HTTPS redirect
        });
        var resp = await client.GetAsync("/api/bootstrap-key");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    private sealed class Factory(string environment, bool loopbackClient) : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-test-{Guid.NewGuid():N}.db");

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment(environment);
            builder.ConfigureHostConfiguration(cfg =>
                cfg.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                }));
            if (loopbackClient)
                builder.ConfigureServices(s =>
                    s.AddSingleton<IStartupFilter>(new FakeRemoteIpStartupFilter(IPAddress.Loopback)));
            return base.CreateHost(builder);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            try { if (File.Exists(_dbPath)) File.Delete(_dbPath); } catch { /* best effort */ }
        }
    }

    /// <summary>Stamps a fake client IP on every connection, ahead of the app pipeline.</summary>
    private sealed class FakeRemoteIpStartupFilter(IPAddress ip) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (ctx, nextMiddleware) =>
            {
                ctx.Connection.RemoteIpAddress = ip;
                await nextMiddleware();
            });
            next(app);
        };
    }
}
