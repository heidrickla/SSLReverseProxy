using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using Xunit;

namespace SslReverseProxy.Tests;

public class ContractTests : IDisposable
{
    private readonly PasskeyFactory _factory = new();

    public void Dispose() => _factory.Dispose();

    private HttpClient Scoped(params Permission[] scopes)
    {
        using var scope = _factory.Services.CreateScope();
        var admin = scope.ServiceProvider.GetRequiredService<AppDbContext>().Users.First(u => u.Role == Role.Admin);
        var token = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
            .CreateAsync(admin.Id, "contract", _factory.Clock.GetUtcNow().AddDays(30), scopes).GetAwaiter().GetResult().PlaintextToken;
        var c = _factory.Anonymous();
        c.DefaultRequestHeaders.Add("X-Api-Key", token);
        return c;
    }

    [Fact]
    public async Task TheInstanceId_IsStableAndStored()
    {
        var key = Scoped(Permission.CertRead);
        var first = JsonNode.Parse(await key.GetStringAsync("/api/instance"))!;
        var second = JsonNode.Parse(await key.GetStringAsync("/api/instance"))!;
        Assert.Equal((string)first["instanceId"]!, (string)second["instanceId"]!);
        Assert.Equal(_factory.Db(db => db.Instance.Single().InstanceId).ToString(), (string)first["instanceId"]!);
        Assert.Equal(1, (int)first["apiVersion"]!);
        Assert.Equal(["scoped-api-keys", "push-preview", "backup", "recent-requests"], first["capabilities"]!.AsArray().Select(c => (string)c!));
    }

    [Fact]
    public async Task TheInstanceEndpoint_NeedsSignIn()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Anonymous().GetAsync("/api/instance")).StatusCode);
    }

    [Fact]
    public async Task TheOpenApiDocument_NeedsServerRead()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Anonymous().GetAsync("/api/openapi/v1.json")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Scoped(Permission.CertRead).GetAsync("/api/openapi/v1.json")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Scoped(Permission.ServerRead).GetAsync("/api/openapi/v1.json")).StatusCode);
    }

    [Fact]
    public async Task TheOpenApiDocument_DescribesTheKeyAndLeavesOutTheBootstrapClaim()
    {
        var doc = JsonNode.Parse(await Scoped(Permission.ServerRead).GetStringAsync("/api/openapi/v1.json"))!;
        var paths = doc["paths"]!.AsObject().Select(p => p.Key).ToList();
        Assert.Contains("/api/servers", paths);
        Assert.Contains("/api/instance", paths);
        Assert.Contains("/api/apikeys/options", paths);
        Assert.Contains("/api/proxy/preview", paths);
        Assert.Contains("/api/proxy/snapshots/{id}/preview", paths);
        Assert.Contains("/api/backup/import/dry-run", paths);
        Assert.Contains("/api/servers/{serverId}/rules/{ruleId}/requests", paths);
        Assert.DoesNotContain("/api/bootstrap-key", paths);
        var scheme = doc["components"]!["securitySchemes"]!["ApiKey"]!;
        Assert.Equal("apiKey", (string)scheme["type"]!);
        Assert.Equal("header", (string)scheme["in"]!);
        Assert.Equal("X-Api-Key", (string)scheme["name"]!);
    }

    [Fact]
    public async Task InProduction_TheOpenApiDocumentIsServedBehindSignIn()
    {
        using var prod = new ProductionFactory();
        var https = new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false };
        Assert.Equal(HttpStatusCode.Unauthorized, (await prod.CreateClient(https).GetAsync("/api/openapi/v1.json")).StatusCode);

        using var scope = prod.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var admin = db.Users.First(u => u.Role == Role.Admin);
        var token = (await scope.ServiceProvider.GetRequiredService<IApiKeyService>()
            .CreateAsync(admin.Id, "prod", DateTimeOffset.UtcNow.AddDays(1), [Permission.ServerRead])).PlaintextToken;
        var client = prod.CreateClient(https);
        client.DefaultRequestHeaders.Add("X-Api-Key", token);
        var r = await client.GetAsync("/api/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("\"/api/servers\"", await r.Content.ReadAsStringAsync());
    }

    private sealed class ProductionFactory : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-prod-{Guid.NewGuid():N}.db");

        protected override void ConfigureWebHost(IWebHostBuilder builder) =>
            builder.ConfigureTestServices(s => s.RemoveAll<IHostedService>());

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.ConfigureHostConfiguration(cfg => cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                ["Security:ApiKeyPepper"] = Convert.ToBase64String(new byte[32]),
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
