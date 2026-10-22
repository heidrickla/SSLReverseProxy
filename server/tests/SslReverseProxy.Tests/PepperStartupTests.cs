using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslReverseProxy.Api.Security;
using Xunit;

namespace SslReverseProxy.Tests;

public class PepperStartupTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not base64!")]
    public void AnUnusablePepper_IsRefused(string? pepper) => Assert.NotNull(SecurityOptions.PepperRefusal(pepper));

    [Fact]
    public void AGeneratedPepper_IsAccepted_AndNotShort()
    {
        var pepper = Convert.ToBase64String(new byte[32]);
        Assert.Null(SecurityOptions.PepperRefusal(pepper));
        Assert.False(SecurityOptions.PepperIsShort(pepper));
        Assert.True(SecurityOptions.PepperIsShort(Convert.ToBase64String(new byte[16])));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not base64!")]
    public void Production_DoesNotStart_WithoutAUsablePepper(string? pepper)
    {
        using var factory = new ProductionFactory(pepper);
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("Security:ApiKeyPepper", ex.ToString());
    }

    [Fact]
    public async Task Production_Starts_WithAShortPepper()
    {
        using var factory = new ProductionFactory(Convert.ToBase64String(new byte[16]));
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        var resp = await client.GetAsync("/api/health");
        Assert.True(resp.IsSuccessStatusCode, resp.StatusCode.ToString());
    }

    private sealed class ProductionFactory(string? pepper) : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-pepper-{Guid.NewGuid():N}.db");

        protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder) =>
            builder.ConfigureTestServices(s => s.RemoveAll<IHostedService>());

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Production");
            builder.ConfigureHostConfiguration(cfg => cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:AppDb"] = $"Data Source={_dbPath}",
                ["Security:ApiKeyPepper"] = pepper,
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
