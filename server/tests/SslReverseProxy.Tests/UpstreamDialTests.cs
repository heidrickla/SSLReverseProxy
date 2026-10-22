using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure;
using SslReverseProxy.Infrastructure.Proxy;
using Xunit;

namespace SslReverseProxy.Tests;

/// <summary>A loopback listener that answers each connection with one fixed HTTP response.</summary>
internal sealed class OneShotHttp : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly string _response;
    private int _accepted;

    public OneShotHttp(string response)
    {
        _response = response;
        _listener.Start();
        _ = ServeAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public int Accepted => Volatile.Read(ref _accepted);

    private async Task ServeAsync()
    {
        try
        {
            while (true)
            {
                using var client = await _listener.AcceptTcpClientAsync();
                Interlocked.Increment(ref _accepted);
                var stream = client.GetStream();
                var buffer = new byte[4096];
                var seen = new StringBuilder();
                while (!seen.ToString().Contains("\r\n\r\n"))
                {
                    var n = await stream.ReadAsync(buffer);
                    if (n == 0) break;
                    seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
                }
                await stream.WriteAsync(Encoding.ASCII.GetBytes(_response));
            }
        }
        catch (ObjectDisposedException) { }
        catch (SocketException) { }
        catch (InvalidOperationException) { }
    }

    public void Dispose() => _listener.Stop();
}

public class GuardedConnectTests
{
    private const string Ok = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    [Fact]
    public async Task ANameResolvingToABlockedAddress_IsNeverDialled()
    {
        using var target = new OneShotHttp(Ok);
        using var client = new HttpClient(GuardedConnect.Handler(new ProxyTargetValidator(new ProxyTargetPolicy { AllowLoopback = false })));
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://localhost:{target.Port}/"));
        Assert.Contains("Loopback", ex.Message);
        Assert.Equal(0, target.Accepted);
    }

    [Fact]
    public async Task AnAllowedAddress_IsDialled()
    {
        using var target = new OneShotHttp(Ok);
        using var client = new HttpClient(GuardedConnect.Handler(new ProxyTargetValidator()));
        using var resp = await client.GetAsync($"http://127.0.0.1:{target.Port}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(1, target.Accepted);
    }
}

public class UpstreamHealthClientTests
{
    private static ServiceProvider Services(bool allowLoopback) =>
        new ServiceCollection()
            .AddLogging()
            .AddInfrastructure(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Proxy:AllowLoopbackUpstreams"] = allowLoopback ? "true" : "false",
            }).Build())
            .BuildServiceProvider();

    [Fact]
    public async Task TheProbe_ReportsARedirect_AndDoesNotFollowIt()
    {
        using var elsewhere = new OneShotHttp("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var upstream = new OneShotHttp(
            $"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere.Port}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await using var sp = Services(allowLoopback: true);
        using var scope = sp.CreateScope();
        var checker = scope.ServiceProvider.GetRequiredService<IUpstreamHealthChecker>();

        var result = await checker.CheckAsync($"http://127.0.0.1:{upstream.Port}/");

        Assert.Equal(302, result.StatusCode);
        Assert.Equal(1, upstream.Accepted);
        Assert.Equal(0, elsewhere.Accepted);
    }

    [Fact]
    public async Task TheProbeClient_RefusesABlockedAddress_AtConnect()
    {
        using var target = new OneShotHttp("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await using var sp = Services(allowLoopback: false);
        var client = sp.GetRequiredService<IHttpClientFactory>().CreateClient(UpstreamHealthChecker.ClientName);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://127.0.0.1:{target.Port}/"));
        Assert.Equal(0, target.Accepted);
    }
}

/// <summary>Rule writes under a policy that refuses loopback upstreams, as appsettings.Production.json sets.</summary>
public sealed class LoopbackPolicyEndpointTests : IDisposable
{
    private readonly StrictFactory _factory = new();
    private readonly HttpClient _admin;

    public LoopbackPolicyEndpointTests() => _admin = _factory.Authed();

    public void Dispose()
    {
        _admin.Dispose();
        _factory.Dispose();
    }

    private async Task<HttpResponseMessage> PostRule(string upstreamUrl, object? signIn = null)
    {
        var server = await SignInEndpointTests.NewServer(_admin);
        return await _admin.PostAsJsonAsync($"/api/servers/{server}/rules", new
        {
            domain = $"r{Guid.NewGuid():N}.example.com", upstreamUrl, enableTls = false, enabled = true, signIn,
        });
    }

    private static async Task<JsonObject> Errors(HttpResponseMessage r)
    {
        Assert.True(r.StatusCode == HttpStatusCode.BadRequest, await r.Content.ReadAsStringAsync());
        return JsonNode.Parse(await r.Content.ReadAsStringAsync())!["errors"]!.AsObject();
    }

    [Theory]
    [InlineData("http://localhost:2019")]
    [InlineData("http://admin.localhost:2019")]
    [InlineData("http://127.1:2019")]
    [InlineData("http://0.0.0.0:2019")]
    public async Task ALoopbackUpstream_IsRefused(string upstream) =>
        Assert.True((await Errors(await PostRule(upstream))).ContainsKey("upstreamUrl"));

    [Fact]
    public async Task ALoopbackVerifier_IsRefused()
    {
        var errors = await Errors(await PostRule("http://10.0.0.5", new { provider = "authelia", verifierUrl = "http://localhost:9091" }));
        Assert.True(errors.ContainsKey("signIn.verifierUrl"), errors.ToJsonString());
    }

    [Fact]
    public async Task APrivateUpstream_IsStillAccepted()
    {
        var r = await PostRule("http://10.0.0.5:8080");
        Assert.True(r.StatusCode == HttpStatusCode.Created, await r.Content.ReadAsStringAsync());
    }

    private sealed class StrictFactory : WebApplicationFactory<Program>
    {
        private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sslrp-strict-{Guid.NewGuid():N}.db");

        public HttpClient Authed()
        {
            using var scope = Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SslReverseProxy.Infrastructure.Persistence.AppDbContext>();
            var admin = db.Users.First(u => u.Role == SslReverseProxy.Core.Domain.Role.Admin);
            var key = scope.ServiceProvider.GetRequiredService<IApiKeyService>()
                .CreateAsync(admin.Id, "loopback-policy-tests", null).GetAwaiter().GetResult().PlaintextToken;
            var client = CreateClient();
            client.DefaultRequestHeaders.Add("X-Api-Key", key);
            return client;
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            // App configuration, so it lands after appsettings.json, which allows loopback.
            builder.ConfigureAppConfiguration(cfg => cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Proxy:AllowLoopbackUpstreams"] = "false",
            }));
            builder.ConfigureTestServices(s =>
            {
                s.RemoveAll<IHostedService>();
                s.RemoveAll<IProxyController>();
                s.AddSingleton<IProxyController>(new FakeProxy());
            });
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.UseEnvironment("Development");
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
