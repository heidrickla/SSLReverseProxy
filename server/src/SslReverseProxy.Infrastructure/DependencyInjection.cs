using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Audit;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        var connString = config.GetConnectionString("AppDb") ?? "Data Source=sslrp.db";
        services.AddDbContext<AppDbContext>(o => o.UseSqlite(connString));

        services.Configure<ProxyOptions>(config.GetSection(ProxyOptions.SectionName));

        services.AddSingleton(TimeProvider.System);

        // API-key pepper comes from configuration/secret store, never source.
        var pepper = config["Security:ApiKeyPepper"];
        services.AddSingleton<IApiKeyHasher>(_ => new ApiKeyHasher(pepper));
        services.AddSingleton<BootstrapKeyBroker>();
        services.AddScoped<IApiKeyService, ApiKeyService>();
        services.AddScoped<IAuditLog, AuditLog>();

        services.AddSingleton<ProxyTargetValidator>(sp =>
        {
            var opts = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ProxyOptions>>().Value;
            return new ProxyTargetValidator(new ProxyTargetPolicy
            {
                AllowLoopback = opts.AllowLoopbackUpstreams,
                AllowPrivateNetworks = opts.AllowPrivateUpstreams,
            });
        });

        services.AddHttpClient("caddy-admin");
        services.AddHttpClient("upstream-health");
        services.AddSingleton<IProxyController, CaddyProxyController>();
        services.AddSingleton<IEventStream, EventStream>();
        services.AddScoped<IUpstreamHealthChecker, UpstreamHealthChecker>();

        return services;
    }
}
