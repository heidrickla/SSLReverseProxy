using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Alerts;
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
        services.AddSingleton(SecretRedactor.FromConfiguration(config));
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

        services.AddHttpClient("caddy-admin", c => c.Timeout = CaddyProxyController.AdminRequestTimeout);
        services.AddHttpClient("upstream-health");

        services.Configure<AlertOptions>(config.GetSection(AlertOptions.SectionName));
        services.AddHttpClient(AlertSender.ClientName, c => c.Timeout = AlertSender.RequestTimeout)
            // The factory's logging handlers write the request URL, which is a secret for these targets.
            .RemoveAllLoggers()
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
        services.AddSingleton<AlertSender>();
        services.AddSingleton<TrafficRecorder>();
        services.AddSingleton<CaddyCertificateLog>();
        services.AddSingleton<RecentRequests>();
        services.AddSingleton<ICertificateProbe, TlsCertificateProbe>();
        services.AddSingleton<IProxyController, CaddyProxyController>();
        services.AddSingleton<ProxyChanges>();
        services.AddSingleton<IEventStream, EventStream>();
        services.AddScoped<IUpstreamHealthChecker, UpstreamHealthChecker>();

        return services;
    }
}
