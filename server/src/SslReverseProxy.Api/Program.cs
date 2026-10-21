using System.Net;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Fido2NetLib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using SslReverseProxy.Api.Alerts;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Api.Endpoints;
using SslReverseProxy.Api.Health;
using SslReverseProxy.Api.Security;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure;
using SslReverseProxy.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

var securityOptions = builder.Configuration.GetSection(SecurityOptions.SectionName).Get<SecurityOptions>()
    ?? new SecurityOptions();
builder.Services.AddSingleton(securityOptions);

var passkeyOptions = builder.Configuration.GetSection(PasskeyOptions.SectionName).Get<PasskeyOptions>()
    ?? new PasskeyOptions();
builder.Services.Configure<PasskeyOptions>(builder.Configuration.GetSection(PasskeyOptions.SectionName));

// Optional mutual TLS: ask Kestrel to request/require a client certificate.
builder.WebHost.ConfigureKestrel(k =>
{
    k.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = securityOptions.RequireMutualTls
            ? ClientCertificateMode.RequireCertificate
            : ClientCertificateMode.AllowCertificate;
        // Chain validation is delegated to the allow-list (thumbprint pin) in
        // ClientCertificateMiddleware.
        https.AllowAnyClientCertificate();
    });
});

// Serialize/deserialize enums as their string names (e.g. role "Viewer").
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentPrincipal, CurrentPrincipal>();
builder.Services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, UnscopedAuthorizationHandler>();

builder.Services.AddSingleton<PasskeyChallenges>();
builder.Services.AddSingleton<IFido2>(_ => new Fido2(new Fido2Configuration
{
    RPID = passkeyOptions.RelyingPartyId?.Trim() ?? "localhost",
    RPName = passkeyOptions.RelyingPartyName,
    Origins = passkeyOptions.AllowedOrigins,
}));

builder.Services.AddSingleton<AlertDispatcher>();
builder.Services.AddSingleton<IAlertSink>(sp => sp.GetRequiredService<AlertDispatcher>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<AlertDispatcher>());
builder.Services.AddSingleton<ServerHealthMonitor>();
builder.Services.AddSingleton<IServerHealthStore>(sp => sp.GetRequiredService<ServerHealthMonitor>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<ServerHealthMonitor>());
builder.Services.AddHostedService<TrafficSampler>();
builder.Services.AddSingleton<CertificateMonitor>();
builder.Services.AddSingleton<ICertificateChecks>(sp => sp.GetRequiredService<CertificateMonitor>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<CertificateMonitor>());
builder.Services.AddSingleton<ApiKeyExpiryMonitor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ApiKeyExpiryMonitor>());

builder.Services.AddAuthentication(ApiKeyDefaults.Scheme)
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(ApiKeyDefaults.Scheme, _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPermissionPolicies();
    options.AddUnscopedPolicy();
    // Deny by default: everything requires an authenticated principal unless it
    // explicitly opts out with AllowAnonymous.
    options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
});

builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
{
    if (securityOptions.CorsAllowedOrigins.Length > 0)
        p.WithOrigins(securityOptions.CorsAllowedOrigins)
            .WithHeaders("Authorization", ApiKeyDefaults.HeaderName, "Content-Type")
            .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE");
    // With no configured origins the policy allows nothing cross-origin.
}));

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
    {
        var key = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, securityOptions.RequestsPerMinute),
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
    });
    options.AddPolicy(PasskeyEndpoints.OptionsLimit, ctx => PerIp(ctx, passkeyOptions.OptionsPerMinute));
    options.AddPolicy(PasskeyEndpoints.SignInLimit, ctx => PerIp(ctx, passkeyOptions.SignInsPerMinute));

    static RateLimitPartition<string> PerIp(HttpContext ctx, int perMinute) =>
        RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = Math.Max(1, perMinute),
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            });
});

// Trust X-Forwarded-* only from configured proxies so the real client IP (used
// by the rate limiter and audit log) can't be spoofed by clients.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Clear();
    o.KnownIPNetworks.Clear();
    foreach (var proxy in securityOptions.TrustedProxies)
    {
        if (proxy.Contains('/'))
        {
            if (System.Net.IPNetwork.TryParse(proxy, out var network))
                o.KnownIPNetworks.Add(network);
        }
        else if (IPAddress.TryParse(proxy, out var ip))
        {
            o.KnownProxies.Add(ip);
        }
    }
});

builder.Services.AddProblemDetails();
builder.Services.AddOpenApi(o => o.AddDocumentTransformer(OpenApiDescription.Describe));

var app = builder.Build();

// Fail loudly in production if secret material is missing.
if (app.Environment.IsProduction() && string.IsNullOrEmpty(securityOptions.ApiKeyPepper))
{
    app.Logger.LogWarning(
        "Security:ApiKeyPepper is not set. Configure a random pepper via user-secrets or environment " +
        "before exposing this service in production.");
}

app.UseForwardedHeaders();

app.UseExceptionHandler();
app.UseStatusCodePages();

// Caddy calls the sign-in checks with the proxied request's headers, cookies and Authorization included.
// The authentication handler skips them too: UseAuthentication inside a branch would be added again for every request.
static bool ControlPlane(HttpContext ctx) => !SignInEndpoints.IsSignInPath(ctx.Request.Path);

if (!app.Environment.IsDevelopment())
{
    app.UseWhen(ControlPlane, b =>
    {
        b.UseHsts();
        b.UseHttpsRedirection();
    });
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseWhen(ControlPlane, b => b.UseMiddleware<ClientCertificateMiddleware>()); // enforces mTLS when enabled
app.UseRateLimiter();
app.UseCors();
app.UseAuthentication();
app.UseMiddleware<SessionCsrfMiddleware>();
app.UseAuthorization();

// The API's own description, under /api so the edge that forwards /api serves it, for any principal that can read servers.
app.MapOpenApi("/api/openapi/{documentName}.json").RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

app.MapProxyEndpoints();
app.MapServerEndpoints();
app.MapAdminEndpoints();
app.MapCertificateEndpoints();
app.MapBackupEndpoints();
app.MapAlertEndpoints();
app.MapPasskeyEndpoints();
app.MapSignInEndpoints();

// Seed:Demo fills a new Development database with sample data, for screenshots and the browser smoke test.
var seedDemo = app.Configuration.GetValue<bool>("Seed:Demo");
if (seedDemo && !app.Environment.IsDevelopment())
{
    app.Logger.LogWarning("Seed:Demo is ignored outside Development.");
    seedDemo = false;
}
await DbBootstrapper.InitializeAsync(app.Services,
    seedDemo ? app.Configuration["Seed:DemoUpstreamBase"] ?? "http://127.0.0.1:5195" : null);

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program { }
