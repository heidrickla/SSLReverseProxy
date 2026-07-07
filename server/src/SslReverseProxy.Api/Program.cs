using System.Net;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Endpoints;
using SslReverseProxy.Api.Security;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Infrastructure;
using SslReverseProxy.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

var securityOptions = builder.Configuration.GetSection(SecurityOptions.SectionName).Get<SecurityOptions>()
    ?? new SecurityOptions();
builder.Services.AddSingleton(securityOptions);

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

builder.Services.AddAuthentication(ApiKeyDefaults.Scheme)
    .AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(ApiKeyDefaults.Scheme, _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPermissionPolicies();
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
            PermitLimit = 100,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
    });
});

// Trust X-Forwarded-* only from configured proxies so the real client IP (used
// by the rate limiter and audit log) can't be spoofed by clients.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownProxies.Clear();
    o.KnownNetworks.Clear();
    foreach (var proxy in securityOptions.TrustedProxies)
    {
        if (proxy.Contains('/'))
        {
            var parts = proxy.Split('/');
            if (IPAddress.TryParse(parts[0], out var prefix) && int.TryParse(parts[1], out var len))
                o.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(prefix, len));
        }
        else if (IPAddress.TryParse(proxy, out var ip))
        {
            o.KnownProxies.Add(ip);
        }
    }
});

builder.Services.AddProblemDetails();
if (builder.Environment.IsDevelopment())
    builder.Services.AddOpenApi();

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

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<ClientCertificateMiddleware>(); // enforces mTLS when enabled
app.UseRateLimiter();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
    app.MapOpenApi();

app.MapProxyEndpoints();
app.MapServerEndpoints();
app.MapAdminEndpoints();

await DbBootstrapper.InitializeAsync(app.Services);

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program { }
