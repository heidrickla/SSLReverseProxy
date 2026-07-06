namespace SslReverseProxy.Api.Security;

/// <summary>Adds hardening response headers to every response.</summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var h = ctx.Response.Headers;
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Referrer-Policy"] = "no-referrer";
        h["Cross-Origin-Opener-Policy"] = "same-origin";
        h["Cross-Origin-Resource-Policy"] = "same-origin";
        // This API returns JSON only; lock the CSP down hard.
        h["Content-Security-Policy"] =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
        h.Remove("Server");
        await _next(ctx);
    }
}

public sealed class SecurityOptions
{
    public const string SectionName = "Security";
    public string? ApiKeyPepper { get; set; }
    public bool RequireMutualTls { get; set; }
    /// <summary>Allowed client-certificate thumbprints (SHA-256, hex) when mTLS is required.</summary>
    public string[] AllowedClientCertificateThumbprints { get; set; } = Array.Empty<string>();
    public string[] CorsAllowedOrigins { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Enforces mutual TLS when enabled: the request must present a client
/// certificate whose SHA-256 thumbprint is in the allow-list. Layered beneath
/// API-key auth as an additional transport gate.
/// </summary>
public sealed class ClientCertificateMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityOptions _options;
    private readonly ILogger<ClientCertificateMiddleware> _logger;

    public ClientCertificateMiddleware(RequestDelegate next, SecurityOptions options, ILogger<ClientCertificateMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!_options.RequireMutualTls)
        {
            await _next(ctx);
            return;
        }

        var cert = await ctx.Connection.GetClientCertificateAsync(ctx.RequestAborted);
        if (cert is null)
        {
            _logger.LogWarning("mTLS required but no client certificate was presented from {Ip}.",
                ctx.Connection.RemoteIpAddress);
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var thumb = cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);
        var allowed = _options.AllowedClientCertificateThumbprints
            .Any(t => string.Equals(t, thumb, StringComparison.OrdinalIgnoreCase));
        if (!allowed)
        {
            _logger.LogWarning("Client certificate {Thumb} not in allow-list.", thumb);
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await _next(ctx);
    }
}
