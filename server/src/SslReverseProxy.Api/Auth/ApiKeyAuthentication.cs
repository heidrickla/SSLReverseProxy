using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;

namespace SslReverseProxy.Api.Auth;

public static class ApiKeyDefaults
{
    public const string Scheme = "ApiKey";
    public const string HeaderName = "X-Api-Key";
}

public sealed class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions { }

/// <summary>
/// Authenticates requests by a presented API key, taken from the
/// <c>X-Api-Key</c> header or an <c>Authorization: Bearer</c> header. On success
/// it emits claims for the user id, name, and role. No plaintext key is logged.
/// </summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private readonly IApiKeyService _apiKeys;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IApiKeyService apiKeys)
        : base(options, logger, encoder)
    {
        _apiKeys = apiKeys;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = ExtractToken();
        if (string.IsNullOrEmpty(token))
            return AuthenticateResult.NoResult(); // let the challenge produce 401

        var user = await _apiKeys.AuthenticateAsync(token, Context.RequestAborted);
        if (user is null)
            return AuthenticateResult.Fail("Invalid API key.");

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(ClaimTypes.Role, user.Role.ToString()),
        };
        var identity = new ClaimsIdentity(claims, ApiKeyDefaults.Scheme);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, ApiKeyDefaults.Scheme));
    }

    private string? ExtractToken()
    {
        if (Request.Headers.TryGetValue(ApiKeyDefaults.HeaderName, out var headerVal))
        {
            var v = headerVal.ToString();
            if (!string.IsNullOrWhiteSpace(v)) return v.Trim();
        }

        var auth = Request.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();

        return null;
    }
}
