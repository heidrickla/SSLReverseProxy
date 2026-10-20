using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Auth;

public static class ApiKeyDefaults
{
    public const string Scheme = "ApiKey";
    public const string HeaderName = "X-Api-Key";

    /// <summary>Set on principals signed in with a session cookie; its value is the session id.</summary>
    public const string SessionClaim = "sslrp:session";
}

public sealed class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions { }

/// <summary>
/// Authenticates a request by an API key (<c>X-Api-Key</c> or <c>Authorization: Bearer</c>) or by a passkey
/// session cookie, never both. A session is checked against the database on every request: unexpired, not
/// revoked, the user active and in the role the session started with. Claims carry the user id, name and
/// role. No token is logged.
/// </summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    /// <summary>Holds the session secret for <see cref="SessionCsrfMiddleware"/>.</summary>
    public const string SessionSecretItem = "sslrp:session-secret";

    private readonly IApiKeyService _apiKeys;
    private readonly AppDbContext _db;
    private readonly PasskeyOptions _passkeys;
    private readonly TimeProvider _clock;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IApiKeyService apiKeys,
        AppDbContext db,
        IOptions<PasskeyOptions> passkeys,
        TimeProvider clock)
        : base(options, logger, encoder)
    {
        _apiKeys = apiKeys;
        _db = db;
        _passkeys = passkeys.Value;
        _clock = clock;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = ExtractToken();
        var cookie = _passkeys.Enabled ? Request.Cookies[SessionTokens.CookieName] : null;

        if (!string.IsNullOrEmpty(token) && !string.IsNullOrEmpty(cookie))
            return AuthenticateResult.Fail("Send an API key or a session cookie, not both.");

        if (!string.IsNullOrEmpty(cookie))
            return await AuthenticateSessionAsync(cookie);

        if (string.IsNullOrEmpty(token))
            return AuthenticateResult.NoResult(); // let the challenge produce 401

        var user = await _apiKeys.AuthenticateAsync(token, Context.RequestAborted);
        if (user is null)
            return AuthenticateResult.Fail("Invalid API key.");
        return Success(user, null);
    }

    private async Task<AuthenticateResult> AuthenticateSessionAsync(string cookie)
    {
        if (!SessionTokens.TryParse(cookie, out var id, out var secret))
            return Reject();

        var session = await _db.Sessions.Include(s => s.User)
            .SingleOrDefaultAsync(s => s.Id == id, Context.RequestAborted);
        if (session is null || !SessionTokens.Matches(secret, session.SecretHash))
            return Reject();

        var now = _clock.GetUtcNow();
        if (session.RevokedAt is not null || session.ExpiresAt <= now || session.User is not { IsActive: true } user)
            return Reject();
        if (user.Role != session.Role)
        {
            session.RevokedAt = now;
            await _db.SaveChangesAsync(Context.RequestAborted);
            return Reject();
        }

        Context.Items[SessionSecretItem] = secret;
        return Success(user, session.Id);
    }

    // A cookie that no longer authenticates is cleared, so the browser stops sending it.
    private AuthenticateResult Reject()
    {
        Response.Cookies.Delete(SessionTokens.CookieName, SessionTokens.CookieOptions(DateTimeOffset.UnixEpoch));
        return AuthenticateResult.Fail("Session is not valid.");
    }

    private AuthenticateResult Success(User user, Guid? sessionId)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Role, user.Role.ToString()),
        };
        if (sessionId is { } sid) claims.Add(new Claim(ApiKeyDefaults.SessionClaim, sid.ToString()));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, ApiKeyDefaults.Scheme));
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

/// <summary>
/// For requests signed in with a session cookie, an unsafe method needs an <c>Origin</c> listed in
/// <c>Passkeys:Origins</c> and the session's CSRF token in <c>X-CSRF-Token</c>. API-key requests carry no
/// ambient credential and pass through.
/// </summary>
public sealed class SessionCsrfMiddleware(RequestDelegate next, IOptions<PasskeyOptions> options)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        if (ctx.Items[ApiKeyAuthenticationHandler.SessionSecretItem] is string secret
            && !HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method)
            && !HttpMethods.IsOptions(ctx.Request.Method))
        {
            var origin = ctx.Request.Headers.Origin.ToString();
            if (!options.Value.AllowsOrigin(origin)
                || !SessionTokens.CsrfMatches(secret, ctx.Request.Headers[SessionTokens.CsrfHeader].ToString()))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsJsonAsync(new { message = "The request's origin or CSRF token is missing or wrong." });
                return;
            }
        }
        await next(ctx);
    }
}
