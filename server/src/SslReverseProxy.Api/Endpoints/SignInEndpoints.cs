using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>
/// The checks Caddy calls for a rule's sign-in, with the proxied request's headers. Requests under
/// <see cref="PathPrefix"/> skip HTTPS redirection, the client certificate and this service's own sign-in.
/// </summary>
public static class SignInEndpoints
{
    public const string PathPrefix = "/api/sign-in";

    public static bool IsSignInPath(PathString path) => path.StartsWithSegments(PathPrefix, StringComparison.OrdinalIgnoreCase);

    public static void MapSignInEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(SignInProviders.CloudflareVerifyPath + "{ruleId:guid}", async (
            Guid ruleId, HttpContext ctx, AppDbContext db, CloudflareAccessVerifier verifier, ILoggerFactory logs) =>
        {
            var log = logs.CreateLogger(typeof(SignInEndpoints).FullName!);
            var rule = await db.Rules.AsNoTracking().Where(r => r.Id == ruleId)
                .Select(r => new { r.SignInProvider, r.CloudflareTeamDomain, r.CloudflareAudience })
                .FirstOrDefaultAsync(ctx.RequestAborted);
            if (rule is not { SignInProvider: SignInProviders.CloudflareAccess, CloudflareTeamDomain: { } team, CloudflareAudience: { } audience })
            {
                log.LogWarning("Cloudflare Access check for rule {RuleId} refused: the rule does not use Cloudflare Access.", ruleId);
                return Refused();
            }

            var tokens = ctx.Request.Headers[SignInProviders.CloudflareTokenHeader];
            var result = tokens.Count > 1
                ? new CloudflareAccessResult(false, null, "more than one token")
                : await verifier.VerifyAsync(team, audience, tokens.ToString(), ctx.RequestAborted);
            if (!result.Ok)
            {
                log.LogInformation("Cloudflare Access check for rule {RuleId} refused: {Reason}.", ruleId, result.Reason);
                return Refused();
            }
            if (result.Email is { } email && IsHeaderSafe(email))
                ctx.Response.Headers[SignInProviders.CloudflareEmailHeader] = email;
            return Results.Ok();
        }).AllowAnonymous().DisableRateLimiting().ExcludeFromDescription();
    }

    // Caddy hands a refusal to the client as it stands.
    private static IResult Refused() => Results.Text("Sign-in required.", "text/plain", statusCode: StatusCodes.Status403Forbidden);

    private static bool IsHeaderSafe(string value) => value.Length is > 0 and <= 320 && value.All(c => c is > ' ' and < '\x7f');
}
