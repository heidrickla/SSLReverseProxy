using System.Text.Json;
using System.Text.Json.Nodes;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>
/// Passkey sign-in and the passkeys a user holds. Sign-in uses discoverable credentials with user
/// verification required, and starts a cookie session; API keys work as before.
/// </summary>
public static class PasskeyEndpoints
{
    public const string OptionsLimit = "passkey-options";
    public const string SignInLimit = "passkey-signin";
    public const int MaxPerUser = 10;

    public static IEndpointRouteBuilder MapPasskeyEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/api/auth").WithTags("Auth");

        auth.MapGet("/methods", (IOptions<PasskeyOptions> o) => Results.Ok(new AuthMethodsDto(o.Value.Enabled)))
            .AllowAnonymous();

        auth.MapPost("/passkey/options", (IFido2 fido2, PasskeyChallenges challenges, IOptions<PasskeyOptions> o) =>
        {
            if (!o.Value.Enabled) return NotConfigured();
            var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = [],
                UserVerification = UserVerificationRequirement.Required,
            });
            var json = options.ToJson();
            return challenges.Add(PasskeyChallenges.Kind.SignIn, null, json) is { } handle
                ? Ceremony(handle, json)
                : Busy();
        }).AllowAnonymous().RequireRateLimiting(OptionsLimit);

        auth.MapPost("/passkey", async (
            JsonElement body, IFido2 fido2, PasskeyChallenges challenges, IOptions<PasskeyOptions> o,
            AppDbContext db, IAuditLog audit, TimeProvider clock, HttpContext ctx) =>
        {
            if (!o.Value.Enabled) return NotConfigured();
            var ct = ctx.RequestAborted;
            if (!TryRead<AuthenticatorAssertionRawResponse>(body, out var handle, out var response))
                return Results.BadRequest(new { message = "Expected {handle, response}." });

            var json = challenges.Take(handle, PasskeyChallenges.Kind.SignIn, null);
            if (json is null)
                return await SignInFailed(audit, ctx, null, "ceremony expired or unknown");

            var cred = await db.Passkeys.Include(p => p.User)
                .SingleOrDefaultAsync(p => p.CredentialId == response.RawId, ct);
            if (cred?.User is not { IsActive: true } user)
                return await SignInFailed(audit, ctx, cred, cred is null ? "unknown credential" : "user inactive");

            try
            {
                var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
                {
                    AssertionResponse = response,
                    OriginalOptions = AssertionOptions.FromJson(json),
                    StoredPublicKey = cred.PublicKey,
                    StoredSignatureCounter = cred.SignCount,
                    IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
                        Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(cred.UserId.ToByteArray())),
                }, ct);
                cred.SignCount = result.SignCount;
                cred.BackedUp = result.IsBackedUp;
            }
            catch (Fido2VerificationException)
            {
                return await SignInFailed(audit, ctx, cred, "verification failed");
            }

            var now = clock.GetUtcNow();
            cred.LastUsedAt = now;
            var session = new UserSession
            {
                UserId = user.Id,
                PasskeyId = cred.Id,
                Role = user.Role,
                CreatedAt = now,
                ExpiresAt = now.AddHours(Math.Clamp(o.Value.SessionHours, 1, 168)),
            };
            var (token, hash) = SessionTokens.Create(session.Id);
            session.SecretHash = hash;
            db.Sessions.Add(session);
            // Ended sessions of this user are dropped here, so the table stays small without a sweeper.
            var ended = (await db.Sessions.Where(s => s.UserId == user.Id).ToListAsync(ct))
                .Where(s => s.RevokedAt is not null || s.ExpiresAt <= now);
            db.Sessions.RemoveRange(ended);
            user.LastSeenAt = now;
            await db.SaveChangesAsync(ct);

            ctx.Response.Cookies.Append(SessionTokens.CookieName, token, SessionTokens.CookieOptions(session.ExpiresAt));
            await audit.WriteAsync(Entry(ctx, user.Name, user.Id, "Passkey Sign-In", cred.Name, true, null), ct);
            var secret = token[(token.LastIndexOf('.') + 1)..];
            return Results.Ok(new PasskeySignInDto(SessionTokens.CsrfToken(secret), session.ExpiresAt, new WhoAmIDto(
                user.Id, user.Name, user.Role.ToString(), Permissions.For(user.Role).Select(p => p.ToString()).ToArray())));
        }).AllowAnonymous().RequireRateLimiting(SignInLimit);

        // A reloaded page recovers the CSRF token for its cookie here.
        auth.MapGet("/session", async (HttpContext ctx, ICurrentPrincipal me, AppDbContext db) =>
        {
            if (ctx.Items[ApiKeyAuthenticationHandler.SessionSecretItem] is not string secret
                || !Guid.TryParse(ctx.User.FindFirst(ApiKeyDefaults.SessionClaim)?.Value, out var id))
                return Results.NotFound(new { message = "Not signed in with a passkey session." });
            var session = await db.Sessions.AsNoTracking().SingleAsync(s => s.Id == id, ctx.RequestAborted);
            return Results.Ok(new SessionDto(SessionTokens.CsrfToken(secret), session.ExpiresAt));
        }).RequireAuthorization();

        // Anonymous so a stale cookie can still be cleared; a live session is revoked (the CSRF check applies).
        auth.MapPost("/logout", async (HttpContext ctx, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, TimeProvider clock) =>
        {
            if (Guid.TryParse(ctx.User.FindFirst(ApiKeyDefaults.SessionClaim)?.Value, out var id)
                && await db.Sessions.FindAsync([id], ctx.RequestAborted) is { } session)
            {
                session.RevokedAt = clock.GetUtcNow();
                await db.SaveChangesAsync(ctx.RequestAborted);
                await audit.AuditAsync(me, ctx, "Sign Out", "Session", me.Name);
            }
            ctx.Response.Cookies.Delete(SessionTokens.CookieName, SessionTokens.CookieOptions(DateTimeOffset.UnixEpoch));
            return Results.NoContent();
        }).AllowAnonymous();

        var passkeys = app.MapGroup("/api/passkeys").WithTags("Auth").RequireAuthorization();

        passkeys.MapGet("/", async (ICurrentPrincipal me, AppDbContext db, CancellationToken ct) =>
        {
            var rows = me.UserId is { } uid
                ? await db.Passkeys.AsNoTracking().Where(p => p.UserId == uid).ToListAsync(ct)
                : [];
            return Results.Ok(rows.OrderBy(p => p.CreatedAt).Select(p => p.ToDto()));
        });

        passkeys.MapPost("/options", async (
            ICurrentPrincipal me, AppDbContext db, IFido2 fido2, PasskeyChallenges challenges,
            IOptions<PasskeyOptions> o, CancellationToken ct) =>
        {
            if (!o.Value.Enabled) return NotConfigured();
            if (await db.Users.FindAsync([me.UserId], ct) is not { } user) return Results.NotFound();
            var existing = await db.Passkeys.Where(p => p.UserId == user.Id).Select(p => p.CredentialId).ToListAsync(ct);
            if (existing.Count >= MaxPerUser)
                return Results.Conflict(new { message = $"A user may hold {MaxPerUser} passkeys; remove one first." });

            var options = fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = new Fido2User { Id = user.Id.ToByteArray(), Name = user.Email, DisplayName = user.Name },
                ExcludeCredentials = existing.Select(id => new PublicKeyCredentialDescriptor(id)).ToList(),
                AuthenticatorSelection = new AuthenticatorSelection
                {
                    ResidentKey = ResidentKeyRequirement.Required,
                    UserVerification = UserVerificationRequirement.Required,
                },
                AttestationPreference = AttestationConveyancePreference.None,
            });
            var json = options.ToJson();
            return challenges.Add(PasskeyChallenges.Kind.Register, user.Id, json) is { } handle
                ? Ceremony(handle, json)
                : Busy();
        });

        passkeys.MapPost("/", async (
            JsonElement body, ICurrentPrincipal me, AppDbContext db, IFido2 fido2, PasskeyChallenges challenges,
            IOptions<PasskeyOptions> o, IAuditLog audit, TimeProvider clock, HttpContext ctx) =>
        {
            if (!o.Value.Enabled) return NotConfigured();
            var ct = ctx.RequestAborted;
            if (!TryRead<AuthenticatorAttestationRawResponse>(body, out var handle, out var response))
                return Results.BadRequest(new { message = "Expected {handle, name, response}." });
            var name = body.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()!.Trim() : "";
            if (name.Length == 0) name = "Passkey";
            if (name.Length > 100 || name.Any(char.IsControl))
                return Results.BadRequest(new { message = "Name must be at most 100 characters, with no control characters." });

            var json = challenges.Take(handle, PasskeyChallenges.Kind.Register, me.UserId);
            if (json is null || await db.Users.FindAsync([me.UserId], ct) is not { } user)
                return Results.BadRequest(new { message = "The registration expired; start again." });

            RegisteredPublicKeyCredential registered;
            try
            {
                registered = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
                {
                    AttestationResponse = response,
                    OriginalOptions = CredentialCreateOptions.FromJson(json),
                    IsCredentialIdUniqueToUserCallback = async (args, token) =>
                        !await db.Passkeys.AnyAsync(p => p.CredentialId == args.CredentialId, token),
                }, ct);
            }
            catch (Fido2VerificationException)
            {
                await audit.AuditAsync(me, ctx, "Register Passkey", "Passkey", name, success: false, details: "verification failed");
                return Results.BadRequest(new { message = "The passkey could not be verified." });
            }

            var passkey = new PasskeyCredential
            {
                UserId = user.Id,
                CredentialId = registered.Id,
                PublicKey = registered.PublicKey,
                SignCount = registered.SignCount,
                Name = name,
                AaGuid = registered.AaGuid,
                BackupEligible = registered.IsBackupEligible,
                BackedUp = registered.IsBackedUp,
                CreatedAt = clock.GetUtcNow(),
            };
            db.Passkeys.Add(passkey);
            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException)
            {
                return Results.Conflict(new { message = "This passkey is already registered." });
            }
            await audit.AuditAsync(me, ctx, "Register Passkey", "Passkey", name);
            return Results.Created($"/api/passkeys/{passkey.Id}", passkey.ToDto());
        });

        // Deleting a passkey ends every session it started.
        passkeys.MapDelete("/{id:guid}", async (Guid id, ICurrentPrincipal me, AppDbContext db, IAuditLog audit, HttpContext ctx) =>
        {
            var passkey = await db.Passkeys.SingleOrDefaultAsync(p => p.Id == id && p.UserId == me.UserId, ctx.RequestAborted);
            if (passkey is null) return Results.NotFound();
            db.Passkeys.Remove(passkey);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Delete Passkey", "Passkey", passkey.Name);
            return Results.NoContent();
        });

        return app;
    }

    private static bool TryRead<T>(JsonElement body, out string? handle, out T response) where T : class
    {
        handle = null;
        response = null!;
        try
        {
            if (body.ValueKind != JsonValueKind.Object
                || !body.TryGetProperty("handle", out var h) || h.ValueKind != JsonValueKind.String
                || !body.TryGetProperty("response", out var r) || r.ValueKind != JsonValueKind.Object)
                return false;
            handle = h.GetString();
            // The library's own (de)serialisation, not the API's options, which change enum names.
            response = JsonSerializer.Deserialize<T>(r.GetRawText())!;
            return response is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static IResult Ceremony(string handle, string optionsJson) =>
        Results.Text(new JsonObject { ["handle"] = handle, ["options"] = JsonNode.Parse(optionsJson) }.ToJsonString(),
            "application/json");

    private static IResult NotConfigured() =>
        Results.NotFound(new { message = "Passkeys are not configured (Passkeys:RelyingPartyId, Passkeys:Origins)." });

    private static IResult Busy() =>
        Results.Problem(title: "Too many passkey ceremonies are in progress; try again shortly.",
            statusCode: StatusCodes.Status503ServiceUnavailable);

    private static async Task<IResult> SignInFailed(IAuditLog audit, HttpContext ctx, PasskeyCredential? cred, string reason)
    {
        await audit.WriteAsync(Entry(ctx, cred?.User?.Name ?? "anonymous", cred?.UserId, "Passkey Sign-In",
            cred?.Name ?? "unknown", false, reason), ctx.RequestAborted);
        return Results.Json(new { message = "Passkey sign-in failed." }, statusCode: StatusCodes.Status401Unauthorized);
    }

    private static AuditEntry Entry(HttpContext ctx, string actor, Guid? userId, string action, string target, bool success, string? details) => new()
    {
        ActorName = actor,
        ActorUserId = userId,
        Action = action,
        TargetType = "Passkey",
        TargetName = target,
        SourceIp = ctx.Connection.RemoteIpAddress?.ToString(),
        Success = success,
        Details = details,
    };

    public static PasskeyDto ToDto(this PasskeyCredential p) => new(p.Id, p.Name, p.CreatedAt, p.LastUsedAt, p.BackedUp);
}
