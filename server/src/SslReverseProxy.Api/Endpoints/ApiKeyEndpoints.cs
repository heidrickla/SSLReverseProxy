using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>
/// Issues, lists, rotates and revokes API keys. A key's scopes stay within its owner's role and within the
/// caller's own permissions, so no key issues a wider one. Lifetime is 1 to 365 days for every issued key.
/// </summary>
public static class ApiKeyEndpoints
{
    private const int MaxNameLength = 100;

    public static void MapApiKeys(IEndpointRouteBuilder app)
    {
        var keys = app.MapGroup("/api/apikeys").WithTags("API Keys")
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ApiKeyManage));

        keys.MapGet("/", async (AppDbContext db, Guid? userId, CancellationToken ct) =>
        {
            var q = db.ApiKeys.AsNoTracking().Include(k => k.User).AsQueryable();
            if (userId is { } uid) q = q.Where(k => k.UserId == uid);
            var rows = await q.ToListAsync(ct);
            return Results.Ok(rows.OrderByDescending(k => k.CreatedAt).Select(k => k.ToDto()));
        });

        keys.MapGet("/options", () => Results.Ok(new ApiKeyOptionsDto(
            [.. ApiKeyScopes.LifetimeDays], ApiKeyScopes.DefaultLifetimeDays, ApiKeyScopes.MaxLifetimeDays,
            ApiKeyScopes.Presets.Select(p => new ApiKeyPresetDto(
                p.Id, p.Name, p.Description, p.Scopes is null ? null : DtoMappings.Names(p.Scopes))).ToArray(),
            DtoMappings.Names(Enum.GetValues<Permission>()),
            Enum.GetValues<Role>().ToDictionary(r => r.ToString(), r => DtoMappings.Names(Permissions.For(r))))));

        keys.MapPost("/", async (
            CreateApiKeyRequest req, AppDbContext db, IApiKeyService svc, TimeProvider clock,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var ct = ctx.RequestAborted;
            var name = req.Name?.Trim() ?? "";
            if (name.Length is 0 or > MaxNameLength || name.Any(char.IsControl))
                return Invalid("name", $"Name must be 1 to {MaxNameLength} characters, with no control characters.");
            if (await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == req.UserId, ct) is not { } owner)
                return Results.NotFound(new { message = "User not found." });

            var refusal = Check(req.LifetimeDays, req.ExpiresAt, req.Scopes, owner, me, clock.GetUtcNow(),
                out var expiresAt, out var scopes);
            if (refusal is not null) return refusal;

            var issued = await svc.CreateAsync(owner.Id, name, expiresAt, scopes, ct);
            await audit.AuditAsync(me, ctx, "Create API Key", "API Key", issued.Record.Name,
                details: Describe(owner, issued.Record));
            // The plaintext token is returned here once and never persisted or shown again.
            return Results.Created($"/api/apikeys/{issued.Record.Id}", Issued(issued));
        });

        keys.MapPost("/{id:guid}/revoke", async (
            Guid id, IApiKeyService svc, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            await svc.RevokeAsync(id, ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Revoke API Key", "API Key", id.ToString());
            return Results.NoContent();
        });

        // Issues a new key for the same owner and name and revokes the old one, in one write transaction,
        // so two rotations of one key cannot both succeed.
        keys.MapPost("/{id:guid}/rotate", async (
            Guid id, RotateApiKeyRequest? req, AppDbContext db, IApiKeyService svc, TimeProvider clock,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var ct = ctx.RequestAborted;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var old = await db.ApiKeys.Include(k => k.User).FirstOrDefaultAsync(k => k.Id == id, ct);
            if (old?.User is not { } owner) return Results.NotFound();
            if (old.RevokedAt is not null)
                return Results.Conflict(new { message = "A revoked key cannot be rotated; issue a new one." });

            var now = clock.GetUtcNow();
            var refusal = req is null
                ? Check(KeptLifetimeDays(old), null, DtoMappings.ScopeNames(old.Scopes), owner, me, now,
                    out var expiresAt, out var scopes, kept: true)
                : Check(req.LifetimeDays, req.ExpiresAt, req.Scopes, owner, me, now, out expiresAt, out scopes);
            if (refusal is not null) return refusal;

            var issued = await svc.CreateAsync(owner.Id, old.Name, expiresAt, scopes, ct);
            old.RevokedAt = now;
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            await audit.AuditAsync(me, ctx, "Rotate API Key", "API Key", old.Name, details: Describe(owner, issued.Record));
            return Results.Ok(Issued(issued));
        });
    }

    /// <summary>
    /// Null when the lifetime and scopes may be issued to <paramref name="owner"/> by <paramref name="me"/>;
    /// otherwise the refusal. Exactly one of days or a date; scopes within the owner's role and the caller's
    /// permissions; a key that follows its owner's role only from a caller that is not a scoped key.
    /// </summary>
    internal static IResult? Check(int? lifetimeDays, DateTimeOffset? requestedExpiry, string[]? scopeNames,
        User owner, ICurrentPrincipal me, DateTimeOffset now,
        out DateTimeOffset expiresAt, out IReadOnlySet<Permission>? scopes, bool kept = false)
    {
        expiresAt = default;
        scopes = null;
        var max = TimeSpan.FromDays(ApiKeyScopes.MaxLifetimeDays);

        switch (lifetimeDays, requestedExpiry)
        {
            case (null, null):
                return Invalid("lifetimeDays", kept
                    ? "The old key does not expire; choose how long the new key lasts, 1 to 365 days."
                    : "Choose how long the key lasts, 1 to 365 days.");
            case ({ }, { }):
                return Invalid("lifetimeDays", "Send lifetimeDays or expiresAt, not both.");
            case ({ } days, null):
                if (days is < 1 or > ApiKeyScopes.MaxLifetimeDays)
                    return Invalid("lifetimeDays", "A key lasts 1 to 365 days.");
                expiresAt = now.AddDays(days);
                break;
            case (null, { } at):
                if (at <= now || at - now > max)
                    return Invalid("expiresAt", "The expiry date must be in the future and at most 365 days away.");
                expiresAt = at.ToUniversalTime();
                break;
        }

        if (scopeNames is null)
        {
            if (me.IsScopedKey)
                return Results.Json(new { message = "A key limited to scopes cannot issue a key that follows its owner's role." },
                    statusCode: StatusCodes.Status403Forbidden);
            return null;
        }

        var requested = ApiKeyScopes.FromNames(scopeNames, out var unknown);
        if (requested is null)
            return Invalid("scopes", $"'{unknown}' is not a permission.");
        if (requested.Count == 0)
            return Invalid("scopes", "Choose at least one permission.");

        var ownerLacks = requested.Except(Permissions.For(owner.Role)).Order().ToList();
        if (ownerLacks.Count > 0)
            return Invalid("scopes", $"{owner.Name} ({owner.Role}) does not hold {string.Join(", ", ownerLacks)}.");
        var callerLacks = requested.Except(me.Permissions).Order().ToList();
        if (callerLacks.Count > 0)
            return Results.Json(new { message = $"You cannot grant permissions you do not hold: {string.Join(", ", callerLacks)}." },
                statusCode: StatusCodes.Status403Forbidden);

        scopes = requested;
        return null;
    }

    // The old key's lifetime, whole days, capped at the maximum; null when it does not expire.
    private static int? KeptLifetimeDays(ApiKey old) =>
        old.ExpiresAt is { } exp
            ? Math.Clamp((int)Math.Round((exp - old.CreatedAt).TotalDays), 1, ApiKeyScopes.MaxLifetimeDays)
            : null;

    private static IssuedApiKeyDto Issued(IssuedApiKey issued) => new(
        issued.Record.Id, issued.Record.Name, issued.PlaintextToken, issued.Record.ExpiresAt,
        DtoMappings.ScopeNames(issued.Record.Scopes));

    private static string Describe(User owner, ApiKey key) =>
        $"owner {owner.Name}; expires {key.ExpiresAt:yyyy-MM-dd HH:mm 'UTC'}; scopes {key.Scopes ?? "role"}";

    private static IResult Invalid(string field, string message) =>
        Results.ValidationProblem(new Dictionary<string, string[]> { [field] = [message] });
}
