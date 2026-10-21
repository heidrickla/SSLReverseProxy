using System.Net;
using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Api.Endpoints;

public static class AdminEndpoints
{
    /// <summary>The longest an event stream stays open; the dashboard reconnects and signs in again.</summary>
    internal static readonly TimeSpan EventStreamLifetime = TimeSpan.FromMinutes(15);

    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        MapMeta(app);
        MapUsers(app);
        ApiKeyEndpoints.MapApiKeys(app);
        MapAudit(app);
        return app;
    }

    private static void MapMeta(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/whoami", async (ICurrentPrincipal me, AppDbContext db, CancellationToken ct) =>
        {
            var key = me.ApiKeyId is { } kid
                ? await db.ApiKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == kid, ct)
                : null;
            return Results.Ok(new WhoAmIDto(
                me.UserId, me.Name, me.Role.ToString(), DtoMappings.Names(me.Permissions), me.HoldsWholeRole,
                key is null ? null : new WhoAmIKeyDto(key.Id, key.Name, key.ExpiresAt, DtoMappings.ScopeNames(key.Scopes))));
        })
            .RequireAuthorization()
            .WithTags("Meta");

        // The installation's stable id and what this API offers, for clients that pair with it.
        app.MapGet("/api/instance", async (AppDbContext db, TimeProvider clock, CancellationToken ct) =>
        {
            var instance = await InstanceIdentity.GetAsync(db, clock, ct);
            return Results.Ok(new InstanceDto(instance.InstanceId, ApiContract.ApiVersion, [.. ApiContract.Capabilities]));
        })
            .RequireAuthorization()
            .WithTags("Meta");

        // Liveness probe — intentionally unauthenticated, returns no sensitive data.
        app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }))
            .AllowAnonymous().WithTags("Meta");

        // First-run convenience: lets a local dev UI claim the seeded bootstrap
        // key instead of copying it from the log. Deliberately narrow — answers
        // only in Development, only to loopback clients, and only until the key
        // is claimed once or the seeding process exits; 404 in every other case
        // so probes learn nothing.
        app.MapGet("/api/bootstrap-key", (
            HttpContext ctx, IHostEnvironment env, BootstrapKeyBroker broker, ILoggerFactory loggerFactory) =>
        {
            if (!env.IsDevelopment()) return Results.NotFound();
            var ip = ctx.Connection.RemoteIpAddress;
            if (ip is null || !IPAddress.IsLoopback(ip)) return Results.NotFound();

            var token = broker.Claim();
            if (token is null) return Results.NotFound();

            loggerFactory.CreateLogger("DbBootstrapper").LogWarning(
                "Bootstrap API key was claimed via /api/bootstrap-key from {Ip}; it can no longer be claimed again.", ip);
            return Results.Ok(new { apiKey = token });
        }).AllowAnonymous().ExcludeFromDescription();

        // Readiness probe — checks dependencies (DB + proxy). Unauthenticated but
        // returns only a coarse ready flag and the proxy state string.
        app.MapGet("/api/ready", async (AppDbContext db, IProxyController proxy, CancellationToken ct) =>
        {
            bool dbOk;
            try { dbOk = await db.Database.CanConnectAsync(ct); } catch { dbOk = false; }
            var status = await proxy.GetStatusAsync(ct);
            var dto = new ReadyDto(dbOk, dbOk, status.State.ToString());
            return dbOk ? Results.Ok(dto) : Results.Json(dto, statusCode: StatusCodes.Status503ServiceUnavailable);
        }).AllowAnonymous().WithTags("Meta");

        // Server-Sent Events stream of control-plane events for a live dashboard. It ends when the key or session
        // expires and at most EventStreamLifetime after it opened, and each event goes out only while the
        // credential still holds ServerRead, so a revoked key or a deactivated owner hears nothing more.
        app.MapGet("/api/events", async (IEventStream events, AppDbContext db, TimeProvider clock, HttpContext ctx) =>
        {
            var now = clock.GetUtcNow();
            var until = await CredentialCheck.ValidUntilAsync(ctx.User, Permission.ServerRead, db, now, ctx.RequestAborted);
            if (until is not { } validUntil)
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            var left = validUntil - now;
            using var expiry = new CancellationTokenSource(left < EventStreamLifetime ? left : EventStreamLifetime, clock);
            using var end = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted, expiry.Token);

            ctx.Response.Headers.ContentType = "text/event-stream";
            ctx.Response.Headers.CacheControl = "no-cache";

            // The first MoveNextAsync registers the subscriber; doing it before the headers
            // go out means a client that has the response cannot miss a later event.
            await using var subscription = events.Subscribe(end.Token).GetAsyncEnumerator(end.Token);
            try
            {
                var next = subscription.MoveNextAsync();
                await ctx.Response.Body.FlushAsync(end.Token);
                while (await next)
                {
                    if (await CredentialCheck.ValidUntilAsync(ctx.User, Permission.ServerRead, db, clock.GetUtcNow(), end.Token) is null)
                        break;
                    var json = System.Text.Json.JsonSerializer.Serialize(subscription.Current, System.Text.Json.JsonSerializerOptions.Web);
                    await ctx.Response.WriteAsync($"data: {json}\n\n", end.Token);
                    await ctx.Response.Body.FlushAsync(end.Token);
                    next = subscription.MoveNextAsync();
                }
            }
            catch (OperationCanceledException) when (end.IsCancellationRequested)
            {
                // Expired, past its lifetime, or the client left: the response ends here.
            }
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead)).WithTags("Meta");
    }

    private static void MapUsers(IEndpointRouteBuilder app)
    {
        var users = app.MapGroup("/api/users").WithTags("Users");

        users.MapGet("/", async (AppDbContext db) =>
            Results.Ok((await db.Users.AsNoTracking().ToListAsync()).Select(u => u.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.UserWrite));

        users.MapPost("/", async (
            CreateUserRequest req, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name) || string.IsNullOrWhiteSpace(req.Email))
                return Results.ValidationProblem(new Dictionary<string, string[]>
                    { ["email"] = ["Name and email are required."] });
            if (await db.Users.AnyAsync(u => u.Email == req.Email, ctx.RequestAborted))
                return Results.Conflict(new { message = "A user with that email already exists." });

            var user = new User { Name = req.Name.Trim(), Email = req.Email.Trim(), Role = req.Role };
            db.Users.Add(user);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Create User", "User", user.Email);
            return Results.Created($"/api/users/{user.Id}", user.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.UserWrite));

        users.MapPut("/{id:guid}", async (
            Guid id, UpdateUserRequest req, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var user = await db.Users.FindAsync([id], ctx.RequestAborted);
            if (user is null) return Results.NotFound();

            // Safety: never leave the system without an active admin.
            var demotingOrDisabling = user.Role == Role.Admin && (req.Role != Role.Admin || !req.IsActive);
            if (demotingOrDisabling)
            {
                var otherActiveAdmins = await db.Users.CountAsync(
                    u => u.Id != id && u.Role == Role.Admin && u.IsActive, ctx.RequestAborted);
                if (otherActiveAdmins == 0)
                    return Results.Conflict(new { message = "Cannot demote or deactivate the last active admin." });
            }

            user.Name = req.Name.Trim();
            user.Role = req.Role;
            user.IsActive = req.IsActive;
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Update User", "User", user.Email);
            return Results.Ok(user.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.UserWrite));

        return;
    }

    private static void MapAudit(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/audit", async (
            AppDbContext db, string? actor, string? action, string? targetType,
            long? beforeId, int? take) =>
        {
            var limit = Math.Clamp(take ?? 100, 1, 500);
            // Order by the autoincrement Id (monotonic with insertion, i.e. newest
            // first) — SQLite can't ORDER BY a DateTimeOffset column. `beforeId`
            // gives stable cursor pagination.
            var q = db.AuditEntries.AsNoTracking().AsQueryable();
            if (!string.IsNullOrWhiteSpace(actor)) q = q.Where(a => a.ActorName == actor);
            if (!string.IsNullOrWhiteSpace(action)) q = q.Where(a => a.Action == action);
            if (!string.IsNullOrWhiteSpace(targetType)) q = q.Where(a => a.TargetType == targetType);
            if (beforeId is { } b) q = q.Where(a => a.Id < b);

            var entries = await q.OrderByDescending(a => a.Id).Take(limit).ToListAsync();
            return Results.Ok(entries.Select(a => a.ToDto()));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.AuditRead)).WithTags("Audit");

        return;
    }
}
