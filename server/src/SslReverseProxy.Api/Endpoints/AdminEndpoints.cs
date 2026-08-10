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
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        MapMeta(app);
        MapUsers(app);
        MapApiKeys(app);
        MapCertificates(app);
        MapAudit(app);
        return app;
    }

    private static void MapMeta(IEndpointRouteBuilder app)
    {
        app.MapGet("/api/whoami", (ICurrentPrincipal me) =>
            Results.Ok(new WhoAmIDto(
                me.UserId, me.Name, me.Role.ToString(),
                Permissions.For(me.Role).Select(p => p.ToString()).ToArray())))
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
        }).AllowAnonymous().WithTags("Meta");

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

        // Server-Sent Events stream of control-plane events for a live dashboard.
        app.MapGet("/api/events", async (IEventStream events, HttpContext ctx) =>
        {
            ctx.Response.Headers.ContentType = "text/event-stream";
            ctx.Response.Headers.CacheControl = "no-cache";
            await foreach (var evt in events.Subscribe(ctx.RequestAborted))
            {
                var json = System.Text.Json.JsonSerializer.Serialize(evt);
                await ctx.Response.WriteAsync($"data: {json}\n\n", ctx.RequestAborted);
                await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
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

    private static void MapApiKeys(IEndpointRouteBuilder app)
    {
        var keys = app.MapGroup("/api/apikeys").WithTags("API Keys");

        keys.MapGet("/", async (AppDbContext db, Guid? userId) =>
        {
            var q = db.ApiKeys.AsNoTracking();
            if (userId is { } uid) q = q.Where(k => k.UserId == uid);
            return Results.Ok((await q.ToListAsync()).Select(k => k.ToDto()));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ApiKeyManage));

        keys.MapPost("/", async (
            CreateApiKeyRequest req, AppDbContext db, IApiKeyService svc,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            if (!await db.Users.AnyAsync(u => u.Id == req.UserId, ctx.RequestAborted))
                return Results.NotFound(new { message = "User not found." });

            var lifetime = req.LifetimeDays is > 0 ? TimeSpan.FromDays(req.LifetimeDays.Value) : (TimeSpan?)null;
            var issued = await svc.CreateAsync(req.UserId, req.Name.Trim(), lifetime, ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Create API Key", "API Key", issued.Record.Name);
            // The plaintext token is returned here once and never persisted or shown again.
            return Results.Created($"/api/apikeys/{issued.Record.Id}",
                new IssuedApiKeyDto(issued.Record.Id, issued.Record.Name, issued.PlaintextToken, issued.Record.ExpiresAt));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ApiKeyManage));

        keys.MapPost("/{id:guid}/revoke", async (
            Guid id, IApiKeyService svc, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            await svc.RevokeAsync(id, ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Revoke API Key", "API Key", id.ToString());
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ApiKeyManage));

        // Rotate: issue a fresh key for the same owner/name, then revoke the old one.
        keys.MapPost("/{id:guid}/rotate", async (
            Guid id, AppDbContext db, IApiKeyService svc, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var old = await db.ApiKeys.AsNoTracking().FirstOrDefaultAsync(k => k.Id == id, ctx.RequestAborted);
            if (old is null) return Results.NotFound();

            var lifetime = old.ExpiresAt is { } exp ? exp - old.CreatedAt : (TimeSpan?)null;
            var issued = await svc.CreateAsync(old.UserId, old.Name, lifetime, ctx.RequestAborted);
            await svc.RevokeAsync(id, ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Rotate API Key", "API Key", old.Name);
            return Results.Ok(new IssuedApiKeyDto(issued.Record.Id, issued.Record.Name, issued.PlaintextToken, issued.Record.ExpiresAt));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ApiKeyManage));

        return;
    }

    private static void MapCertificates(IEndpointRouteBuilder app)
    {
        var certs = app.MapGroup("/api/certificates").WithTags("Certificates");

        certs.MapGet("/", async (AppDbContext db) =>
            Results.Ok((await db.Certificates.AsNoTracking().ToListAsync()).Select(c => c.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertRead));

        // Certificates are issued/renewed by the proxy engine (Caddy ACME). This
        // registers a domain to be managed; issuance happens out-of-band.
        certs.MapPost("/", async (
            CertificateDto req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var d = validator.ValidateDomain(req.Domain);
            if (!d.Ok) return Results.ValidationProblem(new Dictionary<string, string[]> { ["domain"] = [d.Reason!] });

            var cert = new Certificate
            {
                Domain = req.Domain.Trim(),
                Issuer = "ACME (managed by proxy)",
                Status = CertificateStatus.Issuing,
                Managed = true,
            };
            db.Certificates.Add(cert);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Register Certificate", "Certificate", cert.Domain);
            return Results.Created($"/api/certificates/{cert.Id}", cert.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

        // Real status derived from the cert's dates (not just the stored flag).
        certs.MapGet("/{id:guid}/status", async (Guid id, AppDbContext db, TimeProvider clock, CancellationToken ct) =>
        {
            var cert = await db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
            if (cert is null) return Results.NotFound();
            var health = CertificateStatusEvaluator.Evaluate(cert, clock.GetUtcNow());
            return Results.Ok(new CertStatusDto(cert.Id, cert.Domain, health.Status.ToString(), health.DaysRemaining, cert.ExpiresAt));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertRead));

        // Force renewal: mark issuing and reload the proxy so Caddy (re)obtains it.
        certs.MapPost("/{id:guid}/renew", async (
            Guid id, AppDbContext db, IProxyController proxy, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var cert = await db.Certificates.FirstOrDefaultAsync(c => c.Id == id, ctx.RequestAborted);
            if (cert is null) return Results.NotFound();
            cert.Status = CertificateStatus.Issuing;
            await db.SaveChangesAsync(ctx.RequestAborted);

            var rules = await db.Rules.AsNoTracking().ToListAsync(ctx.RequestAborted);
            var status = await proxy.ApplyConfigurationAsync(rules, ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Renew Certificate", "Certificate", cert.Domain,
                success: status.State is ProxyState.Running, details: status.Message);
            return Results.Accepted($"/api/certificates/{cert.Id}/status", cert.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

        certs.MapDelete("/{id:guid}", async (
            Guid id, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var cert = await db.Certificates.FindAsync([id], ctx.RequestAborted);
            if (cert is null) return Results.NotFound();
            db.Certificates.Remove(cert);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Delete Certificate", "Certificate", cert.Domain);
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.CertWrite));

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
