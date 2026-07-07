using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Endpoints;

public static class ServerEndpoints
{
    public static IEndpointRouteBuilder MapServerEndpoints(this IEndpointRouteBuilder app)
    {
        var servers = app.MapGroup("/api/servers").WithTags("Servers");

        servers.MapGet("/", async (AppDbContext db) =>
            Results.Ok((await db.Servers.AsNoTracking().Include(s => s.Rules).ToListAsync())
                .Select(s => s.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        servers.MapPost("/", async (
            CreateServerRequest req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var domainCheck = validator.ValidateDomain(req.Host);
            if (!domainCheck.Ok && !System.Net.IPAddress.TryParse(req.Host, out _))
                return Results.ValidationProblem(new Dictionary<string, string[]>
                    { ["host"] = [domainCheck.Reason ?? "Invalid host."] });

            var server = new ProxyServer
            {
                Name = req.Name.Trim(),
                Host = req.Host.Trim(),
                Os = req.Os == "windows" ? "windows" : "linux",
            };
            db.Servers.Add(server);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Create Server", "Server", server.Name);
            return Results.Created($"/api/servers/{server.Id}", server.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerWrite));

        servers.MapDelete("/{id:guid}", async (
            Guid id, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var server = await db.Servers.FindAsync([id], ctx.RequestAborted);
            if (server is null) return Results.NotFound();
            db.Servers.Remove(server);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Delete Server", "Server", server.Name);
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerWrite));

        // Rules nested under a server.
        servers.MapGet("/{serverId:guid}/rules", async (Guid serverId, AppDbContext db) =>
            Results.Ok((await db.Rules.AsNoTracking().Where(r => r.ServerId == serverId).ToListAsync())
                .Select(r => r.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        servers.MapPost("/{serverId:guid}/rules", async (
            Guid serverId, CreateRuleRequest req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            if (!await db.Servers.AnyAsync(s => s.Id == serverId, ctx.RequestAborted))
                return Results.NotFound();

            var problem = ValidateRule(req.Domain, req.UpstreamUrl, validator, req.AllowedCidrs, req.DeniedCidrs,
                req.RateLimitPerMinute, req.BasicAuthUsername, req.BasicAuthPassword, isCreate: true);
            if (problem is not null) return problem;

            var rule = new ProxyRule
            {
                ServerId = serverId,
                Domain = req.Domain.Trim(),
                UpstreamUrl = req.UpstreamUrl.Trim(),
                EnableTls = req.EnableTls,
                Enabled = req.Enabled,
                AllowedCidrs = NormalizeCidrs(req.AllowedCidrs),
                DeniedCidrs = NormalizeCidrs(req.DeniedCidrs),
                RateLimitPerMinute = req.RateLimitPerMinute is > 0 ? req.RateLimitPerMinute : null,
                BasicAuthUsername = string.IsNullOrWhiteSpace(req.BasicAuthUsername) ? null : req.BasicAuthUsername.Trim(),
                BasicAuthPasswordHash = HashBasicAuth(req.BasicAuthUsername, req.BasicAuthPassword),
            };
            db.Rules.Add(rule);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Create Proxy Rule", "Proxy Rule", rule.Domain);
            return Results.Created($"/api/servers/{serverId}/rules/{rule.Id}", rule.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        servers.MapPut("/{serverId:guid}/rules/{ruleId:guid}", async (
            Guid serverId, Guid ruleId, UpdateRuleRequest req, AppDbContext db, ProxyTargetValidator validator,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ctx.RequestAborted);
            if (rule is null) return Results.NotFound();

            var problem = ValidateRule(req.Domain, req.UpstreamUrl, validator, req.AllowedCidrs, req.DeniedCidrs,
                req.RateLimitPerMinute, req.BasicAuthUsername, req.BasicAuthPassword, isCreate: false);
            if (problem is not null) return problem;

            rule.Domain = req.Domain.Trim();
            rule.UpstreamUrl = req.UpstreamUrl.Trim();
            rule.EnableTls = req.EnableTls;
            rule.Enabled = req.Enabled;
            rule.AllowedCidrs = NormalizeCidrs(req.AllowedCidrs);
            rule.DeniedCidrs = NormalizeCidrs(req.DeniedCidrs);
            rule.RateLimitPerMinute = req.RateLimitPerMinute is > 0 ? req.RateLimitPerMinute : null;
            rule.BasicAuthUsername = string.IsNullOrWhiteSpace(req.BasicAuthUsername) ? null : req.BasicAuthUsername.Trim();
            // Only re-hash when a new password is supplied; blank username clears auth.
            if (string.IsNullOrWhiteSpace(req.BasicAuthUsername))
                rule.BasicAuthPasswordHash = null;
            else if (!string.IsNullOrEmpty(req.BasicAuthPassword))
                rule.BasicAuthPasswordHash = HashBasicAuth(req.BasicAuthUsername, req.BasicAuthPassword);
            rule.UpdatedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Update Proxy Rule", "Proxy Rule", rule.Domain);
            return Results.Ok(rule.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        // Quick enable/disable toggle without a full update.
        servers.MapPatch("/{serverId:guid}/rules/{ruleId:guid}/enabled", async (
            Guid serverId, Guid ruleId, ToggleRuleRequest req, AppDbContext db,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ctx.RequestAborted);
            if (rule is null) return Results.NotFound();
            rule.Enabled = req.Enabled;
            rule.UpdatedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, req.Enabled ? "Enable Proxy Rule" : "Disable Proxy Rule", "Proxy Rule", rule.Domain);
            return Results.Ok(rule.ToDto());
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        // Probe the rule's upstream for reachability (SSRF policy re-applied).
        servers.MapGet("/{serverId:guid}/rules/{ruleId:guid}/health", async (
            Guid serverId, Guid ruleId, AppDbContext db, IUpstreamHealthChecker checker, CancellationToken ct) =>
        {
            var rule = await db.Rules.AsNoTracking().FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ct);
            if (rule is null) return Results.NotFound();
            var h = await checker.CheckAsync(rule.UpstreamUrl, ct);
            return Results.Ok(new UpstreamHealthDto(h.Reachable, h.StatusCode, h.LatencyMs, h.Error));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        servers.MapDelete("/{serverId:guid}/rules/{ruleId:guid}", async (
            Guid serverId, Guid ruleId, AppDbContext db, IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rule = await db.Rules.FirstOrDefaultAsync(r => r.Id == ruleId && r.ServerId == serverId, ctx.RequestAborted);
            if (rule is null) return Results.NotFound();
            db.Rules.Remove(rule);
            await db.SaveChangesAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Delete Proxy Rule", "Proxy Rule", rule.Domain);
            return Results.NoContent();
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.RuleWrite));

        return app;
    }

    private static IResult? ValidateRule(
        string domain, string upstream, ProxyTargetValidator validator,
        string? allowedCidrs, string? deniedCidrs,
        int? rateLimitPerMinute, string? basicAuthUsername, string? basicAuthPassword, bool isCreate)
    {
        var errors = new Dictionary<string, string[]>();
        var d = validator.ValidateDomain(domain);
        if (!d.Ok) errors["domain"] = [d.Reason!];
        var u = validator.ValidateUpstream(upstream);
        if (!u.Ok) errors["upstreamUrl"] = [u.Reason!];
        if (InvalidCidr(allowedCidrs) is { } a) errors["allowedCidrs"] = [a];
        if (InvalidCidr(deniedCidrs) is { } dn) errors["deniedCidrs"] = [dn];
        if (rateLimitPerMinute is < 1 or > 100000)
            errors["rateLimitPerMinute"] = ["Rate limit must be between 1 and 100000 requests/minute."];
        // On create, a basic-auth username requires a password (nothing to keep).
        if (isCreate && !string.IsNullOrWhiteSpace(basicAuthUsername) && string.IsNullOrEmpty(basicAuthPassword))
            errors["basicAuthPassword"] = ["A password is required when a basic-auth username is set."];
        return errors.Count > 0 ? Results.ValidationProblem(errors) : null;
    }

    // Returns an error message if any entry is not a valid IP or CIDR, else null.
    private static string? InvalidCidr(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        foreach (var entry in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var slash = entry.IndexOf('/');
            var addr = slash >= 0 ? entry[..slash] : entry;
            if (!System.Net.IPAddress.TryParse(addr, out _))
                return $"'{entry}' is not a valid IP or CIDR range.";
            if (slash >= 0 && (!int.TryParse(entry[(slash + 1)..], out var bits) || bits < 0 || bits > 128))
                return $"'{entry}' has an invalid CIDR prefix length.";
        }
        return null;
    }

    private static string? NormalizeCidrs(string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv)) return null;
        var parts = csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 0 ? null : string.Join(",", parts);
    }

    // Hash the basic-auth password with bcrypt. Returns null when no auth is set.
    private static string? HashBasicAuth(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password)) return null;
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
}
