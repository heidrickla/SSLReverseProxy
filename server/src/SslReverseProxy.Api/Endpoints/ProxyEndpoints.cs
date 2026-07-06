using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>The control service: start/stop/status, validate/preview, metrics,
/// and config snapshots/rollback for the reverse proxy.</summary>
public static class ProxyEndpoints
{
    public static IEndpointRouteBuilder MapProxyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/proxy").WithTags("Proxy Control");

        group.MapGet("/status", async (IProxyController proxy) =>
            Results.Ok(ToDto(await proxy.GetStatusAsync())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        group.MapGet("/metrics", async (IProxyController proxy, CancellationToken ct) =>
        {
            var m = await proxy.GetMetricsAsync(ct);
            return Results.Ok(new MetricsDto(m.CollectedAt, m.Available, m.TotalRequests, m.RequestsInFlight, m.Series, m.Message));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        // Preview the generated proxy config without applying it.
        group.MapGet("/config", async (IProxyController proxy, AppDbContext db, CancellationToken ct) =>
        {
            var rules = await db.Rules.AsNoTracking().ToListAsync(ct);
            return Results.Text(proxy.BuildConfigJson(rules), "application/json");
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        // Dry-run: validate the current rule set without touching the live proxy.
        group.MapPost("/validate", async (IProxyController proxy, AppDbContext db, CancellationToken ct) =>
        {
            var rules = await db.Rules.AsNoTracking().ToListAsync(ct);
            var r = await proxy.ValidateConfigurationAsync(rules, ct);
            return Results.Ok(new ProxyValidationDto(r.Valid, r.Issues, r.EngineValidated));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/start", async (
            IProxyController proxy, AppDbContext db, IAuditLog audit, IEventStream events,
            ICurrentPrincipal me, HttpContext ctx) =>
        {
            var status = await proxy.StartAsync(ctx.RequestAborted);
            if (status.State == ProxyState.Running)
            {
                var rules = await db.Rules.AsNoTracking().ToListAsync(ctx.RequestAborted);
                status = await proxy.ApplyConfigurationAsync(rules, ctx.RequestAborted);
                await CaptureSnapshotAsync(db, proxy, rules, me.Name, "start", ctx.RequestAborted);
            }
            await audit.AuditAsync(me, ctx, "Proxy Start", "Proxy", status.Engine,
                success: status.State is ProxyState.Running, details: status.Message);
            events.Publish(new ProxyEvent("proxy.start", $"state={status.State}", DateTimeOffset.UtcNow, me.Name));
            return Results.Ok(ToDto(status));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/stop", async (
            IProxyController proxy, IAuditLog audit, IEventStream events, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var status = await proxy.StopAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Proxy Stop", "Proxy", status.Engine,
                success: status.State is ProxyState.Stopped, details: status.Message);
            events.Publish(new ProxyEvent("proxy.stop", $"state={status.State}", DateTimeOffset.UtcNow, me.Name));
            return Results.Ok(ToDto(status));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/reload", async (
            IProxyController proxy, AppDbContext db, IAuditLog audit, IEventStream events,
            ICurrentPrincipal me, HttpContext ctx) =>
        {
            var rules = await db.Rules.AsNoTracking().ToListAsync(ctx.RequestAborted);
            var status = await proxy.ApplyConfigurationAsync(rules, ctx.RequestAborted);
            if (status.State == ProxyState.Running)
                await CaptureSnapshotAsync(db, proxy, rules, me.Name, "reload", ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Proxy Reload", "Proxy", status.Engine,
                success: status.State is ProxyState.Running, details: status.Message);
            events.Publish(new ProxyEvent("proxy.reload", $"rules={status.ActiveRuleCount}", DateTimeOffset.UtcNow, me.Name));
            return Results.Ok(ToDto(status));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        // Snapshots + rollback.
        group.MapGet("/snapshots", async (AppDbContext db, CancellationToken ct) =>
            Results.Ok((await db.ConfigSnapshots.AsNoTracking()
                .OrderByDescending(s => s.Id).Take(50).ToListAsync(ct)).Select(s => s.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/rollback", async (
            RollbackRequest req, IProxyController proxy, AppDbContext db, IAuditLog audit,
            IEventStream events, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var snap = await db.ConfigSnapshots.FindAsync([req.SnapshotId], ctx.RequestAborted);
            if (snap is null) return Results.NotFound(new { message = "Snapshot not found." });

            var status = await proxy.ApplyRawConfigAsync(snap.ConfigJson, ctx.RequestAborted);
            var ok = status.State == ProxyState.Running;
            await audit.AuditAsync(me, ctx, "Proxy Rollback", "Config Snapshot", snap.Id.ToString(),
                success: ok, details: status.Message);
            events.Publish(new ProxyEvent("proxy.rollback", $"snapshot={snap.Id} state={status.State}", DateTimeOffset.UtcNow, me.Name));
            return ok ? Results.Ok(ToDto(status)) : Results.Problem(status.Message ?? "Rollback failed.");
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        return app;
    }

    private static async Task CaptureSnapshotAsync(
        AppDbContext db, IProxyController proxy, IReadOnlyCollection<ProxyRule> rules,
        string actor, string note, CancellationToken ct)
    {
        db.ConfigSnapshots.Add(new ConfigSnapshot
        {
            Actor = actor,
            ConfigJson = proxy.BuildConfigJson(rules),
            RuleCount = rules.Count(r => r.Enabled),
            Note = note,
        });
        await db.SaveChangesAsync(ct);
    }

    private static ProxyStatusDto ToDto(ProxyStatus s) =>
        new(s.State.ToString(), s.Engine, s.ProcessId, s.StartedAt, s.ActiveRuleCount, s.Message);
}
