using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;
using SslReverseProxy.Infrastructure.Proxy;
using SslReverseProxy.Infrastructure.Security;

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

        // The last 24 hours of stored traffic samples, for the dashboard.
        group.MapGet("/traffic", async (
            AppDbContext db, IProxyController proxy, TimeProvider clock,
            IOptions<ProxyOptions> options, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var since = (now - TrafficSummary.Window).ToUnixTimeSeconds();
            var samples = await db.TrafficSamples.AsNoTracking().Where(s => s.At > since).ToListAsync(ct);
            var interval = Math.Max(0, options.Value.TrafficSampleSeconds);
            // In-flight is shown while the newest sample is under two intervals old.
            var summary = TrafficSummary.Compute(samples, now, TimeSpan.FromSeconds(Math.Max(interval, 1) * 2 + 5));
            var running = (await proxy.GetStatusAsync(ct)).State == ProxyState.Running;
            return Results.Ok(summary.ToDto(interval, running));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ServerRead));

        // Preview the generated proxy config without applying it.
        group.MapGet("/config", async (IProxyController proxy, AppDbContext db, CancellationToken ct) =>
        {
            var plan = await db.LoadProxyPlanAsync(ct);
            try
            {
                return Results.Text(proxy.BuildConfigJson(plan), "application/json");
            }
            catch (InvalidOperationException ex)
            {
                return Results.Problem(title: "Config cannot be built", detail: ex.Message, statusCode: StatusCodes.Status409Conflict);
            }
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyReload));

        // What a Reload would change: Caddy's running config against the config built from the rows.
        group.MapGet("/preview", async (
            IProxyController proxy, ProxyChanges changes, AppDbContext db, SecretRedactor redactor, CancellationToken ct) =>
        {
            using var change = await changes.EnterAsync(ct);
            var plan = await db.LoadProxyPlanAsync(ct);
            string next;
            try { next = proxy.BuildConfigJson(plan); }
            catch (InvalidOperationException ex)
            {
                return Results.Problem(title: "Config cannot be built", detail: ex.Message, statusCode: StatusCodes.Status409Conflict);
            }
            return Results.Ok(ToDto(ConfigDiff.Compare(await proxy.GetRunningConfigJsonAsync(ct), next, redactor)));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyReload));

        // Dry-run: validate the current rule set without touching the live proxy.
        group.MapPost("/validate", async (IProxyController proxy, AppDbContext db, CancellationToken ct) =>
        {
            var r = await proxy.ValidateConfigurationAsync(await db.LoadProxyPlanAsync(ct), ct);
            return Results.Ok(new ProxyValidationDto(r.Valid, r.Issues, r.EngineValidated));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyReload));

        group.MapPost("/start", async (
            IProxyController proxy, ProxyChanges changes, AppDbContext db, IAuditLog audit, IEventStream events,
            ICertificateChecks certificates, ICurrentPrincipal me, HttpContext ctx) =>
        {
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            var status = await change.StartAsync(ctx.RequestAborted);
            if (status.State == ProxyState.Running)
            {
                var plan = await db.LoadProxyPlanAsync(ctx.RequestAborted);
                status = await change.ApplyAsync(plan, ctx.RequestAborted);
                await CaptureSnapshotAsync(db, proxy, plan, me.Name, "start", ctx.RequestAborted);
                certificates.RequestCheck();
            }
            await audit.AuditAsync(me, ctx, "Proxy Start", "Proxy", status.Engine,
                success: status.State is ProxyState.Running, details: status.Message);
            events.Publish(new ProxyEvent("proxy.start", $"state={status.State}", DateTimeOffset.UtcNow, me.Name));
            return Results.Ok(ToDto(status));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/stop", async (
            ProxyChanges changes, IAuditLog audit, IEventStream events, ICurrentPrincipal me, HttpContext ctx) =>
        {
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            var status = await change.StopAsync(ctx.RequestAborted);
            await audit.AuditAsync(me, ctx, "Proxy Stop", "Proxy", status.Engine,
                success: status.State is ProxyState.Stopped, details: status.Message);
            events.Publish(new ProxyEvent("proxy.stop", $"state={status.State}", DateTimeOffset.UtcNow, me.Name));
            return Results.Ok(ToDto(status));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/reload", async (
            ReloadRequest? req, IProxyController proxy, ProxyChanges changes, AppDbContext db, IAuditLog audit, IEventStream events,
            ICertificateChecks certificates, ICurrentPrincipal me, HttpContext ctx) =>
        {
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            var plan = await db.LoadProxyPlanAsync(ctx.RequestAborted);
            if (req?.PreviewDigest is { } digest)
            {
                string? next;
                try { next = proxy.BuildConfigJson(plan); }
                catch (InvalidOperationException) { next = null; }
                if (next is null || ConfigDiff.Digest(await proxy.GetRunningConfigJsonAsync(ctx.RequestAborted), next) != digest)
                    return StalePreview();
            }
            var status = await change.ApplyAsync(plan, ctx.RequestAborted);
            if (status.State == ProxyState.Running)
            {
                await CaptureSnapshotAsync(db, proxy, plan, me.Name, "reload", ctx.RequestAborted);
                certificates.RequestCheck();
            }
            await audit.AuditAsync(me, ctx, "Proxy Reload", "Proxy", status.Engine,
                success: status.State is ProxyState.Running, details: status.Message);
            events.Publish(new ProxyEvent("proxy.reload", $"rules={status.ActiveRuleCount}", DateTimeOffset.UtcNow, me.Name));
            return Results.Ok(ToDto(status));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyReload));

        // Snapshots + rollback.
        group.MapGet("/snapshots", async (AppDbContext db, CancellationToken ct) =>
            Results.Ok((await db.ConfigSnapshots.AsNoTracking()
                .OrderByDescending(s => s.Id).Take(50).ToListAsync(ct)).Select(s => s.ToDto())))
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        // What a rollback to this snapshot would change.
        group.MapGet("/snapshots/{id:long}/preview", async (
            long id, IProxyController proxy, ProxyChanges changes, AppDbContext db, SecretRedactor redactor, CancellationToken ct) =>
        {
            var snap = await db.ConfigSnapshots.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct);
            if (snap is null) return Results.NotFound(new { message = "Snapshot not found." });
            using var change = await changes.EnterAsync(ct);
            return Results.Ok(ToDto(ConfigDiff.Compare(await proxy.GetRunningConfigJsonAsync(ct), snap.ConfigJson, redactor)));
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        group.MapPost("/rollback", async (
            RollbackRequest req, IProxyController proxy, ProxyChanges changes, AppDbContext db, IAuditLog audit,
            IEventStream events, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var snap = await db.ConfigSnapshots.FindAsync([req.SnapshotId], ctx.RequestAborted);
            if (snap is null) return Results.NotFound(new { message = "Snapshot not found." });

            // The push and the cleared marks land together, so no renewal or cleanup push falls between them.
            using var change = await changes.EnterAsync(ctx.RequestAborted);
            if (req.PreviewDigest is { } digest
                && ConfigDiff.Digest(await proxy.GetRunningConfigJsonAsync(ctx.RequestAborted), snap.ConfigJson) != digest)
                return StalePreview();
            var status = await change.ApplyRawAsync(snap.ConfigJson, ctx.RequestAborted);
            var ok = status.State == ProxyState.Running;
            if (ok)
            {
                // Snapshots hold no renewal policy, so a renewal under way stops with the rollback.
                var now = DateTimeOffset.UtcNow;
                var pending = await db.Certificates.Where(c => c.RenewFromSerial != null).ToListAsync(ctx.RequestAborted);
                foreach (var cert in pending)
                {
                    cert.RenewFromSerial = null;
                    events.Publish(new ProxyEvent("certificate.renew_cancelled",
                        $"Renewal of {cert.Domain} was cancelled by a rollback", now, me.Name));
                }
                await db.SaveChangesAsync(ctx.RequestAborted);
            }
            await audit.AuditAsync(me, ctx, "Proxy Rollback", "Config Snapshot", snap.Id.ToString(),
                success: ok, details: status.Message);
            events.Publish(new ProxyEvent("proxy.rollback", $"snapshot={snap.Id} state={status.State}", DateTimeOffset.UtcNow, me.Name));
            return ok ? Results.Ok(ToDto(status)) : Results.Problem(status.Message ?? "Rollback failed.");
        }).RequireAuthorization(AuthorizationSetup.PolicyName(Permission.ProxyControl));

        return app;
    }

    private static async Task CaptureSnapshotAsync(
        AppDbContext db, IProxyController proxy, ProxyPlan plan,
        string actor, string note, CancellationToken ct)
    {
        db.ConfigSnapshots.Add(new ConfigSnapshot
        {
            Actor = actor,
            // A rollback must not restart a forced renewal the monitor has since ended.
            ConfigJson = proxy.BuildConfigJson(plan.WithoutPendingRenewals()),
            RuleCount = plan.Rules.Count(r => r.Enabled),
            Note = note,
        });
        await db.SaveChangesAsync(ct);
    }

    private static IResult StalePreview() => Results.Problem(
        title: "The preview is out of date",
        detail: "Caddy's config or the rules changed after the preview. Preview again before applying.",
        statusCode: StatusCodes.Status409Conflict);

    private static ProxyPreviewDto ToDto(ConfigPreview p) => new(
        p.RunningAvailable,
        p.RunningAvailable ? null : "Caddy is not running or did not answer, so there is no running config to compare.",
        p.Changes.Select(c => new ConfigChangeDto(c.Group, c.Kind, c.Path, c.Before, c.After)).ToList(),
        p.Truncated,
        p.Digest);

    private static ProxyStatusDto ToDto(ProxyStatus s) =>
        new(s.State.ToString(), s.Engine, s.ProcessId, s.StartedAt, s.ActiveRuleCount, s.Message);
}
