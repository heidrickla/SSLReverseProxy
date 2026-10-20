using SslReverseProxy.Api.Alerts;
using SslReverseProxy.Api.Auth;
using SslReverseProxy.Api.Contracts;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Api.Endpoints;

/// <summary>Alert targets come from configuration (<c>Alerts:Targets</c>); these list them and send test alerts.</summary>
public static class AlertEndpoints
{
    public static IEndpointRouteBuilder MapAlertEndpoints(this IEndpointRouteBuilder app)
    {
        var alerts = app.MapGroup("/api/alerts").WithTags("Alerts")
            .RequireAuthorization(AuthorizationSetup.PolicyName(Permission.AlertManage));

        alerts.MapGet("/", (AlertDispatcher dispatcher) => Results.Ok(new AlertsDto(
            dispatcher.Targets.Select(t => new AlertTargetDto(
                t.Name, t.Kind, t.Events.Order(StringComparer.Ordinal).ToList(), t.Problem)).ToList(),
            AlertTypes.Subscribable)));

        alerts.MapPost("/test", async (
            AlertTestRequest? request, AlertDispatcher dispatcher, TimeProvider clock,
            IAuditLog audit, ICurrentPrincipal me, HttpContext ctx) =>
        {
            var name = request?.Target?.Trim();
            var targets = string.IsNullOrEmpty(name)
                ? dispatcher.Targets.Where(t => t.Usable).ToList()
                : dispatcher.Targets.Where(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase)).ToList();
            if (targets.Count == 0)
                return string.IsNullOrEmpty(name)
                    ? Results.Conflict(new { message = "No usable alert target is configured." })
                    : Results.NotFound(new { message = $"No alert target is named '{name}'." });

            var results = await dispatcher.TestAsync(targets, me.Name, clock.GetUtcNow(), ctx.RequestAborted);
            foreach (var r in results)
                await audit.AuditAsync(me, ctx, "Test Alert", "AlertTarget", r.Target, success: r.Delivered,
                    details: r.Delivered ? $"HTTP {r.Status}" : r.Error);
            return Results.Ok(results.Select(r => new AlertDeliveryDto(r.Target, r.Delivered, r.Status, r.Error, r.Attempts)));
        });

        return app;
    }
}
