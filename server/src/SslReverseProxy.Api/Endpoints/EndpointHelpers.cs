using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Api.Endpoints;

public static class EndpointHelpers
{
    public static Task AuditAsync(
        this IAuditLog audit,
        ICurrentPrincipal principal,
        HttpContext ctx,
        string action,
        string targetType,
        string targetName,
        bool success = true,
        string? details = null)
    {
        return audit.WriteAsync(new AuditEntry
        {
            ActorName = principal.Name,
            ActorUserId = principal.UserId,
            Action = action,
            TargetType = targetType,
            TargetName = targetName,
            SourceIp = ctx.Connection.RemoteIpAddress?.ToString(),
            Success = success,
            Details = details,
        }, ctx.RequestAborted);
    }
}
