using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Core.Security;

namespace SslReverseProxy.Api.Auth;

/// <summary>Authorization requirement for a single fine-grained permission.</summary>
public sealed class PermissionRequirement : IAuthorizationRequirement
{
    public Permission Permission { get; }
    public PermissionRequirement(Permission permission) => Permission = permission;
}

public sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var roleClaim = context.User.FindFirstValue(ClaimTypes.Role);
        if (Enum.TryParse<Role>(roleClaim, out var role) && Permissions.Has(role, requirement.Permission))
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

public static class AuthorizationSetup
{
    /// <summary>Register one policy per permission, each requiring authentication.</summary>
    public static AuthorizationOptions AddPermissionPolicies(this AuthorizationOptions options)
    {
        foreach (var permission in Enum.GetValues<Permission>())
        {
            options.AddPolicy(PolicyName(permission), policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(new PermissionRequirement(permission));
            });
        }
        return options;
    }

    public static string PolicyName(Permission permission) => $"perm:{permission}";
}

/// <summary>Reads the authenticated principal off the current HttpContext.</summary>
public sealed class CurrentPrincipal : ICurrentPrincipal
{
    private readonly ClaimsPrincipal? _user;

    public CurrentPrincipal(IHttpContextAccessor accessor) => _user = accessor.HttpContext?.User;

    public bool IsAuthenticated => _user?.Identity?.IsAuthenticated ?? false;

    public Guid? UserId =>
        Guid.TryParse(_user?.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    public string Name => _user?.FindFirstValue(ClaimTypes.Name) ?? "anonymous";

    public Role Role =>
        Enum.TryParse<Role>(_user?.FindFirstValue(ClaimTypes.Role), out var r) ? r : Role.Viewer;

    public bool Has(Permission permission) => IsAuthenticated && Permissions.Has(Role, permission);
}
