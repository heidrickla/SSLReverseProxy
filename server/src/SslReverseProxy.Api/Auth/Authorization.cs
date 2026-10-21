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
        if (PrincipalPermissions.Of(context.User).Contains(requirement.Permission))
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

/// <summary>
/// Refuses a principal that holds less than its role: a key narrower than its owner's role, including a key
/// issued before a promotion. Used where a principal could reach the whole role, as a passkey does.
/// </summary>
public sealed class WholeRoleRequirement : IAuthorizationRequirement { }

public sealed class WholeRoleAuthorizationHandler : AuthorizationHandler<WholeRoleRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, WholeRoleRequirement requirement)
    {
        if (PrincipalPermissions.HoldsWholeRole(context.User)) context.Succeed(requirement);
        return Task.CompletedTask;
    }
}

/// <summary>The one place a principal's permissions are worked out from its claims.</summary>
public static class PrincipalPermissions
{
    public static IReadOnlySet<Permission> Of(ClaimsPrincipal? user)
    {
        if (user?.Identity?.IsAuthenticated != true
            || !Enum.TryParse<Role>(user.FindFirstValue(ClaimTypes.Role), out var role) || !Enum.IsDefined(role))
            return new HashSet<Permission>();
        var scopes = user.FindFirst(ApiKeyDefaults.ScopesClaim) is { } claim ? ApiKeyScopes.Parse(claim.Value) : null;
        return Permissions.Effective(role, scopes);
    }

    /// <summary>True when the principal holds every permission of its current role.</summary>
    public static bool HoldsWholeRole(ClaimsPrincipal? user) =>
        Enum.TryParse<Role>(user?.FindFirstValue(ClaimTypes.Role), out var role) && Enum.IsDefined(role)
        && Of(user).SetEquals(Permissions.For(role));
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

    /// <summary>Signed in with a session or with a key holding its owner's whole current role.</summary>
    public const string WholeRole = "whole-role";

    public static AuthorizationOptions AddWholeRolePolicy(this AuthorizationOptions options)
    {
        options.AddPolicy(WholeRole, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.Requirements.Add(new WholeRoleRequirement());
        });
        return options;
    }
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

    public Guid? ApiKeyId =>
        Guid.TryParse(_user?.FindFirstValue(ApiKeyDefaults.KeyClaim), out var id) ? id : null;

    public bool HoldsWholeRole => PrincipalPermissions.HoldsWholeRole(_user);

    public IReadOnlySet<Permission> Permissions => PrincipalPermissions.Of(_user);

    public bool Has(Permission permission) => Permissions.Contains(permission);
}
