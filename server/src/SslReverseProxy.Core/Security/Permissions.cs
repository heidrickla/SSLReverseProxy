using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Core.Security;

/// <summary>
/// Authoritative role → permission mapping enforced server-side on every
/// request. This is the real authorization boundary (unlike the client's
/// UI-gating). Deny by default: a role only has the permissions listed here.
/// </summary>
public static class Permissions
{
    private static readonly IReadOnlyDictionary<Role, HashSet<Permission>> Map =
        new Dictionary<Role, HashSet<Permission>>
        {
            [Role.Viewer] = new()
            {
                Permission.ServerRead,
                Permission.CertRead,
                Permission.AuditRead,
            },
            [Role.Editor] = new()
            {
                Permission.ProxyControl,
                Permission.ProxyReload,
                Permission.ServerRead,
                Permission.ServerWrite,
                Permission.RuleWrite,
                Permission.CertRead,
                Permission.CertWrite,
                Permission.CertRenew,
                Permission.AuditRead,
                Permission.RecentRequestsRead,
            },
            [Role.Admin] = new(Enum.GetValues<Permission>()), // all permissions
        };

    public static bool Has(Role role, Permission permission) =>
        Map.TryGetValue(role, out var set) && set.Contains(permission);

    public static IReadOnlyCollection<Permission> For(Role role) =>
        Map.TryGetValue(role, out var set) ? set : Array.Empty<Permission>();

    /// <summary>
    /// What a principal may do: its role's permissions, narrowed to an API key's scopes when the key has
    /// them. The role is the owner's current one, so a demotion narrows every key at once.
    /// </summary>
    public static IReadOnlySet<Permission> Effective(Role role, IReadOnlySet<Permission>? scopes)
    {
        var granted = new HashSet<Permission>(For(role));
        if (scopes is not null) granted.IntersectWith(scopes);
        return granted;
    }
}
