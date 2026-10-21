using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Core.Security;

/// <summary>
/// A named set of scopes offered when a key is issued. Null scopes mean everything the owner's role allows
/// when the key is issued, stored then as that list.
/// </summary>
public sealed record ApiKeyPreset(string Id, string Name, string Description, IReadOnlyList<Permission>? Scopes);

/// <summary>
/// How a key's scopes are stored, and the presets and lifetimes keys are issued with. A key's scopes are a
/// comma-separated list of permission names. Null belongs to the bootstrap key and to keys issued before
/// full access was stored as a list; those follow the owner's role until they are rotated.
/// </summary>
public static class ApiKeyScopes
{
    public const int MaxLifetimeDays = 365;
    public const int DefaultLifetimeDays = 30;
    public static readonly IReadOnlyList<int> LifetimeDays = [1, 7, 30, 90, 365];

    public static readonly IReadOnlyList<ApiKeyPreset> Presets =
    [
        new("read-only", "Read only", "Servers, rules, traffic and certificates.",
            [Permission.ServerRead, Permission.CertRead]),
        new("home-assistant", "Home Assistant", "Read status, reload the proxy and renew certificates.",
            [Permission.ServerRead, Permission.CertRead, Permission.ProxyReload, Permission.CertRenew]),
        new("rules-editor", "Rules editor", "Edit rules, preview and reload the proxy.",
            [Permission.ServerRead, Permission.RuleWrite, Permission.ProxyReload]),
        new("full", "Full access", "Everything the owner's role allows today. A later promotion does not widen it.", null),
    ];

    /// <summary>The stored form. Unknown names are dropped, so a name removed from the code grants nothing.</summary>
    public static IReadOnlySet<Permission>? Parse(string? stored)
    {
        if (stored is null) return null;
        var set = new HashSet<Permission>();
        foreach (var name in stored.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (TryName(name, out var p))
                set.Add(p);
        return set;
    }

    public static string Format(IEnumerable<Permission> scopes) =>
        string.Join(',', scopes.Distinct().Order().Select(p => p.ToString()));

    /// <summary>Names as the API takes them, or null with the first name that is not a permission.</summary>
    public static IReadOnlySet<Permission>? FromNames(IEnumerable<string> names, out string? unknown)
    {
        var set = new HashSet<Permission>();
        foreach (var name in names)
        {
            if (!TryName(name, out var p))
            {
                unknown = name;
                return null;
            }
            set.Add(p);
        }
        unknown = null;
        return set;
    }

    // Exact names only: Enum.TryParse also takes numbers, padding and comma lists.
    private static bool TryName(string? name, out Permission permission) =>
        Enum.TryParse(name, ignoreCase: false, out permission) && Enum.IsDefined(permission)
        && permission.ToString() == name;
}
