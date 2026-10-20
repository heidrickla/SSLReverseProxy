using System.Reflection;

namespace SslReverseProxy.Core.Domain;

/// <summary>
/// Caddy expands "{...}" placeholders, including <c>{env.*}</c>, in several fields this app
/// fills from rule text (the basic-auth username, path matchers, path rewrites). No rule
/// string may carry a brace. Every string property is checked, so a field added later is
/// covered without being listed here.
/// </summary>
public static class RulePlaceholders
{
    private static readonly PropertyInfo[] StringProperties = typeof(ProxyRule)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(p => p.PropertyType == typeof(string) && p.CanRead)
        .ToArray();

    public static bool HasBrace(string? value) =>
        value is not null && (value.Contains('{') || value.Contains('}'));

    /// <summary>Names of the rule's string properties that contain a brace.</summary>
    public static IEnumerable<string> PlaceholderFields(this ProxyRule rule) =>
        StringProperties.Where(p => HasBrace((string?)p.GetValue(rule))).Select(p => p.Name);
}
