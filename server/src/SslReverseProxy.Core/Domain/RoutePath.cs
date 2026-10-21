namespace SslReverseProxy.Core.Domain;

/// <summary>Validation and normalisation of a rule's path prefix.</summary>
public static class RoutePath
{
    public const int MaxLength = 256;

    /// <summary>
    /// Returns the stored form of <paramref name="input"/>: trimmed, trailing slashes removed,
    /// null for "whole host". Only unreserved URI characters and "/" are allowed, which keeps
    /// Caddy placeholders ("{...}"), matcher wildcards, queries, fragments and percent-escapes out.
    /// </summary>
    public static bool TryNormalize(string? input, out string? prefix, out string? error)
    {
        prefix = null;
        error = null;
        var p = input?.Trim();
        if (string.IsNullOrEmpty(p)) return true;

        if (!p.StartsWith('/'))
        {
            error = "Must start with '/'.";
            return false;
        }
        p = p.TrimEnd('/');
        if (p.Length == 0) return true;
        if (p.Length > MaxLength)
        {
            error = $"Must be at most {MaxLength} characters.";
            return false;
        }
        foreach (var c in p)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '/' or '-' or '.' or '_' or '~'))
            {
                error = "Only letters, digits, '-', '.', '_', '~' and '/' are allowed.";
                return false;
            }
        }
        var segments = p.Split('/');
        if (segments.Skip(1).Any(s => s.Length == 0 || s == "." || s == ".."))
        {
            error = "Must not contain empty, '.' or '..' segments.";
            return false;
        }
        prefix = p;
        return true;
    }

    /// <summary>Key for "the same route": host and prefix, case-insensitive as Caddy matches both.</summary>
    public static string RouteKey(string domain, string? prefix) =>
        $"{domain.Trim().ToLowerInvariant()}{prefix?.ToLowerInvariant()}";

    /// <summary>
    /// Enabled rules on one host and path, or on one host with different TLS settings or sign-in callbacks.
    /// Caddy serves such a set with one rule shadowing the other, so writes, validation and apply refuse it.
    /// </summary>
    public static IEnumerable<string> Conflicts(IEnumerable<ProxyRule> rules)
    {
        var enabled = rules.Where(r => r.Enabled).ToList();
        foreach (var g in enabled.GroupBy(r => RouteKey(r.Domain, r.PathPrefix)).Where(g => g.Count() > 1))
            yield return Duplicate(g.First());
        foreach (var g in enabled.GroupBy(r => r.Domain.Trim(), StringComparer.OrdinalIgnoreCase)
                     .Where(g => g.Select(r => r.EnableTls).Distinct().Count() > 1))
            yield return MixedTls(g.Key);
        foreach (var g in enabled.GroupBy(r => r.Domain.Trim(), StringComparer.OrdinalIgnoreCase))
            if (SignInConflict(g.Key, [.. g]) is { } signIn) yield return signIn;
    }

    /// <summary>The conflict <paramref name="rule"/> would have with the other rules, or null.</summary>
    public static string? ConflictWith(ProxyRule rule, IEnumerable<ProxyRule> others)
    {
        if (!rule.Enabled) return null;
        var enabled = others.Where(o => o.Enabled && o.Id != rule.Id).ToList();
        var key = RouteKey(rule.Domain, rule.PathPrefix);
        if (enabled.Any(o => RouteKey(o.Domain, o.PathPrefix) == key)) return Duplicate(rule);
        var host = rule.Domain.Trim();
        var sameHost = enabled.Where(o => string.Equals(o.Domain.Trim(), host, StringComparison.OrdinalIgnoreCase)).ToList();
        if (sameHost.Any(o => o.EnableTls != rule.EnableTls)) return MixedTls(host);
        return SignInConflict(host, [.. sameHost, rule]);
    }

    /// <summary>
    /// A host has one callback route for Authentik or oauth2-proxy sign-in, so the host's rules that use one
    /// share it, and no rule's prefix may sit under the callback path the route takes.
    /// </summary>
    private static string? SignInConflict(string host, IReadOnlyList<ProxyRule> hostRules)
    {
        var callbacks = hostRules.Where(r => CallbackOf(r) is not null).ToList();
        if (callbacks.Count == 0) return null;
        if (callbacks.Select(r => (r.SignInProvider, r.SignInVerifierUrl?.ToLowerInvariant())).Distinct().Count() > 1)
            return $"Rules for '{host}' sign in through different Authentik or oauth2-proxy verifiers; a host has one sign-in callback.";
        var profile = CallbackOf(callbacks[0])!;
        var prefix = profile.CallbackPrefix!;
        return hostRules.FirstOrDefault(r => r.PathPrefix is { } p
                && (p.Equals(prefix, StringComparison.OrdinalIgnoreCase) || p.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase))) is { } shadowed
            ? $"Route '{host}{shadowed.PathPrefix}' is under {prefix}, which {profile.Label} sign-in on this host takes."
            : null;
    }

    private static SignInProviders.Profile? CallbackOf(ProxyRule r) =>
        r.SignInProvider is { } p && SignInProviders.Profiles.TryGetValue(p, out var profile) && profile.CallbackPrefix is not null ? profile : null;

    private static string Duplicate(ProxyRule r) => r.PathPrefix is null
        ? $"Duplicate domain '{r.Domain}' — only one whole-host rule per host is allowed."
        : $"Duplicate route '{r.Domain}{r.PathPrefix}' — only one rule per host and path is allowed.";

    private static string MixedTls(string host) =>
        $"Rules for '{host}' disagree on TLS — every rule for a host must use the same setting.";
}
