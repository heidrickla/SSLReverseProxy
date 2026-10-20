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
}
