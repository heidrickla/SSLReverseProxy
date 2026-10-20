using System.Text.RegularExpressions;
using SslReverseProxy.Core.Domain;

namespace SslReverseProxy.Infrastructure.Alerts;

/// <summary>A configured target after validation. A target with a <see cref="Problem"/> is listed and never sent to.</summary>
public sealed record AlertTarget(
    string Name, string Kind, Uri? Url, string? Token, IReadOnlySet<string> Events, string? Problem)
{
    public const string Webhook = "webhook";
    public const string Ntfy = "ntfy";

    public bool Usable => Problem is null;

    public bool Wants(string type) => Usable && (Events.Count == 0 || Events.Contains(type));
}

public static partial class AlertTargets
{
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")]
    private static partial Regex NamePattern();

    // ntfy's own topic rule.
    [GeneratedRegex("^[-_A-Za-z0-9]{1,64}$")]
    private static partial Regex TopicPattern();

    public static IReadOnlyList<AlertTarget> From(AlertOptions options)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return options.Targets.Select((t, i) => Validate(t, i, seen)).ToList();
    }

    private static AlertTarget Validate(AlertTargetOptions t, int index, HashSet<string> seen)
    {
        var name = t.Name?.Trim() ?? "";
        var kind = t.Kind?.Trim().ToLowerInvariant() ?? "";
        var events = t.Events.Select(e => e.Trim()).Where(e => e.Length > 0).ToHashSet(StringComparer.Ordinal);
        Uri.TryCreate(t.Url?.Trim(), UriKind.Absolute, out var url);

        string? problem = null;
        if (!NamePattern().IsMatch(name))
        {
            problem = "Name must be 1 to 64 letters, digits, spaces, dots, hyphens or underscores.";
            name = $"target {index + 1}";
        }
        else if (!seen.Add(name))
            problem = "Another target has this name.";
        else if (kind is not (AlertTarget.Webhook or AlertTarget.Ntfy))
            problem = "Kind must be webhook or ntfy.";
        else if (url is null || url.Scheme is not ("http" or "https"))
            problem = "Url must be an absolute http or https URL.";
        else if (url.UserInfo.Length > 0)
            problem = "Url must not carry a user name or password; set Token instead.";
        else if (kind == AlertTarget.Ntfy && (url.Query.Length > 0 || !TopicPattern().IsMatch(url.Segments[^1])))
            problem = "An ntfy Url ends in the topic, as https://ntfy.sh/<topic>.";
        else if (t.Token is { Length: > 0 } token && token.Any(c => c is < '!' or > '~'))
            problem = "Token must be printable ASCII without spaces.";
        else if (events.FirstOrDefault(e => !AlertTypes.Subscribable.Contains(e)) is { } unknown)
            problem = $"Unknown event '{unknown}'; use {string.Join(", ", AlertTypes.Subscribable)}.";

        return new AlertTarget(name, kind, problem is null ? url : null,
            string.IsNullOrEmpty(t.Token) ? null : t.Token, events, problem);
    }
}
