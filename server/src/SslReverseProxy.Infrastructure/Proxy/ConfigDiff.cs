using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>One difference between Caddy's running config and the config a push would load.</summary>
/// <param name="Group">The route (host and path prefix, then the server), the certificate policy, or the config section.</param>
/// <param name="Kind">added, removed or changed.</param>
/// <param name="Path">JSON Pointer inside the group; empty for the whole group.</param>
public sealed record ConfigChange(string Group, string Kind, string Path, string? Before, string? After);

public sealed record ConfigPreview(bool RunningAvailable, IReadOnlyList<ConfigChange> Changes, bool Truncated, string Digest);

/// <summary>
/// Compares two Caddy configs. Routes are matched by host and path prefix, certificate policies by subject and
/// handlers by name, so an inserted route or handler shows as one addition instead of shifting every index.
/// Credential fields are compared but never shown, and every shown value passes the secret redactor.
/// </summary>
public static class ConfigDiff
{
    public const int MaxChanges = 500;
    public const int MaxValueLength = 2000;
    public const string Masked = "[masked]";

    private static readonly HashSet<string> CredentialFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "api_token", "token", "secret", "client_secret", "shared_secret",
    };

    public static ConfigPreview Compare(string? running, string next, SecretRedactor redactor)
    {
        var digest = Digest(running, next);
        if (running is null) return new ConfigPreview(false, [], false, digest);

        var changes = new List<ConfigChange>();
        var truncated = !Walk(Normalise(Parse(running), null), Normalise(Parse(next), null), [], changes, redactor);
        return new ConfigPreview(true, changes, truncated, digest);
    }

    /// <summary>Names the exact pair compared, so a push can refuse when either side moved after the preview.</summary>
    public static string Digest(string? running, string next)
    {
        var framed = $"{(running is null ? -1 : running.Length)}:{running}\n{next}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(framed)));
    }

    private static JsonNode? Parse(string json) =>
        JsonNode.Parse(json) ?? throw new InvalidOperationException("Config is not JSON.");

    // Arrays whose order carries no meaning for the reader become objects keyed by what identifies each entry.
    private static JsonNode? Normalise(JsonNode? node, string? property)
    {
        switch (node)
        {
            case JsonObject obj:
                var copy = new JsonObject();
                foreach (var (key, value) in obj) copy[key] = Normalise(value, key);
                return copy;
            case JsonArray arr when arr.Count > 0 && arr.All(e => e is JsonObject) && KeyFor(property, arr) is { } key:
                var keyed = new JsonObject();
                var seen = new Dictionary<string, int>(StringComparer.Ordinal);
                for (var i = 0; i < arr.Count; i++)
                {
                    var name = key((JsonObject)arr[i]!, i);
                    seen[name] = seen.GetValueOrDefault(name) + 1;
                    keyed[seen[name] == 1 ? name : $"{name} #{seen[name]}"] = Normalise(arr[i], null);
                }
                return keyed;
            case JsonArray { Count: 0 } when property is "routes" or "policies" or "handle":
                return new JsonObject();
            case JsonArray arr:
                return new JsonArray(arr.Select(e => Normalise(e, null)).ToArray());
            default:
                return node?.DeepClone();
        }
    }

    private static Func<JsonObject, int, string>? KeyFor(string? property, JsonArray arr)
    {
        if (property == "routes") return RouteKey;
        if (property == "policies" && arr.All(e => e!["subjects"] is JsonArray || e!["subjects"] is null))
            return (p, _) => p["subjects"] is JsonArray s && s.Count > 0 ? string.Join(",", s.Select(x => x?.ToString())) : "(default)";
        if (arr.All(e => e!["handler"] is JsonValue v && v.TryGetValue<string>(out _)))
            return (h, _) => (string)h["handler"]!;
        return null;
    }

    private static string RouteKey(JsonObject route, int index)
    {
        if (route["match"] is JsonArray { Count: > 0 } m && m[0] is JsonObject first)
        {
            var host = first["host"] is JsonArray { Count: > 0 } h ? h[0]?.ToString() : null;
            var path = first["path"] is JsonArray { Count: > 0 } p ? p[0]?.ToString() : null;
            if (host is not null || path is not null) return $"{host}{path}";
        }
        return $"route {index + 1}";
    }

    // Returns false once the change list is full.
    private static bool Walk(JsonNode? before, JsonNode? after, List<string> at, List<ConfigChange> changes, SecretRedactor redactor)
    {
        if (before is null && after is null) return true;
        if (before is JsonObject b && after is JsonObject a)
        {
            foreach (var key in b.Select(p => p.Key).Concat(a.Select(p => p.Key).Where(k => !b.ContainsKey(k))))
            {
                at.Add(key);
                var ok = Walk(b[key], a[key], at, changes, redactor);
                at.RemoveAt(at.Count - 1);
                if (!ok) return false;
            }
            return true;
        }
        // An added or removed container is opened down to its routes and policies, so each shows by name.
        if ((before is null && after is JsonObject || after is null && before is JsonObject) && Container(at))
            return Walk(before ?? new JsonObject(), after ?? new JsonObject(), at, changes, redactor);
        if (before is JsonArray ba && after is JsonArray aa)
        {
            for (var i = 0; i < Math.Max(ba.Count, aa.Count); i++)
            {
                at.Add(i.ToString(System.Globalization.CultureInfo.InvariantCulture));
                var ok = Walk(i < ba.Count ? ba[i] : null, i < aa.Count ? aa[i] : null, at, changes, redactor);
                at.RemoveAt(at.Count - 1);
                if (!ok) return false;
            }
            return true;
        }
        if (before is not null && after is not null && JsonNode.DeepEquals(before, after)) return true;

        if (changes.Count >= MaxChanges) return false;
        var kind = before is null ? "added" : after is null ? "removed" : "changed";
        var masked = at.Any(CredentialFields.Contains);
        var (group, path) = Locate(at);
        changes.Add(new ConfigChange(group, kind, path,
            before is null ? null : masked ? Masked : Render(before, redactor),
            after is null ? null : masked ? Masked : Render(after, redactor)));
        return true;
    }

    // The levels above the routes and certificate policies.
    private static bool Container(List<string> at) => at switch
    {
        [] or ["apps"] or ["apps", "http"] or ["apps", "http", "servers"] or ["apps", "http", "servers", _]
            or ["apps", "http", "servers", _, "routes"] or ["apps", "tls"] or ["apps", "tls", "automation"]
            or ["apps", "tls", "automation", "policies"] => true,
        _ => false,
    };

    private static (string Group, string Path) Locate(List<string> at) => at switch
    {
        ["apps", "http", "servers", var server, "routes", var route, .. var rest] => ($"{route} ({server})", Pointer(rest)),
        ["apps", "http", "servers", var server, .. var rest] => ($"{server} server", Pointer(rest)),
        ["apps", "tls", "automation", "policies", var subjects, .. var rest] => ($"certificate policy {subjects}", Pointer(rest)),
        ["apps", var app, .. var rest] => ($"{app} app", Pointer(rest)),
        [var section, .. var rest] => (section, Pointer(rest)),
        _ => ("config", ""),
    };

    private static string Pointer(IEnumerable<string> segments) =>
        string.Concat(segments.Select(s => "/" + s.Replace("~", "~0").Replace("/", "~1")));

    private static string Render(JsonNode node, SecretRedactor redactor)
    {
        var text = redactor.Redact(Mask(node).ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        return text.Length <= MaxValueLength ? text : text[..MaxValueLength] + "…";
    }

    private static JsonNode Mask(JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                var copy = new JsonObject();
                foreach (var (key, value) in obj)
                    copy[key] = CredentialFields.Contains(key) && value is not null ? JsonValue.Create(Masked) : value is null ? null : Mask(value);
                return copy;
            case JsonArray arr:
                return new JsonArray(arr.Select(e => e is null ? null : Mask(e)).ToArray());
            default:
                return node.DeepClone();
        }
    }
}
