using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>One request a rule's route served, as kept: no query, headers, cookies or credentials.</summary>
public sealed record RecentRequest(
    long Seq, DateTimeOffset At, Guid RuleId, string Method, string Host, string Path, int Status,
    double DurationMs, long Size, string? ClientIp);

/// <summary>
/// The last <see cref="Capacity"/> requests, at most <see cref="MaxAge"/> old, read from Caddy's access log lines.
/// Each route names its rule through <see cref="RuleField"/>, so Caddy's own routing decides which rule a request
/// belongs to, a rollback included. Lines without that field are dropped.
/// </summary>
public sealed partial class RecentRequests
{
    public const int Capacity = 10_000;
    public static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);
    public const int MaxPathLength = 512;
    public const int MaxHostLength = 253;
    public const string RuleField = "sslrp_rule";
    public const string AccessLoggerPrefix = "http.log.access.";

    private readonly RecentRequest?[] _ring = new RecentRequest?[Capacity];
    private readonly Lock _lock = new();
    private readonly TimeProvider _clock;
    private long _seq;

    public RecentRequests(TimeProvider clock) => _clock = clock;

    [GeneratedRegex("^[A-Z]{1,16}$")]
    private static partial Regex MethodToken();

    /// <summary>True when the line is an access log entry, kept or not; the caller must not log it.</summary>
    public bool Observe(string line)
    {
        if (!line.Contains("\"logger\":\"" + AccessLoggerPrefix, StringComparison.Ordinal)) return false;
        JsonDocument doc;
        try { doc = JsonDocument.Parse(line); }
        catch (JsonException) { return false; }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || Text(root, "logger") is not { } logger
                || !logger.StartsWith(AccessLoggerPrefix, StringComparison.Ordinal)) return false;
            if (Parse(root) is { } entry) Add(entry);
            return true;
        }
    }

    /// <summary>A rule's requests, newest first, older than <paramref name="before"/> when given.</summary>
    public (IReadOnlyList<RecentRequest> Requests, long? Next) Query(Guid ruleId, int take, Func<int, bool> status, long? before)
    {
        var found = new List<RecentRequest>(Math.Min(take, 64));
        long? next = null;
        var cutoff = _clock.GetUtcNow() - MaxAge;
        lock (_lock)
        {
            var newest = before is { } b ? Math.Min(b - 1, _seq) : _seq;
            var oldest = Math.Max(1, _seq - Capacity + 1);
            for (var s = newest; s >= oldest; s--)
            {
                if (_ring[s % Capacity] is not { } e) continue;
                if (e.At < cutoff) break;
                if (e.RuleId != ruleId || !status(e.Status)) continue;
                if (found.Count == take) { next = found[^1].Seq; break; }
                found.Add(e);
            }
        }
        return (found, next);
    }

    private void Add(Parsed p)
    {
        lock (_lock)
        {
            var seq = ++_seq;
            _ring[seq % Capacity] = new RecentRequest(seq, p.At, p.RuleId, p.Method, p.Host, p.Path, p.Status, p.DurationMs, p.Size, p.ClientIp);
        }
    }

    private sealed record Parsed(DateTimeOffset At, Guid RuleId, string Method, string Host, string Path, int Status, double DurationMs, long Size, string? ClientIp);

    private Parsed? Parse(JsonElement root)
    {
        if (Text(root, RuleField) is not { } ruleText || !Guid.TryParse(ruleText, out var ruleId)) return null;
        if (!root.TryGetProperty("request", out var request) || request.ValueKind != JsonValueKind.Object) return null;

        var at = root.TryGetProperty("ts", out var ts) && ts.TryGetDouble(out var seconds) && double.IsFinite(seconds)
            && seconds is > 0 and < 253402300799
            ? DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000))
            : _clock.GetUtcNow();
        var status = root.TryGetProperty("status", out var st) && st.TryGetInt32(out var code) && code is >= 0 and <= 999 ? code : 0;
        var duration = root.TryGetProperty("duration", out var du) && du.TryGetDouble(out var d) && double.IsFinite(d) && d >= 0 ? d * 1000 : 0;
        var size = root.TryGetProperty("size", out var sz) && sz.TryGetInt64(out var n) && n >= 0 ? n : 0;

        var method = Text(request, "method") is { } m && MethodToken().IsMatch(m) ? m : "?";
        var host = Clean(Text(request, "host") ?? string.Empty, MaxHostLength).ToLowerInvariant();
        var path = Clean(PathOf(Text(request, "uri") ?? string.Empty), MaxPathLength);
        var clientIp = Text(request, "client_ip") is { } ip && IPAddress.TryParse(ip, out var addr) ? addr.ToString() : null;
        return new Parsed(at, ruleId, method, host, path, status, duration, size, clientIp);
    }

    // Caddy's encoder already drops the query; this holds if a config without that filter is running.
    private static string PathOf(string uri)
    {
        var end = uri.IndexOfAny(['?', '#']);
        return end < 0 ? uri : uri[..end];
    }

    private static string Clean(string value, int max)
    {
        var chars = value.Where(c => !char.IsControl(c)).Take(max + 1).ToArray();
        return chars.Length > max ? new string(chars, 0, max) + "…" : new string(chars);
    }

    private static string? Text(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
