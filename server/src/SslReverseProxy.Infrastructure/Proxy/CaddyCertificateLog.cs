using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Security;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>
/// The latest obtain or renew outcome Caddy logged for each name, read from its JSON log lines.
/// <para>
/// Only "could not get certificate from issuer" counts as a failure. After a successful renewal
/// Caddy can log an error-level "unable to unlock" for the same name (seen on Windows storage),
/// which says nothing about the certificate.
/// </para>
/// </summary>
public sealed class CaddyCertificateLog
{
    public const int MaxErrorLength = 500;

    /// <summary>A null <paramref name="Error"/> means the certificate was obtained or renewed.</summary>
    public sealed record Outcome(DateTimeOffset At, string? Error);

    private readonly ConcurrentDictionary<string, Outcome> _latest = new(StringComparer.Ordinal);
    private readonly SecretRedactor _redactor;
    private readonly TimeProvider _clock;

    public CaddyCertificateLog(SecretRedactor redactor, TimeProvider clock)
    {
        _redactor = redactor;
        _clock = clock;
    }

    public Outcome? Latest(string domain) =>
        _latest.TryGetValue(CertificateNames.Normalize(domain), out var o) ? o : null;

    /// <summary>A failure found outside Caddy's log, such as a forced renewal that never produced a new serial.</summary>
    public void RecordFailure(string domain, string error) =>
        _latest[CertificateNames.Normalize(domain)] = new Outcome(_clock.GetUtcNow(), error);

    public void Observe(string line)
    {
        if (!line.Contains("\"logger\":\"tls.", StringComparison.Ordinal)) return;
        JsonObject? entry;
        try { entry = JsonNode.Parse(line) as JsonObject; }
        catch (JsonException) { return; }
        if (entry is null) return;

        var logger = Text(entry, "logger");
        if (logger is not ("tls.obtain" or "tls.renew")) return;
        if (Text(entry, "identifier") is not { } identifier) return;

        var name = CertificateNames.Normalize(identifier);
        switch (Text(entry, "msg"))
        {
            case "certificate obtained successfully":
            case "certificate renewed successfully":
                _latest[name] = new Outcome(_clock.GetUtcNow(), null);
                break;
            case "could not get certificate from issuer" when Text(entry, "level") == "error":
                var error = _redactor.Redact(Text(entry, "error") ?? "Caddy could not get a certificate.");
                if (error.Length > MaxErrorLength) error = error[..MaxErrorLength] + "…";
                _latest[name] = new Outcome(_clock.GetUtcNow(), error);
                break;
        }
    }

    private static string? Text(JsonObject entry, string key) =>
        entry[key] is JsonValue v && v.TryGetValue(out string? s) ? s : null;
}
