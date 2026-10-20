using Microsoft.Extensions.Configuration;

namespace SslReverseProxy.Infrastructure.Security;

/// <summary>
/// Replaces the exact values of configured secrets in text that leaves the process: logs,
/// API responses, stored errors. Exact values only, so an encoded or split secret is not
/// caught; the callers avoid logging raw external payloads for that reason.
/// </summary>
public sealed class SecretRedactor
{
    public const string Mask = "[redacted]";

    // Shorter values would mask ordinary words; no real secret here is this short.
    private const int MinLength = 8;

    private readonly string[] _secrets;

    public SecretRedactor(IEnumerable<string?> secrets) =>
        _secrets = secrets
            .Where(s => !string.IsNullOrEmpty(s) && s.Length >= MinLength)
            .Select(s => s!)
            .Distinct(StringComparer.Ordinal)
            // Longest first, so a secret containing another is masked whole.
            .OrderByDescending(s => s.Length)
            .ToArray();

    public static SecretRedactor None { get; } = new([]);

    /// <summary>The pepper, the Cloudflare token and every alert target's URL and token.</summary>
    public static SecretRedactor FromConfiguration(IConfiguration config)
    {
        var values = new List<string?>
        {
            config["Security:ApiKeyPepper"],
            config["Proxy:CloudflareApiToken"],
        };
        foreach (var target in config.GetSection("Alerts:Targets").GetChildren())
        {
            values.Add(target["Url"]);
            // The sender requests the parsed URL, whose host is lower-cased.
            if (Uri.TryCreate(target["Url"]?.Trim(), UriKind.Absolute, out var url)) values.Add(url.AbsoluteUri);
            values.Add(target["Token"]);
        }
        // Each value as configured and trimmed, as Caddy's environment and the alert sender receive it.
        return new SecretRedactor(values.SelectMany(v => new[] { v, v?.Trim() }));
    }

    public bool Contains(string? text) =>
        !string.IsNullOrEmpty(text) && _secrets.Any(s => text.Contains(s, StringComparison.Ordinal));

    public string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
        foreach (var s in _secrets)
            text = text.Replace(s, Mask, StringComparison.Ordinal);
        return text;
    }
}
