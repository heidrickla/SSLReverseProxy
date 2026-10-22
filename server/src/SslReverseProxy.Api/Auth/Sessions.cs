using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace SslReverseProxy.Api.Auth;

public sealed class PasskeyOptions
{
    public const string SectionName = "Passkeys";

    /// <summary>The WebAuthn relying party id: the host the UI is served from, such as <c>proxy.example.com</c>. Empty turns passkeys off.</summary>
    public string? RelyingPartyId { get; set; }

    public string RelyingPartyName { get; set; } = "SSLReverseProxy";

    /// <summary>Exact origins the UI is served from, such as <c>https://proxy.example.com</c>.</summary>
    public string[] Origins { get; set; } = [];

    public int SessionHours { get; set; } = 12;

    /// <summary>Anonymous sign-in option requests one client IP may make per minute.</summary>
    public int OptionsPerMinute { get; set; } = 10;

    /// <summary>Sign-in attempts one client IP may make per minute.</summary>
    public int SignInsPerMinute { get; set; } = 5;

    /// <summary><see cref="Origins"/> without blanks (an unset environment variable) or trailing slashes.</summary>
    public IReadOnlySet<string> AllowedOrigins =>
        Origins.Where(o => !string.IsNullOrWhiteSpace(o)).Select(o => o.Trim().TrimEnd('/')).ToHashSet(StringComparer.Ordinal);

    public bool Enabled => !string.IsNullOrWhiteSpace(RelyingPartyId) && AllowedOrigins.Count > 0;

    public bool AllowsOrigin(string? origin) => !string.IsNullOrEmpty(origin) && AllowedOrigins.Contains(origin);
}

/// <summary>
/// Session tokens are <c>sps.&lt;id&gt;.&lt;secret&gt;</c> in a <c>__Host-</c> cookie. The database holds the
/// secret's SHA-256 only. The CSRF token is an HMAC of the secret, so it needs no storage and only the
/// holder of the cookie's value can compute it.
/// </summary>
public static class SessionTokens
{
    public const string CookieName = "__Host-sslrp-session";
    public const string CsrfHeader = "X-CSRF-Token";
    private const string Scheme = "sps";

    public static (string Token, byte[] SecretHash) Create(Guid sessionId)
    {
        var secret = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        return ($"{Scheme}.{sessionId:N}.{secret}", Hash(secret));
    }

    public static bool TryParse(string? token, out Guid sessionId, out string secret)
    {
        sessionId = Guid.Empty;
        secret = string.Empty;
        var parts = token?.Split('.');
        if (parts is not { Length: 3 } || parts[0] != Scheme || parts[2].Length is < 40 or > 64) return false;
        if (!Guid.TryParseExact(parts[1], "N", out sessionId)) return false;
        secret = parts[2];
        return true;
    }

    public static byte[] Hash(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));

    public static bool Matches(string secret, byte[] storedHash) =>
        CryptographicOperations.FixedTimeEquals(Hash(secret), storedHash);

    public static string CsrfToken(string secret) =>
        WebEncoders.Base64UrlEncode(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), "sslrp-csrf"u8));

    public static bool CsrfMatches(string secret, string? presented) =>
        presented is not null && CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(CsrfToken(secret)), Encoding.UTF8.GetBytes(presented));

    public static CookieOptions CookieOptions(DateTimeOffset expires) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };
}

/// <summary>
/// WebAuthn ceremony options waiting for the browser's answer, keyed by a random handle. Each is taken once
/// and expires after two minutes. Anonymous sign-ins and signed-in registrations have separate limits, so
/// sign-in traffic cannot crowd out a registration; a kind at its limit drops its oldest entry for the new one,
/// so a flood of ceremonies delays a sign-in by a retry instead of refusing every one.
/// </summary>
public sealed class PasskeyChallenges(TimeProvider clock)
{
    public const int SignInCapacity = 1000;
    public const int RegisterCapacity = 100;
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    public enum Kind { Register, SignIn }

    private sealed record Entry(Kind Kind, Guid? UserId, string OptionsJson, DateTimeOffset Expires);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Lock _adding = new();

    public static int CapacityOf(Kind kind) => kind == Kind.SignIn ? SignInCapacity : RegisterCapacity;

    /// <summary>Stores the options and returns their handle.</summary>
    public string Add(Kind kind, Guid? userId, string optionsJson)
    {
        lock (_adding)
        {
            var now = clock.GetUtcNow();
            foreach (var (key, entry) in _entries)
                if (entry.Expires <= now) _entries.TryRemove(key, out _);

            var sameKind = _entries.Where(e => e.Value.Kind == kind).ToList();
            foreach (var (key, _) in sameKind.OrderBy(e => e.Value.Expires).Take(sameKind.Count - CapacityOf(kind) + 1))
                _entries.TryRemove(key, out _);

            var handle = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(24));
            _entries[handle] = new Entry(kind, userId, optionsJson, now + Lifetime);
            return handle;
        }
    }

    /// <summary>Removes the entry whatever it holds, and returns its options only when kind, user and time match.</summary>
    public string? Take(string? handle, Kind kind, Guid? userId)
    {
        if (handle is null || !_entries.TryRemove(handle, out var entry)) return null;
        return entry.Kind == kind && entry.UserId == userId && entry.Expires > clock.GetUtcNow()
            ? entry.OptionsJson
            : null;
    }
}
