using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SslReverseProxy.Infrastructure.Proxy;

/// <summary>Ok with the token's email, which a service token does not carry, or a refusal reason that holds nothing from the token.</summary>
public sealed record CloudflareAccessResult(bool Ok, string? Email, string Reason);

/// <summary>
/// Checks a Cloudflare Access token: RS256 under a key from the team's certs endpoint, the team as issuer,
/// the application's AUD tag as audience, and an expiry. Keys are cached per team and fetched again after
/// <see cref="KeysFor"/>, or on a key id the cache lacks, at most once per <see cref="RefetchAfter"/>.
/// The injected clock times the key cache; token lifetimes are read against the system clock.
/// </summary>
public sealed class CloudflareAccessVerifier
{
    public const string ClientName = "cloudflare-access";
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan KeysFor = TimeSpan.FromHours(1);
    public static readonly TimeSpan RefetchAfter = TimeSpan.FromSeconds(30);
    /// <summary>Keys this old are dropped when the certs endpoint cannot be read.</summary>
    public static readonly TimeSpan MaxKeyAge = TimeSpan.FromHours(24);
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);
    public const int MaxKeysBytes = 64 * 1024;
    public const int MaxTokenBytes = 16 * 1024;

    private sealed record TeamKeys(IReadOnlyDictionary<string, JsonWebKey> Keys, DateTimeOffset FetchedAt, DateTimeOffset TriedAt);

    private static readonly IReadOnlyDictionary<string, JsonWebKey> NoKeys = new Dictionary<string, JsonWebKey>();

    private readonly IHttpClientFactory _http;
    private readonly IOptions<ProxyOptions> _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<CloudflareAccessVerifier> _log;
    private readonly JsonWebTokenHandler _handler = new() { MaximumTokenSizeInBytes = MaxTokenBytes };
    private readonly ConcurrentDictionary<string, TeamKeys> _teams = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _fetch = new(1, 1);

    public CloudflareAccessVerifier(
        IHttpClientFactory http, IOptions<ProxyOptions> options, TimeProvider clock, ILogger<CloudflareAccessVerifier> log)
    {
        _http = http;
        _options = options;
        _clock = clock;
        _log = log;
    }

    public async Task<CloudflareAccessResult> VerifyAsync(string teamDomain, string audience, string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token)) return Refuse("no token");
        if (token.Length > MaxTokenBytes || !_handler.CanReadToken(token)) return Refuse("malformed token");
        JsonWebToken jwt;
        try { jwt = new JsonWebToken(token); }
        catch (ArgumentException) { return Refuse("malformed token"); }
        if (jwt.Alg != SecurityAlgorithms.RsaSha256) return Refuse("not RS256");
        if (string.IsNullOrEmpty(jwt.Kid)) return Refuse("no key id");

        if (await KeyAsync(teamDomain, jwt.Kid, ct) is not { } key) return Refuse("unknown key");
        var result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "https://" + teamDomain,
            ValidAudience = audience,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            IssuerSigningKey = key,
            TryAllIssuerSigningKeys = false,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            RequireAudience = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = ClockSkew,
        });
        if (!result.IsValid) return Refuse(result.Exception?.GetType().Name ?? "invalid token");
        var email = result.Claims.TryGetValue("email", out var e) ? e as string : null;
        return new CloudflareAccessResult(true, email, "verified");
    }

    private static CloudflareAccessResult Refuse(string reason) => new(false, null, reason);

    private async Task<JsonWebKey?> KeyAsync(string team, string kid, CancellationToken ct)
    {
        if (_teams.TryGetValue(team, out var have) && _clock.GetUtcNow() - have.FetchedAt < KeysFor
            && have.Keys.TryGetValue(kid, out var cached))
            return cached;

        await _fetch.WaitAsync(ct);
        try
        {
            var now = _clock.GetUtcNow();
            _teams.TryGetValue(team, out have);
            if (have is null || now - have.TriedAt >= RefetchAfter)
            {
                var fetched = await FetchAsync(team, ct);
                have = fetched is not null
                    ? new TeamKeys(fetched, now, now)
                    : new TeamKeys(have?.Keys ?? NoKeys, have?.FetchedAt ?? DateTimeOffset.MinValue, now);
                _teams[team] = have;
            }
            return now - have.FetchedAt < MaxKeyAge ? have.Keys.GetValueOrDefault(kid) : null;
        }
        finally
        {
            _fetch.Release();
        }
    }

    private async Task<IReadOnlyDictionary<string, JsonWebKey>?> FetchAsync(string team, CancellationToken ct)
    {
        var url = _options.Value.CloudflareAccessCertsUrl.Replace("{team}", team, StringComparison.Ordinal);
        try
        {
            var client = _http.CreateClient(ClientName);
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                _log.LogWarning("Cloudflare Access keys for {Team} answered {Status}.", team, (int)response.StatusCode);
                return null;
            }
            if (response.Content.Headers.ContentLength > MaxKeysBytes)
            {
                _log.LogWarning("Cloudflare Access keys for {Team} are over {Max} bytes.", team, MaxKeysBytes);
                return null;
            }
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[MaxKeysBytes + 1];
            var read = 0;
            int n;
            while (read < buffer.Length && (n = await stream.ReadAsync(buffer.AsMemory(read), ct)) > 0) read += n;
            if (read > MaxKeysBytes)
            {
                _log.LogWarning("Cloudflare Access keys for {Team} are over {Max} bytes.", team, MaxKeysBytes);
                return null;
            }
            var set = new JsonWebKeySet(Encoding.UTF8.GetString(buffer, 0, read));
            return set.Keys
                .Where(k => k.Kty == JsonWebAlgorithmsKeyTypes.RSA && !string.IsNullOrEmpty(k.Kid)
                    && (string.IsNullOrEmpty(k.Use) || k.Use == JsonWebKeyUseNames.Sig))
                .GroupBy(k => k.Kid, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            _log.LogWarning("Cloudflare Access keys for {Team} could not be read: {Error}.", team, ex.GetType().Name);
            return null;
        }
    }
}
