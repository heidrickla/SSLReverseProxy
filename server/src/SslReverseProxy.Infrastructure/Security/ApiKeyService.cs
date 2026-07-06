using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SslReverseProxy.Core.Abstractions;
using SslReverseProxy.Core.Domain;
using SslReverseProxy.Infrastructure.Persistence;

namespace SslReverseProxy.Infrastructure.Security;

/// <summary>
/// Issues and verifies API keys. Token format: "srp.{prefix}.{secret}" where
/// prefix is a public lookup handle and secret is high-entropy. The '.' delimiter
/// is safe because it is not in the Base64Url alphabet used for prefix/secret.
/// Only a PBKDF2 hash of the secret is stored; the plaintext is returned once.
/// </summary>
public sealed class ApiKeyService : IApiKeyService
{
    private const string TokenScheme = "srp";
    private const int PrefixBytes = 6;   // -> 8 base64url chars
    private const int SecretBytes = 32;  // 256-bit secret

    private readonly AppDbContext _db;
    private readonly IApiKeyHasher _hasher;
    private readonly TimeProvider _clock;

    public ApiKeyService(AppDbContext db, IApiKeyHasher hasher, TimeProvider clock)
    {
        _db = db;
        _hasher = hasher;
        _clock = clock;
    }

    public async Task<IssuedApiKey> CreateAsync(Guid userId, string name, TimeSpan? lifetime, CancellationToken ct = default)
    {
        var prefix = Base64Url(RandomNumberGenerator.GetBytes(PrefixBytes));
        var secret = Base64Url(RandomNumberGenerator.GetBytes(SecretBytes));
        var (hash, salt, iterations) = _hasher.Hash(secret);
        var now = _clock.GetUtcNow();

        var record = new ApiKey
        {
            Prefix = prefix,
            SecretHash = hash,
            Salt = salt,
            Iterations = iterations,
            Name = name,
            UserId = userId,
            CreatedAt = now,
            ExpiresAt = lifetime is { } l ? now.Add(l) : null,
        };

        _db.ApiKeys.Add(record);
        await _db.SaveChangesAsync(ct);

        var token = $"{TokenScheme}.{prefix}.{secret}";
        return new IssuedApiKey(record, token);
    }

    public async Task<User?> AuthenticateAsync(string presentedToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(presentedToken)) return null;

        var parts = presentedToken.Split('.');
        if (parts.Length != 3 || parts[0] != TokenScheme) return null;
        var prefix = parts[1];
        var secret = parts[2];

        var key = await _db.ApiKeys
            .Include(k => k.User)
            .SingleOrDefaultAsync(k => k.Prefix == prefix, ct);

        var now = _clock.GetUtcNow();

        // Always run the hash to keep timing uniform whether or not the prefix
        // matched, then make the accept/reject decision on constant-time compare.
        if (key is null)
        {
            _ = _hasher.Verify(secret, new byte[32], new byte[16], 120_000);
            return null;
        }

        var ok = _hasher.Verify(secret, key.SecretHash, key.Salt, key.Iterations);
        if (!ok || !key.IsActive(now) || key.User is null || !key.User.IsActive)
            return null;

        key.LastUsedAt = now;
        key.User.LastSeenAt = now;
        await _db.SaveChangesAsync(ct);
        return key.User;
    }

    public async Task RevokeAsync(Guid apiKeyId, CancellationToken ct = default)
    {
        var key = await _db.ApiKeys.FindAsync([apiKeyId], ct);
        if (key is null || key.RevokedAt is not null) return;
        key.RevokedAt = _clock.GetUtcNow();
        await _db.SaveChangesAsync(ct);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
