using System.Security.Cryptography;
using SslReverseProxy.Core.Abstractions;

namespace SslReverseProxy.Infrastructure.Security;

/// <summary>
/// PBKDF2-SHA256 hashing for API-key secrets with a per-key random salt and an
/// optional server-wide pepper (from configuration, never source). Verification
/// uses a fixed-time comparison to avoid leaking the hash via timing.
/// </summary>
public sealed class ApiKeyHasher : IApiKeyHasher
{
    private const int DefaultIterations = 120_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly byte[] _pepper;
    private readonly int _iterations;

    public ApiKeyHasher(string? pepper = null, int iterations = DefaultIterations)
    {
        _pepper = string.IsNullOrEmpty(pepper) ? Array.Empty<byte>() : Convert.FromBase64String(pepper);
        _iterations = iterations;
    }

    public (byte[] hash, byte[] salt, int iterations) Hash(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(secret, salt, _iterations);
        return (hash, salt, _iterations);
    }

    public bool Verify(string secret, byte[] expectedHash, byte[] salt, int iterations)
    {
        var actual = Derive(secret, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
    }

    private byte[] Derive(string secret, byte[] salt, int iterations)
    {
        // Bind the pepper into the input so it is required to reproduce the hash.
        var secretBytes = System.Text.Encoding.UTF8.GetBytes(secret);
        var input = new byte[secretBytes.Length + _pepper.Length];
        Buffer.BlockCopy(secretBytes, 0, input, 0, secretBytes.Length);
        Buffer.BlockCopy(_pepper, 0, input, secretBytes.Length, _pepper.Length);

        using var pbkdf2 = new Rfc2898DeriveBytes(input, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(HashSize);
    }
}
