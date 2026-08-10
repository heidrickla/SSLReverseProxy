namespace SslReverseProxy.Infrastructure.Security;

/// <summary>
/// Holds the seeded bootstrap admin API key in memory so a local development UI
/// can claim it once on first load instead of copying it from the log. The key
/// is only ever offered by the first-run seeder, is never persisted, and is
/// consumed by a single claim; a process restart leaves the broker permanently
/// empty.
/// </summary>
public sealed class BootstrapKeyBroker
{
    private string? _token;

    public void Offer(string token) => _token = token;

    /// <summary>Returns the key and clears it, or null if none is available.</summary>
    public string? Claim() => Interlocked.Exchange(ref _token, null);
}
